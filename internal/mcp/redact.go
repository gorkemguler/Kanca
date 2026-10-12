package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// secretBox swaps secret values (cookies, tokens, passwords) for stable
// placeholders before traffic is shown to an AI assistant, and swaps them back
// when the assistant sends a request that contains them. The same value always
// gets the same placeholder, so the assistant can still correlate requests.
type secretBox struct {
	mu      sync.Mutex
	byValue map[string]string
	byKey   map[string]string
}

func newSecretBox() *secretBox {
	return &secretBox{byValue: map[string]string{}, byKey: map[string]string{}}
}

var placeholderRe = regexp.MustCompile(`\[\[KANCA_SECRET_[0-9]+\]\]`)

func (b *secretBox) mask(v string) string {
	if v == "" {
		return v
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if k, ok := b.byValue[v]; ok {
		return k
	}
	k := fmt.Sprintf("[[KANCA_SECRET_%d]]", len(b.byKey)+1)
	b.byValue[v] = k
	b.byKey[k] = v
	return k
}

// unmask restores every known placeholder in s to its original value.
func (b *secretBox) unmask(s string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return placeholderRe.ReplaceAllStringFunc(s, func(k string) string {
		if v, ok := b.byKey[k]; ok {
			return v
		}
		return k
	})
}

// sensitiveName reports whether a header, form field or JSON key name usually
// carries a credential.
func sensitiveName(name string) bool {
	n := strings.ToLower(name)
	for _, w := range []string{"pass", "pwd", "token", "secret", "apikey", "api-key", "api_key", "session", "auth", "csrf", "xsrf", "otp", "cookie"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)

// maskMessage masks a raw HTTP request or response (head + body).
func (b *secretBox) maskMessage(raw string) string {
	head, body, sep := splitMessage(raw)
	lines := strings.Split(head, "\r\n")
	for i, line := range lines {
		if i == 0 {
			lines[0] = b.maskRequestLine(line)
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		lines[i] = name + ": " + b.maskHeader(name, value)
	}
	head = strings.Join(lines, "\r\n")
	if body != "" {
		body = b.maskBody(head, body)
	}
	return head + sep + body
}

func (b *secretBox) maskRequestLine(line string) string {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || strings.HasPrefix(parts[0], "HTTP/") {
		return line // status line, or something we don't understand
	}
	target, query, hasQuery := strings.Cut(parts[1], "?")
	if !hasQuery {
		return line
	}
	return parts[0] + " " + target + "?" + b.maskQuery(query) + " " + parts[2]
}

// maskQuery masks values of sensitive keys in a raw (still-encoded) query.
func (b *secretBox) maskQuery(q string) string {
	pairs := strings.Split(q, "&")
	for i, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		if sensitiveName(name) {
			pairs[i] = k + "=" + b.mask(v)
		}
	}
	return strings.Join(pairs, "&")
}

func (b *secretBox) maskHeader(name, value string) string {
	switch strings.ToLower(name) {
	case "cookie":
		parts := strings.Split(value, ";")
		for i, p := range parts {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok {
				parts[i] = k + "=" + b.mask(v)
			}
		}
		return strings.Join(parts, "; ")
	case "set-cookie":
		// Mask only the value; attributes (HttpOnly, Secure...) stay visible.
		first, rest, _ := strings.Cut(value, ";")
		if k, v, ok := strings.Cut(first, "="); ok {
			first = k + "=" + b.mask(v)
		}
		if rest != "" {
			return first + ";" + rest
		}
		return first
	case "authorization", "proxy-authorization":
		if scheme, cred, ok := strings.Cut(value, " "); ok {
			return scheme + " " + b.mask(cred)
		}
		return b.mask(value)
	case "www-authenticate", "proxy-authenticate", "authentication-info":
		return value // challenges, not credentials
	}
	if sensitiveName(name) {
		return b.mask(value)
	}
	return jwtRe.ReplaceAllStringFunc(value, b.mask)
}

func (b *secretBox) maskBody(head, body string) string {
	ct := strings.ToLower(headerValue(head, "Content-Type"))
	switch {
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		body = b.maskQuery(body)
	case strings.Contains(ct, "json"):
		var v any
		if json.Unmarshal([]byte(body), &v) == nil {
			b.maskJSON(v)
			if out, err := json.Marshal(v); err == nil {
				body = string(out)
			}
		}
	}
	return jwtRe.ReplaceAllStringFunc(body, b.mask)
}

func (b *secretBox) maskJSON(v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic placeholder numbering
		for _, k := range keys {
			if s, ok := t[k].(string); ok && sensitiveName(k) {
				t[k] = b.mask(s)
				continue
			}
			b.maskJSON(t[k])
		}
	case []any:
		for _, e := range t {
			b.maskJSON(e)
		}
	}
}

// splitMessage splits raw at the blank line, tolerating bare-LF messages.
func splitMessage(raw string) (head, body, sep string) {
	if h, bd, ok := strings.Cut(raw, "\r\n\r\n"); ok {
		return h, bd, "\r\n\r\n"
	}
	if h, bd, ok := strings.Cut(raw, "\n\n"); ok {
		return strings.ReplaceAll(h, "\n", "\r\n"), bd, "\r\n\r\n"
	}
	return raw, "", ""
}

func headerValue(head, name string) string {
	for _, line := range strings.Split(head, "\r\n")[1:] {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
