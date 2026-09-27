// Package rules implements match-and-replace: user-defined regular-expression
// substitutions applied to requests on their way out and responses on their
// way back. It operates on the raw HTTP/1.1 bytes so a rule can rewrite the
// request line, a header, or the body, and keeps Content-Length consistent
// when a body edit changes its length.
package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Phase selects which side of a transaction a rule applies to.
type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
)

// Part selects the region of the message a rule matches against.
type Part string

const (
	// PartFirstLine matches only the request line or status line.
	PartFirstLine Part = "first_line"
	// PartHeaders matches within the header block (excluding the body).
	PartHeaders Part = "headers"
	// PartBody matches within the body only.
	PartBody Part = "body"
)

// Rule is a single match-and-replace directive.
type Rule struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Phase   Phase  `json:"phase"`
	Part    Part   `json:"part"`
	// Match is a Go regular expression. Replace uses $1/$name expansion.
	Match   string `json:"match"`
	Replace string `json:"replace"`
	// Host, when set, limits the rule to hosts that equal it or are a
	// sub-domain of it (matching the scope convention).
	Host string `json:"host,omitempty"`

	re *regexp.Regexp
}

// compile prepares the rule's regexp; call after any Match change.
func (r *Rule) compile() error {
	if r.Match == "" {
		return fmt.Errorf("rules: %q has an empty match", r.Name)
	}
	re, err := regexp.Compile(r.Match)
	if err != nil {
		return fmt.Errorf("rules: %q: %w", r.Name, err)
	}
	r.re = re
	return nil
}

// Set is a mutable, concurrency-safe ordered collection of rules.
type Set struct {
	mu    sync.RWMutex
	seq   int64
	rules []*Rule
}

// NewSet returns an empty rule set.
func NewSet() *Set { return &Set{} }

// Add compiles and appends a rule, returning it with an assigned ID.
func (s *Set) Add(r Rule) (*Rule, error) {
	cp := r
	if err := cp.compile(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	cp.ID = s.seq
	s.rules = append(s.rules, &cp)
	return &cp, nil
}

// Replace swaps the entire rule list (used when the UI saves its editor).
// Each rule is recompiled; on the first error nothing is changed.
func (s *Set) Replace(in []Rule) error {
	compiled := make([]*Rule, 0, len(in))
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.seq
	for i := range in {
		cp := in[i]
		if err := cp.compile(); err != nil {
			return err
		}
		if cp.ID == 0 {
			seq++
			cp.ID = seq
		} else if cp.ID > seq {
			seq = cp.ID
		}
		compiled = append(compiled, &cp)
	}
	s.rules = compiled
	s.seq = seq
	return nil
}

// List returns a copy of the current rules (without the compiled regexp).
func (s *Set) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, len(s.rules))
	for i, r := range s.rules {
		out[i] = *r
		out[i].re = nil
	}
	return out
}

// Apply runs every enabled rule for the given phase against raw and returns
// the (possibly) rewritten bytes. host scopes host-limited rules. The input is
// never mutated; when no rule changes anything the original slice is returned.
func (s *Set) Apply(phase Phase, host string, raw []byte) []byte {
	s.mu.RLock()
	active := make([]*Rule, 0, len(s.rules))
	for _, r := range s.rules {
		if r.Enabled && r.Phase == phase && r.re != nil && hostAllowed(host, r.Host) {
			active = append(active, r)
		}
	}
	s.mu.RUnlock()
	if len(active) == 0 {
		return raw
	}

	out := raw
	changed := false
	for _, r := range active {
		next := applyOne(r, out)
		if !bytes.Equal(next, out) {
			out = next
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return out
}

// applyOne applies a single rule to the addressed region of the message.
func applyOne(r *Rule, raw []byte) []byte {
	head, body, ok := splitMessage(raw)
	if !ok {
		// No header/body separator: treat the whole thing as head.
		head, body = raw, nil
	}
	switch r.Part {
	case PartBody:
		newBody := r.re.ReplaceAll(body, []byte(r.Replace))
		if bytes.Equal(newBody, body) {
			return raw
		}
		return assemble(setContentLength(head, len(newBody)), newBody)
	case PartFirstLine:
		nl := bytes.IndexByte(head, '\n')
		if nl < 0 {
			nl = len(head)
		}
		line := head[:nl]
		rest := head[nl:]
		newLine := r.re.ReplaceAll(line, []byte(r.Replace))
		if bytes.Equal(newLine, line) {
			return raw
		}
		return assemble(append(append([]byte(nil), newLine...), rest...), body)
	default: // PartHeaders
		newHead := r.re.ReplaceAll(head, []byte(r.Replace))
		if bytes.Equal(newHead, head) {
			return raw
		}
		return assemble(newHead, body)
	}
}

// splitMessage divides a raw message at the first CRLFCRLF.
func splitMessage(raw []byte) (head, body []byte, ok bool) {
	sep := []byte("\r\n\r\n")
	i := bytes.Index(raw, sep)
	if i < 0 {
		return nil, nil, false
	}
	return raw[:i], raw[i+len(sep):], true
}

func assemble(head, body []byte) []byte {
	out := make([]byte, 0, len(head)+4+len(body))
	out = append(out, head...)
	out = append(out, '\r', '\n', '\r', '\n')
	out = append(out, body...)
	return out
}

// setContentLength rewrites (or appends) the Content-Length header in head to
// match n. Header names are matched case-insensitively.
func setContentLength(head []byte, n int) []byte {
	lines := strings.Split(string(head), "\r\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			lines[i] = "Content-Length: " + strconv.Itoa(n)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, "Content-Length: "+strconv.Itoa(n))
	}
	return []byte(strings.Join(lines, "\r\n"))
}

func hostAllowed(host, pat string) bool {
	if pat == "" {
		return true
	}
	host = strings.ToLower(host)
	if h := strings.IndexByte(host, ':'); h >= 0 {
		host = host[:h]
	}
	pat = strings.ToLower(pat)
	return host == pat || strings.HasSuffix(host, "."+pat)
}
