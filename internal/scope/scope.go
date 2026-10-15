// Package scope matches hosts against a target-scope list.
package scope

import "strings"

// Normalize turns entries into lower-case host patterns, accepting what people
// paste (a URL, host:port), and drops empty and repeated ones.
func Normalize(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if i := strings.Index(h, "://"); i >= 0 {
			h = h[i+3:]
		}
		if i := strings.IndexAny(h, "/?#"); i >= 0 {
			h = h[:i]
		}
		if i := strings.LastIndexByte(h, '@'); i >= 0 {
			h = h[i+1:]
		}
		if strings.HasPrefix(h, "[") {
			if j := strings.IndexByte(h, ']'); j > 0 {
				h = h[1:j]
			}
		} else if strings.Count(h, ":") == 1 {
			h = h[:strings.IndexByte(h, ':')]
		}
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// Matches reports whether host matches pat: exactly, as a parent domain
// ("example.com" covers "api.example.com"), or via "*.example.com" for
// subdomains only. Both are expected lower-case.
func Matches(host, pat string) bool {
	if pat == "" {
		return false
	}
	if strings.HasPrefix(pat, "*.") {
		return strings.HasSuffix(host, pat[1:])
	}
	return host == pat || strings.HasSuffix(host, "."+pat)
}

// Matcher returns a predicate over hosts for the given entries, or nil when
// there are none.
func Matcher(hosts []string) func(host string) bool {
	hosts = Normalize(hosts)
	if len(hosts) == 0 {
		return nil
	}
	return func(host string) bool {
		host = strings.ToLower(host)
		for _, pat := range hosts {
			if Matches(host, pat) {
				return true
			}
		}
		return false
	}
}
