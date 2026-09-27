// Package scanner runs lightweight passive checks over captured flows and
// surfaces security-relevant findings (missing hardening headers, insecure
// cookies, version disclosure, permissive CORS). Passive means it only
// inspects traffic the operator already generated — it never sends requests of
// its own.
package scanner

import (
	"regexp"
	"strings"
	"sync"

	"github.com/gorkemguler/mimlec/internal/proxy"
)

// Severity ranks a finding.
type Severity string

const (
	Info   Severity = "info"
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Finding is one detected issue.
type Finding struct {
	ID       int64    `json:"id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Host     string   `json:"host"`
	URL      string   `json:"url"`
	FlowID   int64    `json:"flowId"`
}

// Scanner accumulates de-duplicated findings across inspected flows.
type Scanner struct {
	mu       sync.Mutex
	seq      int64
	seen     map[string]bool
	findings []*Finding
	onFind   func(Finding)
}

// New returns an empty scanner.
func New() *Scanner {
	return &Scanner{seen: make(map[string]bool)}
}

// OnFinding registers a callback fired once per newly recorded finding.
func (s *Scanner) OnFinding(fn func(Finding)) {
	s.mu.Lock()
	s.onFind = fn
	s.mu.Unlock()
}

// candidate is a potential finding before host/dedup context is attached.
type candidate struct {
	sev    Severity
	title  string
	detail string
}

// Inspect runs the passive checks against a completed flow and records any new
// findings (deduplicated per host + title).
func (s *Scanner) Inspect(f *proxy.Flow) {
	if f == nil || f.Error != "" || f.StatusCode == 0 {
		return
	}
	cands := runChecks(f)
	if len(cands) == 0 {
		return
	}
	host := hostOnly(f.Host)

	s.mu.Lock()
	var fresh []Finding
	for _, c := range cands {
		key := string(c.sev) + "|" + c.title + "|" + host
		if s.seen[key] {
			continue
		}
		s.seen[key] = true
		s.seq++
		fnd := &Finding{
			ID: s.seq, Severity: c.sev, Title: c.title, Detail: c.detail,
			Host: f.Host, URL: f.URL, FlowID: f.ID,
		}
		s.findings = append(s.findings, fnd)
		fresh = append(fresh, *fnd)
	}
	cb := s.onFind
	s.mu.Unlock()

	if cb != nil {
		for _, fnd := range fresh {
			cb(fnd)
		}
	}
}

// Add records an externally-produced finding (e.g. from the active scanner)
// through the same dedup pipeline as passive checks, so it appears in the same
// list and fires OnFinding. The finding's ID is assigned here. It returns
// false when a matching finding (same severity, title and host) already exists.
func (s *Scanner) Add(f Finding) bool {
	host := hostOnly(f.Host)
	key := string(f.Severity) + "|" + f.Title + "|" + host

	s.mu.Lock()
	if s.seen[key] {
		s.mu.Unlock()
		return false
	}
	s.seen[key] = true
	s.seq++
	f.ID = s.seq
	stored := f
	s.findings = append(s.findings, &stored)
	cb := s.onFind
	s.mu.Unlock()

	if cb != nil {
		cb(stored)
	}
	return true
}

// Findings returns a copy of all recorded findings.
func (s *Scanner) Findings() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Finding, len(s.findings))
	for i, f := range s.findings {
		out[i] = *f
	}
	return out
}

// Clear discards all findings and dedup state.
func (s *Scanner) Clear() {
	s.mu.Lock()
	s.findings = nil
	s.seen = make(map[string]bool)
	s.mu.Unlock()
}

var versionRe = regexp.MustCompile(`\d+(\.\d+)+`)

// runChecks is the passive rule set. Each returns zero or more candidates.
func runChecks(f *proxy.Flow) []candidate {
	h := f.Response.Headers
	var out []candidate
	isHTML := strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/html")
	isHTTPS := f.Scheme == "https"

	if h.Get("X-Content-Type-Options") == "" {
		out = append(out, candidate{Low, "Missing X-Content-Type-Options",
			"Response has no 'X-Content-Type-Options: nosniff'; browsers may MIME-sniff the body."})
	}
	if isHTML && h.Get("Content-Security-Policy") == "" {
		out = append(out, candidate{Medium, "Missing Content-Security-Policy",
			"HTML response has no Content-Security-Policy header, weakening XSS mitigation."})
	}
	if isHTML && h.Get("X-Frame-Options") == "" &&
		!strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		out = append(out, candidate{Low, "Missing clickjacking protection",
			"No X-Frame-Options and no CSP frame-ancestors directive; page may be framed."})
	}
	if isHTTPS && h.Get("Strict-Transport-Security") == "" {
		out = append(out, candidate{Medium, "Missing HSTS",
			"HTTPS response has no Strict-Transport-Security header."})
	}
	for _, c := range h.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		if !strings.Contains(lc, "httponly") {
			out = append(out, candidate{Low, "Cookie without HttpOnly",
				"A Set-Cookie is missing the HttpOnly flag: " + cookieName(c)})
		}
		if isHTTPS && !strings.Contains(lc, "secure") {
			out = append(out, candidate{Low, "Cookie without Secure",
				"A Set-Cookie over HTTPS is missing the Secure flag: " + cookieName(c)})
		}
	}
	if acao := h.Get("Access-Control-Allow-Origin"); acao == "*" {
		out = append(out, candidate{Info, "Permissive CORS",
			"Access-Control-Allow-Origin is '*', allowing any origin to read responses."})
	}
	for _, hdr := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if v := h.Get(hdr); v != "" && versionRe.MatchString(v) {
			out = append(out, candidate{Info, "Version disclosure via " + hdr,
				hdr + " header reveals software version: " + v})
		}
	}
	return out
}

func cookieName(setCookie string) string {
	if i := strings.IndexByte(setCookie, '='); i > 0 {
		return strings.TrimSpace(setCookie[:i])
	}
	return "(unnamed)"
}

func hostOnly(authority string) string {
	if i := strings.LastIndexByte(authority, ':'); i > 0 && !strings.Contains(authority[i:], "]") {
		return authority[:i]
	}
	return authority
}
