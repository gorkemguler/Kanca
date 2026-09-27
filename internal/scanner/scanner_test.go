package scanner

import (
	"net/http"
	"testing"

	"github.com/gorkemguler/mimlec/internal/proxy"
)

func flow(id int64, scheme, host string, h http.Header) *proxy.Flow {
	return &proxy.Flow{
		ID: id, Scheme: scheme, Host: host, URL: scheme + "://" + host + "/",
		StatusCode: 200, Response: proxy.Message{Headers: h},
	}
}

func titles(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Title] = true
	}
	return m
}

func TestFindsMissingHeaders(t *testing.T) {
	s := New()
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	// HTTPS HTML page with no hardening headers at all.
	s.Inspect(flow(1, "https", "example.com", h))

	got := titles(s.Findings())
	for _, want := range []string{
		"Missing X-Content-Type-Options",
		"Missing Content-Security-Policy",
		"Missing clickjacking protection",
		"Missing HSTS",
	} {
		if !got[want] {
			t.Errorf("expected finding %q; got %v", want, got)
		}
	}
}

func TestNoFalsePositivesWhenHardened(t *testing.T) {
	s := New()
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("Strict-Transport-Security", "max-age=63072000")
	s.Inspect(flow(1, "https", "secure.example.com", h))

	if fs := s.Findings(); len(fs) != 0 {
		t.Fatalf("expected no findings on hardened response, got %+v", fs)
	}
}

func TestInsecureCookieAndDedup(t *testing.T) {
	s := New()
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Add("Set-Cookie", "sid=abc; Path=/")
	s.Inspect(flow(1, "https", "api.example.com", h))
	// Same host + same issue on another flow must not duplicate.
	s.Inspect(flow(2, "https", "api.example.com", h))

	got := titles(s.Findings())
	if !got["Cookie without HttpOnly"] || !got["Cookie without Secure"] {
		t.Fatalf("expected cookie findings, got %v", got)
	}
	// Dedup: exactly one HttpOnly finding despite two flows.
	count := 0
	for _, f := range s.Findings() {
		if f.Title == "Cookie without HttpOnly" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected dedup to 1 HttpOnly finding, got %d", count)
	}
}

func TestVersionDisclosureAndCallback(t *testing.T) {
	s := New()
	var fired int
	s.OnFinding(func(Finding) { fired++ })
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Server", "nginx/1.25.3")
	h.Set("Access-Control-Allow-Origin", "*")
	s.Inspect(flow(1, "http", "x.test", h))

	got := titles(s.Findings())
	if !got["Version disclosure via Server"] || !got["Permissive CORS"] {
		t.Fatalf("expected version + CORS findings, got %v", got)
	}
	if fired == 0 {
		t.Fatal("OnFinding callback never fired")
	}
}
