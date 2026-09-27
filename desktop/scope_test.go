package main

import "testing"

func TestHostMatches(t *testing.T) {
	cases := []struct {
		host, pat string
		want      bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "example.com", true},       // parent domain covers subdomain
		{"example.com.evil.com", "example.com", false}, // not a real subdomain
		{"evilexample.com", "example.com", false},
		{"api.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false}, // wildcard is subdomains only
		{"10.0.0.5", "10.0.0.5", true},
		{"other.com", "example.com", false},
	}
	for _, c := range cases {
		if got := hostMatches(c.host, c.pat); got != c.want {
			t.Errorf("hostMatches(%q,%q)=%v want %v", c.host, c.pat, got, c.want)
		}
	}
}

func TestScopeMatcher(t *testing.T) {
	a := &App{}
	// Disabled scope records everything (nil matcher).
	if a.scopeMatcher() != nil {
		t.Fatal("disabled scope should return nil matcher")
	}
	a.SetScope(ScopeConfig{Enabled: true, Hosts: []string{" Example.COM ", ""}})
	m := a.scopeMatcher()
	if m == nil {
		t.Fatal("enabled scope should return a matcher")
	}
	if !m("api.example.com") {
		t.Error("expected api.example.com in scope (normalised host)")
	}
	if m("other.org") {
		t.Error("other.org should be out of scope")
	}
}
