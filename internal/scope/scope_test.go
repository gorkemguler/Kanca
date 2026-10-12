package scope

import "testing"

func TestMatches(t *testing.T) {
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
		if got := Matches(c.host, c.pat); got != c.want {
			t.Errorf("Matches(%q,%q)=%v want %v", c.host, c.pat, got, c.want)
		}
	}
}

func TestMatcher(t *testing.T) {
	if Matcher([]string{" ", ""}) != nil {
		t.Fatal("no entries should give a nil matcher")
	}
	m := Matcher([]string{" Example.COM "})
	if !m("API.example.com") || m("other.org") {
		t.Fatal("matcher should normalise entries and hosts")
	}
}
