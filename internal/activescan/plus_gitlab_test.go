package activescan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGitLabStatus(t *testing.T) {
	for v, want := range map[string][2]bool{ // {critical, partial}
		"19.5.0-ee":  {true, false},
		"19.5.1-ee":  {false, false},
		"19.4.2":     {true, false},
		"19.4.3-ee":  {false, false},
		"19.3.6":     {false, false},
		"19.2.8":     {true, false},
		"19.2.9-ee":  {false, true},
		"19.0.10":    {false, true},
		"18.11.13":   {false, true},
		"18.11.12":   {true, false},
		"18.10.20":   {true, false},
		"17.11.0":    {true, false},
		"19.6.0-pre": {false, false},
		"20.0.0":     {false, false},
	} {
		critical, partial, ok := gitlabStatus(v)
		if !ok || critical != want[0] || partial != want[1] {
			t.Errorf("%s: critical=%v partial=%v ok=%v, want %v", v, critical, partial, ok, want)
		}
	}
	if _, _, ok := gitlabStatus("unknown"); ok {
		t.Error("a non-version string was classified")
	}
}

// gitlabServer serves a GitLab page and answers /api/v4/version with version,
// but only to a request carrying the session cookie.
func gitlabServer(version string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/version" {
			if c, err := r.Cookie("_gitlab_session"); err != nil || c.Value != "s" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"message":"401 Unauthorized"}`)
				return
			}
			fmt.Fprintf(w, `{"version":%q,"revision":"abc123"}`, version)
			return
		}
		fmt.Fprint(w, `<html><head><meta content="GitLab" property="og:site_name"></head><body>Sign in</body></html>`)
	}))
}

func TestGitLabVersionChecks(t *testing.T) {
	signedIn := "GET /explore HTTP/1.1\r\nHost: HOST\r\nCookie: _gitlab_session=s\r\n\r\n"
	for _, tc := range []struct {
		version, raw, want, notWant string
	}{
		{"19.4.2-ee", signedIn, "GitLab version affected by CVE-2026-110264", "missing fixes"},
		{"19.2.9-ee", signedIn, "GitLab version missing fixes", "affected by CVE-2026-110264"},
		{"19.5.1-ee", signedIn, "", "GitLab version"},
		{"19.4.2-ee", "GET /explore HTTP/1.1\r\nHost: HOST\r\n\r\n", "GitLab instance: check its version", "affected by CVE-2026-110264"},
	} {
		srv := gitlabServer(tc.version)
		got := runPlus(t, srv, tc.raw)
		srv.Close()
		if tc.want != "" && !has(got, tc.want) {
			t.Errorf("%s: expected %q, got %v", tc.version, tc.want, got)
		}
		if has(got, tc.notWant) {
			t.Errorf("%s: unexpected %q in %v", tc.version, tc.notWant, got)
		}
	}
}

func TestGitLabCheckIgnoresOtherSites(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/version" {
			fmt.Fprint(w, `{"version":"1.0.0"}`) // some other app's API
			return
		}
		fmt.Fprint(w, "<html><p>shop</p></html>")
	}))
	defer srv.Close()
	if got := runPlus(t, srv, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n"); has(got, "GitLab") {
		t.Fatalf("a site that isn't GitLab got GitLab findings: %v", got)
	}
}
