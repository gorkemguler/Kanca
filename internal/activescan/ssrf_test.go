package activescan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func runSSRF(t *testing.T, host, raw string, aggressive bool) []string {
	t.Helper()
	fs, err := Run(context.Background(), Config{
		Scheme: "http", Host: host, Raw: []byte(raw),
		InsecureUpstream: true, Aggressive: aggressive, TimeDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var out []string
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}

func TestSSRFCandidate(t *testing.T) {
	cases := map[string]struct {
		label, orig string
		want        bool
	}{
		"url-named":    {"url", "1", true},
		"redirect":     {"redirect_uri", "x", true},
		"value-is-url": {"q", "https://example.com/a", true},
		"value-host":   {"q", "cdn.example.com/x", true},
		"plain":        {"q", "socks", false},
		"number":       {"id", "42", false},
	}
	for name, c := range cases {
		if got := ssrfCandidate(insertionPoint{label: c.label, orig: c.orig}); got != c.want {
			t.Errorf("%s: ssrfCandidate(%q,%q)=%v want %v", name, c.label, c.orig, got, c.want)
		}
	}
}

func TestSSRFDetectsCloudMetadata(t *testing.T) {
	// A fetcher that proxies whatever ?url= points at; here it "reaches" the
	// metadata service and echoes a distinctive marker.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if strings.Contains(u, "169.254.169.254") {
			fmt.Fprint(w, "ami-id\ninstance-id\niam/security-credentials/role")
			return
		}
		fmt.Fprint(w, "<html>nothing fetched</html>")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runSSRF(t, u.Host, "GET /fetch?url=https://example.com HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", true)
	if !has(got, "Possible SSRF (cloud metadata) in url") {
		t.Fatalf("expected a metadata SSRF finding, got %v", got)
	}
}

func TestSSRFDetectsFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("dest")
		if strings.HasPrefix(u, "http") && !strings.Contains(u, "example.com") {
			fmt.Fprint(w, "Warning: file_get_contents(): failed to open stream: Connection refused")
			return
		}
		fmt.Fprint(w, "<html>ok</html>")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runSSRF(t, u.Host, "GET /go?dest=https://example.com/a HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", true)
	if !has(got, "Possible SSRF in dest") {
		t.Fatalf("expected a fetch-error SSRF finding, got %v", got)
	}
}

func TestSSRFNoSignalNoFinding(t *testing.T) {
	// A server that echoes the value back verbatim must not look like SSRF
	// (reflection is caught by its own check, not this one).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html>you asked for %s</html>", r.URL.Query().Get("url"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runSSRF(t, u.Host, "GET /p?url=https://example.com HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", true)
	if has(got, "SSRF") {
		t.Fatalf("plain reflection should not be reported as SSRF: %v", got)
	}
}

func TestSSRFOnlyUnderAggressive(t *testing.T) {
	var metadataProbes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "169.254.169.254") {
			metadataProbes++
		}
		fmt.Fprint(w, "<html>ok</html>")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if got := runSSRF(t, u.Host, "GET /fetch?url=https://example.com HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", false); has(got, "SSRF") {
		t.Fatalf("SSRF probed without Aggressive: %v", got)
	}
	if metadataProbes != 0 {
		t.Fatalf("SSRF sent %d metadata probes without Aggressive, want 0", metadataProbes)
	}
}
