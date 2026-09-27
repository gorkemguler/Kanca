package activescan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// vulnerableEcho reflects the "q" parameter verbatim and, for the "id"
// parameter, emits a fake MySQL error when the value contains a single quote —
// mimicking a reflected-XSS sink and an error-based SQLi sink for testing.
func vulnerableEcho() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			fmt.Fprint(w, "You have an error in your SQL syntax near ''")
			return
		}
		fmt.Fprintf(w, "<html>results for %s</html>", r.URL.Query().Get("q"))
	}))
}

func TestActiveScanFindsReflectionAndSQL(t *testing.T) {
	srv := vulnerableEcho()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	raw := []byte("GET /?q=hello&id=1 HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	findings, err := Run(context.Background(), Config{
		Scheme: "http", Host: u.Host, Raw: raw, InsecureUpstream: true,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	var reflected, sqli bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Reflected input in q") {
			reflected = true
		}
		if strings.Contains(f.Title, "Possible SQL injection in id") {
			sqli = true
		}
	}
	if !reflected {
		t.Errorf("expected reflected-input finding; got %+v", findings)
	}
	if !sqli {
		t.Errorf("expected SQL-injection indicator; got %+v", findings)
	}
}

func TestActiveScanCleanTargetNoFindings(t *testing.T) {
	// A server that HTML-escapes input and never errors should yield nothing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>static page, no reflection</html>")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	raw := []byte("GET /?q=hello&id=1 HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	findings, err := Run(context.Background(), Config{Scheme: "http", Host: u.Host, Raw: raw})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on a clean target, got %+v", findings)
	}
}

func TestActiveScanNoParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	raw := []byte("GET / HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	findings, err := Run(context.Background(), Config{Scheme: "http", Host: u.Host, Raw: raw})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("no query params: expected no findings, got %+v", findings)
	}
}
