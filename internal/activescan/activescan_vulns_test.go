package activescan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// multiVuln simulates a target with one deliberately weak behaviour per path, so
// each detection class can be exercised in isolation.
func multiVuln() *httptest.Server {
	mux := http.NewServeMux()

	// Open redirect: echoes the "next" parameter into Location.
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("next"))
		w.WriteHeader(http.StatusFound)
	})
	// Path traversal: returns /etc/passwd contents when the path escapes upward.
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if strings.Contains(p, "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
			return
		}
		fmt.Fprint(w, "default content")
	})
	// SSTI: evaluates a trivial arithmetic expression.
	mux.HandleFunc("/tpl", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.Contains(name, "991*991") {
			fmt.Fprint(w, "Hello 982081")
			return
		}
		fmt.Fprintf(w, "Hello %s", name)
	})
	// CRLF: reflects the raw "lang" value into a header (response splitting sink).
	mux.HandleFunc("/hdr", func(w http.ResponseWriter, r *http.Request) {
		lang := r.URL.Query().Get("lang")
		if i := strings.Index(lang, "\r\n"); i >= 0 {
			line := lang[i+2:]
			if k, v, ok := strings.Cut(line, ":"); ok {
				w.Header().Set(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
		fmt.Fprint(w, "ok")
	})
	// Boolean SQLi: a true condition returns the full list, false returns empty.
	mux.HandleFunc("/bsql", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'1'='2") {
			fmt.Fprint(w, "no results")
			return
		}
		fmt.Fprint(w, strings.Repeat("row ", 200)) // full list, both baseline and true
	})
	// Time-based SQLi / command injection: sleeps on a delay primitive.
	mux.HandleFunc("/tsql", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "SLEEP(") || strings.Contains(id, "WAITFOR") {
			time.Sleep(1200 * time.Millisecond)
		}
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/cmd", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "sleep 1") {
			time.Sleep(1200 * time.Millisecond)
		}
		fmt.Fprint(w, "ok")
	})
	// Form + JSON body sinks: reflect a field verbatim.
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fmt.Fprintf(w, "<p>%s</p>", r.PostForm.Get("comment"))
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "<p>%s</p>", string(b))
	})
	return httptest.NewServer(mux)
}

func runScan(t *testing.T, host, raw string, aggressive bool) []string {
	t.Helper()
	fs, err := Run(context.Background(), Config{
		Scheme: "http", Host: host, Raw: []byte(raw),
		InsecureUpstream: true, Aggressive: aggressive,
		TimeDelay: time.Second,
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

func has(titles []string, substr string) bool {
	for _, tl := range titles {
		if strings.Contains(tl, substr) {
			return true
		}
	}
	return false
}

func TestDetectsOpenRedirect(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runScan(t, u.Host, "GET /redir?next=/home HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", false)
	if !has(got, "open redirect in next") {
		t.Fatalf("expected open-redirect finding, got %v", got)
	}
}

func TestDetectsPathTraversal(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runScan(t, u.Host, "GET /file?path=readme.txt HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", false)
	if !has(got, "path traversal in path") {
		t.Fatalf("expected path-traversal finding, got %v", got)
	}
}

func TestDetectsSSTI(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runScan(t, u.Host, "GET /tpl?name=bob HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", false)
	if !has(got, "template injection in name") {
		t.Fatalf("expected SSTI finding, got %v", got)
	}
}

func TestDetectsCRLF(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runScan(t, u.Host, "GET /hdr?lang=en HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", false)
	if !has(got, "CRLF/header injection in lang") {
		t.Fatalf("expected CRLF finding, got %v", got)
	}
}

func TestDetectsBooleanSQLOnlyWhenAggressive(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	raw := "GET /bsql?id=1 HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n"

	if has(runScan(t, u.Host, raw, false), "boolean-based SQL injection") {
		t.Fatal("boolean SQLi should not run without Aggressive")
	}
	if !has(runScan(t, u.Host, raw, true), "boolean-based SQL injection in id") {
		t.Fatal("expected boolean SQLi finding under Aggressive")
	}
}

func TestDetectsTimeBasedSQLAggressive(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runScan(t, u.Host, "GET /tsql?id=1 HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", true)
	if !has(got, "time-based SQL injection in id") {
		t.Fatalf("expected time-based SQLi finding, got %v", got)
	}
}

func TestDetectsTimeBasedCommandAggressive(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := runScan(t, u.Host, "GET /cmd?q=hi HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n", true)
	if !has(got, "OS command injection in q") {
		t.Fatalf("expected command-injection finding, got %v", got)
	}
}

func TestDetectsReflectionInFormBody(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	raw := "POST /form HTTP/1.1\r\nHost: " + u.Host +
		"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\ncomment=hey"
	got := runScan(t, u.Host, raw, false)
	if !has(got, "Reflected input in comment") {
		t.Fatalf("expected reflected form-body finding, got %v", got)
	}
}

func TestDetectsReflectionInJSONBody(t *testing.T) {
	srv := multiVuln()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	body := `{"comment":"hey"}`
	raw := fmt.Sprintf("POST /json HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		u.Host, len(body), body)
	got := runScan(t, u.Host, raw, false)
	if !has(got, "Reflected input in comment") {
		t.Fatalf("expected reflected JSON-body finding, got %v", got)
	}
}
