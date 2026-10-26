package activescan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// phpCrashServer answers a big multipart body the way a crashing PHP would, per
// mode, and gives the control (small) request real output.
func phpCrashServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 512*1024 {
			switch mode {
			case "oom":
				fmt.Fprint(w, "<b>Fatal error</b>: Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0")
			case "gateway":
				w.WriteHeader(http.StatusBadGateway)
			case "empty500":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				fmt.Fprint(w, "<html>ok</html>")
			}
			return
		}
		fmt.Fprint(w, "<html>ok</html>")
	}))
}

func runCrash(t *testing.T, srv *httptest.Server, aggressive bool) []string {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	raw := []byte("GET / HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	fs, err := Run(context.Background(), Config{
		Scheme: "http", Host: u.Host, Raw: raw,
		Plus: true, Aggressive: aggressive, TimeDelay: time.Millisecond,
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

func TestCrashProbeDetectsOOM(t *testing.T) {
	srv := phpCrashServer("oom")
	defer srv.Close()
	if !has(runCrash(t, srv, true), "PHP crash via malformed multipart") {
		t.Fatal("expected the OOM fatal to be detected")
	}
}

func TestCrashProbeDetectsGatewayError(t *testing.T) {
	srv := phpCrashServer("gateway")
	defer srv.Close()
	if !has(runCrash(t, srv, true), "PHP crash via malformed multipart") {
		t.Fatal("expected a dead-worker gateway error to be detected")
	}
}

func TestCrashProbeDetectsEmpty500(t *testing.T) {
	srv := phpCrashServer("empty500")
	defer srv.Close()
	if !has(runCrash(t, srv, true), "PHP crash via malformed multipart") {
		t.Fatal("expected an empty 500 to be detected after confirmation")
	}
}

func TestCrashProbeCleanServer(t *testing.T) {
	srv := phpCrashServer("clean")
	defer srv.Close()
	if has(runCrash(t, srv, true), "PHP crash") {
		t.Fatal("a server that answers large bodies normally is not a crash")
	}
}

func TestCrashProbeOnlyUnderAggressive(t *testing.T) {
	// Count how many large bodies the server sees; without Aggressive, none.
	var large int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 512*1024 {
			large++
		}
		fmt.Fprint(w, "<html>ok</html>")
	}))
	defer srv.Close()
	if got := runCrash(t, srv, false); has(got, "PHP crash") {
		t.Fatalf("crash probe ran without Aggressive: %v", got)
	}
	if large != 0 {
		t.Fatalf("Plus without Aggressive sent %d large probe bodies, want 0", large)
	}
}
