package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorkemguler/kanca/internal/proxy"
)

type builtinStatus struct {
	Kanca   bool   `json:"kanca"`
	Proxied bool   `json:"proxied"`
	Listen  string `json:"listen"`
}

func TestBuiltinStatusThroughProxyIsNotRecorded(t *testing.T) {
	p, ca := newProxy(t)
	var flows atomic.Int32
	p.OnFlow(func(*proxy.Flow) { flows.Add(1) })

	resp, err := clientThrough(t, p, ca).Get("http://kanca/status")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var st builtinStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !st.Kanca || !st.Proxied || st.Listen != p.Addr() {
		t.Fatalf("status = %+v, want kanca+proxied on %s", st, p.Addr())
	}
	time.Sleep(100 * time.Millisecond)
	if n := flows.Load(); n != 0 {
		t.Fatalf("builtin request was recorded as %d flow(s)", n)
	}
}

func TestBuiltinServesRootCertificate(t *testing.T) {
	p, ca := newProxy(t)
	resp, err := clientThrough(t, p, ca).Get("http://kanca/cert")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(ca.RootCertPEM()) {
		t.Fatalf("cert body does not match the root CA:\n%s", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-x509-ca-cert" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestBuiltinPageThroughProxy(t *testing.T) {
	p, ca := newProxy(t)
	resp, err := clientThrough(t, p, ca).Get("http://kanca/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "routed through Kanca") {
		t.Fatalf("status %d, body:\n%s", resp.StatusCode, body)
	}
}

func TestBuiltinDirectRequestReportsNotProxied(t *testing.T) {
	p, _ := newProxy(t)
	resp, err := http.Get("http://" + p.Addr() + "/status")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var st builtinStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !st.Kanca || st.Proxied {
		t.Fatalf("status = %+v, want kanca and not proxied", st)
	}
}

// directGet sends an origin-form request straight to the listener with the given
// Host header, as a page that DNS-rebinds onto the proxy port would.
func directGet(t *testing.T, p *proxy.Proxy, host string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://"+p.Addr()+"/", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestDirectRequestWithForeignHostIsRefused(t *testing.T) {
	p, _ := newProxy(t)
	if code := directGet(t, p, "evil.example"); code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

func TestDirectRequestIsNeverRelayed(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer backend.Close()

	p, _ := newProxy(t)
	directGet(t, p, strings.TrimPrefix(backend.URL, "http://"))
	if n := hits.Load(); n != 0 {
		t.Fatalf("origin-form request was relayed to %s %d time(s)", backend.URL, n)
	}
}
