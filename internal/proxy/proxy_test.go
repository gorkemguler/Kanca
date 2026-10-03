package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gorkemguler/kanca/internal/cert"
	"github.com/gorkemguler/kanca/internal/proxy"
)

// newProxy starts an intercepting proxy on a random loopback port and returns
// it with the CA used to sign leaf certificates.
func newProxy(t *testing.T) (*proxy.Proxy, *cert.Authority) {
	t.Helper()
	ca, err := cert.NewEphemeralAuthority()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	p, err := proxy.New(proxy.Config{Addr: "127.0.0.1:0", CA: ca, InsecureUpstream: true})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = p.Stop(ctx)
	})
	return p, ca
}

// clientThrough builds an http.Client that routes through the proxy and trusts
// the proxy's root CA for intercepted HTTPS.
func clientThrough(t *testing.T, p *proxy.Proxy, ca *cert.Authority) *http.Client {
	t.Helper()
	proxyURL, _ := url.Parse("http://" + p.Addr())
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.RootCertPEM()) {
		t.Fatal("append root ca")
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

func TestProxyCapturesHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "ok")
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	defer backend.Close()

	p, ca := newProxy(t)
	var got *proxy.Flow
	var mu sync.Mutex
	done := make(chan struct{}, 1)
	p.OnFlow(func(f *proxy.Flow) {
		mu.Lock()
		got = f
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	client := clientThrough(t, p, ca)
	resp, err := client.Get(backend.URL + "/greet")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello /greet" {
		t.Fatalf("body = %q", body)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("flow not captured")
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Method != "GET" || got.StatusCode != 200 {
		t.Fatalf("flow = %+v", got)
	}
	if got.Response.Headers.Get("X-Backend") != "ok" {
		t.Fatalf("missing backend header: %v", got.Response.Headers)
	}
}

func TestProxyInterceptsHTTPS(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "secure %s", r.URL.Path)
	}))
	defer backend.Close()

	p, ca := newProxy(t)
	captured := make(chan *proxy.Flow, 1)
	p.OnFlow(func(f *proxy.Flow) { captured <- f })

	client := clientThrough(t, p, ca)
	resp, err := client.Get(backend.URL + "/vault")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secure /vault" {
		t.Fatalf("body = %q", body)
	}

	select {
	case f := <-captured:
		if f.Scheme != "https" {
			t.Fatalf("scheme = %q", f.Scheme)
		}
		if f.StatusCode != 200 {
			t.Fatalf("status = %d", f.StatusCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("https flow not captured")
	}
}

func TestInterceptorDropsRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be reached on drop")
	}))
	defer backend.Close()

	p, ca := newProxy(t)
	ic := p.Interceptor()
	ic.SetEnabled(true)
	// Auto-drop every held request.
	p.OnHold(func(h *proxy.Held) {
		ic.Resolve(h.ID, proxy.DecisionDrop, nil)
	})

	client := clientThrough(t, p, ca)
	resp, err := client.Get(backend.URL + "/blocked")
	if err == nil {
		// Plain-HTTP drop surfaces as a 403 from the proxy.
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected drop, got status %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestInterceptorEditsRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hdr=%s", r.Header.Get("X-Injected"))
	}))
	defer backend.Close()

	p, ca := newProxy(t)
	ic := p.Interceptor()
	ic.SetEnabled(true)
	p.OnHold(func(h *proxy.Held) {
		if h.Direction != proxy.DirectionRequest {
			ic.Resolve(h.ID, proxy.DecisionForward, nil)
			return
		}
		// Inject a header into the raw request before forwarding.
		edited := injectHeader(h.Raw, "X-Injected: kanca")
		ic.Resolve(h.ID, proxy.DecisionForward, edited)
	})

	client := clientThrough(t, p, ca)
	resp, err := client.Get(backend.URL + "/echo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hdr=kanca" {
		t.Fatalf("edit not applied, body = %q", body)
	}
}

// injectHeader inserts a header line after the request line of raw HTTP bytes.
func injectHeader(raw []byte, header string) []byte {
	const sep = "\r\n"
	i := indexOf(raw, []byte(sep))
	if i < 0 {
		return raw
	}
	out := make([]byte, 0, len(raw)+len(header)+2)
	out = append(out, raw[:i+len(sep)]...)
	out = append(out, []byte(header+sep)...)
	out = append(out, raw[i+len(sep):]...)
	return out
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func TestStopReleasesHeldRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	p, ca := newProxy(t)
	ic := p.Interceptor()
	ic.SetEnabled(true)

	held := make(chan struct{}, 1)
	// OnHold intentionally does NOT resolve — the request stays paused.
	p.OnHold(func(*proxy.Held) {
		select {
		case held <- struct{}{}:
		default:
		}
	})

	client := clientThrough(t, p, ca)
	go func() { _, _ = client.Get(backend.URL + "/hangs") }()

	select {
	case <-held:
	case <-time.After(2 * time.Second):
		t.Fatal("request was never held")
	}

	// Stop must return promptly even though a request is paused: it releases
	// held items before shutting the listener down.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := p.Stop(ctx); err != nil {
		t.Fatalf("stop returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stop took too long (%v); held request was not released", elapsed)
	}
}

func TestInterceptsAndEditsResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "orig") // 4 bytes
	}))
	defer backend.Close()

	p, ca := newProxy(t)
	ic := p.Interceptor()
	ic.SetEnabled(true)
	ic.SetInterceptResponses(true)
	p.OnHold(func(h *proxy.Held) {
		if h.Direction == proxy.DirectionResponse {
			// Same-length swap keeps Content-Length valid.
			edited := replaceBytes(h.Raw, "orig", "XXXX")
			ic.Resolve(h.ID, proxy.DecisionForward, edited)
			return
		}
		ic.Resolve(h.ID, proxy.DecisionForward, nil)
	})

	client := clientThrough(t, p, ca)
	resp, err := client.Get(backend.URL + "/r")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "XXXX" {
		t.Fatalf("response edit not applied, body = %q", body)
	}
}

func replaceBytes(raw []byte, old, new string) []byte {
	i := indexOf(raw, []byte(old))
	if i < 0 {
		return raw
	}
	out := append([]byte(nil), raw[:i]...)
	out = append(out, []byte(new)...)
	out = append(out, raw[i+len(old):]...)
	return out
}

func TestRewriterModifiesRequestAndResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "seen=%s", r.Header.Get("X-Test"))
	}))
	defer backend.Close()

	p, ca := newProxy(t)
	// Request: inject a header. Response: swap a same-length token so the
	// caller-supplied Content-Length stays valid (a rewriter is trusted to
	// keep it consistent; the rules package does this automatically).
	p.SetRewriter(func(phase, host string, raw []byte) []byte {
		if phase == "request" {
			return injectHeader(raw, "X-Test: injected")
		}
		return replaceBytes(raw, "injected", "OVERRIDE") // 8 == 8, length preserved
	})

	client := clientThrough(t, p, ca)
	resp, err := client.Get(backend.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "seen=OVERRIDE" {
		t.Fatalf("rewrite pipeline wrong, body = %q", body)
	}
}
