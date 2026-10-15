package proxy_test

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// gzipEcho answers in gzip when asked and reports the Accept-Encoding it got.
func gzipEcho(t *testing.T, got chan<- string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Accept-Encoding")
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			io.WriteString(w, "plain body")
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, "compressed body")
		zw.Close()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProxyAsksOnlyForEncodingsItCanRead(t *testing.T) {
	got := make(chan string, 1)
	backend := gzipEcho(t, got)
	p, ca := newProxy(t)
	var mu sync.Mutex
	var flow *proxy.Flow
	done := make(chan struct{})
	p.OnFlow(func(f *proxy.Flow) {
		mu.Lock()
		flow = f
		mu.Unlock()
		close(done)
	})

	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd") // what Chrome and Edge send
	resp, err := clientThrough(t, p, ca).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ae := <-got; ae != "gzip, deflate" {
		t.Fatalf("server was asked for %q, want only codings Kanca decodes", ae)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(string(flow.Request.Raw), "zstd") {
		t.Fatalf("history should show the request as sent:\n%s", flow.Request.Raw)
	}
	if string(flow.Response.DecodedBody()) != "compressed body" {
		t.Fatalf("decoded body = %q", flow.Response.DecodedBody())
	}
}

func TestSenderAsksOnlyForEncodingsItCanRead(t *testing.T) {
	got := make(chan string, 1)
	backend := gzipEcho(t, got)
	host := strings.TrimPrefix(backend.URL, "http://")
	raw := "GET / HTTP/1.1\r\nHost: " + host + "\r\nAccept-Encoding: br, zstd\r\n\r\n"
	f := proxy.NewSender(proxy.SenderConfig{}).Send(context.Background(), []byte(raw), "http", host)
	if f.Error != "" {
		t.Fatal(f.Error)
	}
	if ae := <-got; ae != "identity" {
		t.Fatalf("server was asked for %q, want identity", ae)
	}
	if !strings.Contains(string(f.Request.Raw), "Accept-Encoding: identity") || f.Response.DecodedBodyString() != "plain body" {
		t.Fatalf("request:\n%s\nbody: %q", f.Request.Raw, f.Response.DecodedBody())
	}
}
