package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorkemguler/kanca/internal/cert"
)

func startTestProxy(t *testing.T) *Proxy {
	t.Helper()
	ca, err := cert.NewEphemeralAuthority()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	p, err := New(Config{Addr: "127.0.0.1:0", CA: ca, InsecureUpstream: true})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Stop(ctx)
	})
	return p
}

// openPlainTunnel sends CONNECT for target and returns the connection once the
// proxy has accepted it, without starting TLS: what Chromium does for ws://.
func openPlainTunnel(t *testing.T, p *Proxy, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	return conn, br
}

func TestPlainWebSocketThroughConnectTunnel(t *testing.T) {
	backend := wsEchoServer(t)
	defer backend.Close()
	backendHost := backend.Addr().String()

	p := startTestProxy(t)
	opened := make(chan string, 1)
	frames := make(chan WSFrame, 8)
	p.OnWSOpen(func(id int64, host, url string) { opened <- url })
	p.OnWSFrame(func(id int64, host, url string, f WSFrame) { frames <- f })
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	conn, br := openPlainTunnel(t, p, backendHost)
	key := randomWSKey(t)
	fmt.Fprintf(conn, "GET /chat HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		backendHost, key)

	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wsAcceptKey(key) {
		t.Fatalf("Sec-WebSocket-Accept = %q", got)
	}

	select {
	case url := <-opened:
		if want := "ws://" + backendHost + "/chat"; url != want {
			t.Fatalf("session URL = %q, want %q", url, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WebSocket session was not captured")
	}

	if err := writeWSFrame(conn, WSOpText, true, []byte("hi")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if _, echoed, err := readWSFrame(br); err != nil || string(echoed.Payload) != "hi" {
		t.Fatalf("echo = %+v, err %v", echoed, err)
	}
	select {
	case f := <-frames:
		if string(f.Payload) != "hi" {
			t.Fatalf("captured frame = %q", f.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frame was not captured")
	}
}

func TestPlainHTTPThroughConnectTunnelIsCaptured(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain %s", r.URL.Path)
	}))
	defer backend.Close()
	backendHost := strings.TrimPrefix(backend.URL, "http://")

	p := startTestProxy(t)
	flows := make(chan *Flow, 1)
	p.OnFlow(func(f *Flow) { flows <- f })
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	conn, br := openPlainTunnel(t, p, backendHost)
	fmt.Fprintf(conn, "GET /hello HTTP/1.1\r\nHost: %s\r\n\r\n", backendHost)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "plain /hello" {
		t.Fatalf("body = %q", body)
	}

	select {
	case f := <-flows:
		if f.Scheme != "http" || f.URL != "http://"+backendHost+"/hello" {
			t.Fatalf("flow scheme=%q url=%q, want plain http", f.Scheme, f.URL)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request through the plaintext tunnel was not recorded")
	}
}
