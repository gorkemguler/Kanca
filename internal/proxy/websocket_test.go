package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // required by RFC 6455's handshake, not for security
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorkemguler/mimlec/internal/cert"
)

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAcceptKey(key string) string {
	h := sha1.New() //nolint:gosec
	h.Write([]byte(key + wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func randomWSKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// wsEchoServer is a minimal hand-rolled RFC 6455 server: it completes the
// handshake and echoes every frame it receives back unmasked, closing on a
// Close frame or read error. No external WebSocket library is used, keeping
// the core module dependency-free even in tests.
func wsEchoServer(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				accept := wsAcceptKey(req.Header.Get("Sec-WebSocket-Key"))
				fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
				for {
					_, f, err := readWSFrame(br)
					if err != nil {
						return
					}
					if f.Opcode == WSOpClose {
						return
					}
					if werr := writeWSFrame(conn, f.Opcode, false, f.Payload); werr != nil {
						return
					}
				}
			}()
		}
	}()
	return ln
}

func TestWebSocketPlainEndToEnd(t *testing.T) {
	backend := wsEchoServer(t)
	defer backend.Close()
	backendHost := backend.Addr().String()

	ca, err := cert.NewEphemeralAuthority()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	p, err := New(Config{Addr: "127.0.0.1:0", CA: ca, InsecureUpstream: true})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	opened := make(chan string, 1)
	closed := make(chan string, 1)
	frames := make(chan WSFrame, 8)
	p.OnWSOpen(func(id int64, host, url string) { opened <- host })
	p.OnWSClose(func(id int64, host, url string) { closed <- host })
	p.OnWSFrame(func(id int64, host, url string, f WSFrame) { frames <- f })

	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Stop(ctx)
	}()

	// Dial the proxy directly and speak the handshake in absolute-form, the
	// way a browser configured with an HTTP proxy would for a ws:// URL.
	clientConn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer clientConn.Close()

	key := randomWSKey(t)
	fmt.Fprintf(clientConn, "GET http://%s/ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		backendHost, backendHost, key)

	br := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	wantAccept := wsAcceptKey(key)
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wantAccept {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q (proxy must relay the handshake verbatim)", got, wantAccept)
	}

	select {
	case host := <-opened:
		if host != backendHost {
			t.Fatalf("OnWSOpen host = %q, want %q", host, backendHost)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnWSOpen never fired")
	}

	// Client -> server: masked text frame, expect it echoed back unmasked.
	if err := writeWSFrame(clientConn, WSOpText, true, []byte("hello")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	_, echoed, err := readWSFrame(br)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echoed.Masked || echoed.Opcode != WSOpText || string(echoed.Payload) != "hello" {
		t.Fatalf("echo wrong: %+v", echoed)
	}

	// Both directions must have been captured via OnWSFrame.
	var sawClientToServer, sawServerToClient bool
	for i := 0; i < 2; i++ {
		select {
		case f := <-frames:
			switch f.Direction {
			case "client->server":
				sawClientToServer = true
				if string(f.Payload) != "hello" {
					t.Fatalf("captured client frame payload = %q", f.Payload)
				}
			case "server->client":
				sawServerToClient = true
			default:
				t.Fatalf("unexpected direction %q", f.Direction)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for captured frames")
		}
	}
	if !sawClientToServer || !sawServerToClient {
		t.Fatalf("missing capture: client->server=%v server->client=%v", sawClientToServer, sawServerToClient)
	}

	// Closing the client side must unwind the whole bridge (proves the
	// cross-close logic actually unblocks the other direction) and fire
	// OnWSClose rather than hanging forever.
	clientConn.Close()
	select {
	case host := <-closed:
		if host != backendHost {
			t.Fatalf("OnWSClose host = %q, want %q", host, backendHost)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnWSClose never fired; bridge likely leaked a blocked goroutine")
	}
}

func TestWebSocketUpgradeNotBrokenByHopByHopStripping(t *testing.T) {
	// Regression guard: a plain (non-WebSocket) request must still have its
	// Connection/Upgrade headers treated as hop-by-hop as before; only an
	// actual WebSocket upgrade should take the dedicated bridging path.
	h := http.Header{}
	h.Set("Connection", "keep-alive")
	if isWebSocketUpgrade(h) {
		t.Fatal("plain keep-alive request misdetected as a WebSocket upgrade")
	}
	h.Set("Connection", "Upgrade")
	h.Set("Upgrade", "h2c") // some other upgrade protocol, not websocket
	if isWebSocketUpgrade(h) {
		t.Fatal("non-websocket Upgrade misdetected as a WebSocket upgrade")
	}
	h.Set("Upgrade", "websocket")
	if !isWebSocketUpgrade(h) {
		t.Fatal("genuine websocket upgrade not detected")
	}
	// Real browsers send "Connection: keep-alive, Upgrade" for the handshake.
	h.Set("Connection", "keep-alive, Upgrade")
	if !isWebSocketUpgrade(h) {
		t.Fatal("comma-separated Connection token list not handled")
	}
}
