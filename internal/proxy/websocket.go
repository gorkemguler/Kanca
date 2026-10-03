package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// isWebSocketUpgrade reports whether h carries the headers of a WebSocket
// handshake request (RFC 6455 §4.1): Connection: Upgrade and
// Upgrade: websocket. Both are checked as comma-separated token lists, since
// browsers may send "Connection: keep-alive, Upgrade".
func isWebSocketUpgrade(h http.Header) bool {
	return headerHasToken(h, "Connection", "upgrade") && strings.EqualFold(strings.TrimSpace(h.Get("Upgrade")), "websocket")
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// pipeAndCapture copies bytes from src to dst one WebSocket frame at a time,
// invoking onFrame for each successfully parsed frame. It always relays every
// byte it manages to read from src, even when a frame fails to parse (a
// truncated read, an oversized length field, or plain non-WebSocket garbage):
// proxying stays byte-transparent regardless of whether capture succeeds. On
// a parse error other than a clean EOF, it stops parsing and falls back to a
// raw io.Copy for the remainder of the stream so the connection is never
// broken by a framing edge case Kanca doesn't understand (e.g. an
// extension it doesn't decode).
func pipeAndCapture(direction string, src io.Reader, dst io.Writer, onFrame func(WSFrame)) {
	for {
		raw, frame, err := readWSFrame(src)
		if len(raw) > 0 {
			if _, werr := dst.Write(raw); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				_, _ = io.Copy(dst, src)
			}
			return
		}
		frame.Direction = direction
		if onFrame != nil {
			onFrame(frame)
		}
	}
}

// websocketHandshakeRequest serialises req's handshake verbatim: unlike
// requestToRaw, it preserves Upgrade/Connection and every Sec-WebSocket-*
// header rather than treating them as hop-by-hop, since the upstream server
// needs them intact to complete the handshake.
func websocketHandshakeRequest(req *http.Request) []byte {
	var b bytes.Buffer
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", req.Host)
	for k, vals := range req.Header {
		if k == "Host" {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// websocketHandshakeResponse serialises resp's status line and headers
// verbatim (including Upgrade/Connection/Sec-WebSocket-Accept), with no body.
func websocketHandshakeResponse(resp *http.Response) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// handleWebSocketPlain proxies a ws:// (unencrypted) upgrade: it hijacks the
// client connection, dials the target in plain TCP, performs the handshake,
// and bridges frames once the upstream confirms with 101.
func (p *Proxy) handleWebSocketPlain(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	host := r.Host
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		host = net.JoinHostPort(host, "80")
	}
	upstream, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		writeRawError(clientConn, "websocket upstream dial failed: "+err.Error())
		return
	}
	defer upstream.Close()

	// bufrw.Reader may already hold bytes read from the socket ahead of the
	// parsed request line/headers; it transparently continues from clientConn
	// once exhausted, so it is the correct reader for anything the client
	// sends after the handshake.
	p.bridgeWebSocket(bufrw.Reader, clientConn, func() { _ = clientConn.Close() }, upstream, r, host, "ws")
}

// handleWebSocketTunnel proxies a wss:// upgrade discovered inside an
// already-decrypted CONNECT tunnel. It dials the upstream over TLS, performs
// the handshake, and on success bridges frames — taking over the connection
// for the remainder of its life (the caller's request-read loop must stop).
func (p *Proxy) handleWebSocketTunnel(conn net.Conn, br *bufio.Reader, req *http.Request, authority string) {
	upstream, err := tls.Dial("tcp", authority, &tls.Config{
		InsecureSkipVerify: p.cfg.InsecureUpstream, //nolint:gosec // deliberate for interception
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		writeRawError(conn, "websocket upstream TLS dial failed: "+err.Error())
		return
	}
	defer upstream.Close()

	p.bridgeWebSocket(br, conn, func() { _ = conn.Close() }, upstream, req, authority, "wss")
}

// bridgeWebSocket performs the upstream handshake, relays the response back
// to the client, and — only on a 101 Switching Protocols — bridges frames in
// both directions (with best-effort capture) until either side closes.
// closeClient closes the client connection; it is invoked (alongside closing
// upstream) as soon as either direction ends, so a peer closing its side
// promptly unblocks the other side's blocked Read instead of leaking a
// goroutine that waits forever for a peer that already left.
func (p *Proxy) bridgeWebSocket(clientReader io.Reader, clientWriter io.Writer, closeClient func(), upstream io.ReadWriteCloser, req *http.Request, authority, scheme string) {
	if _, err := upstream.Write(websocketHandshakeRequest(req)); err != nil {
		return
	}

	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		return
	}
	// bodyAllowedForStatus(101) is false in net/http, so ReadResponse never
	// consumes bytes past the header block for a Switching Protocols reply;
	// upstreamReader is already correctly positioned for the frame stream.
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	if _, err := clientWriter.Write(websocketHandshakeResponse(resp)); err != nil {
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return // upstream declined the upgrade; nothing more to bridge
	}

	url := scheme + "://" + authority + req.URL.RequestURI()
	id := nextFlowID()
	host := authority
	p.emitWSOpen(id, host, url)
	onFrame := func(f WSFrame) { p.emitWSFrame(id, host, url, f) }

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = upstream.Close()
			closeClient()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipeAndCapture("client->server", clientReader, upstream, onFrame)
		closeBoth() // client is gone (or errored): unblock the server->client reader too
	}()
	go func() {
		defer wg.Done()
		pipeAndCapture("server->client", upstreamReader, clientWriter, onFrame)
		closeBoth() // server is gone (or errored): unblock the client->server reader too
	}()
	wg.Wait()
	p.emitWSClose(id, host, url)
}
