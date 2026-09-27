package proxy

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
)

// bytesReader adapts a byte slice to an io.Reader with a known length.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// writeCapturedResponse relays a captured Flow's response through a standard
// http.ResponseWriter (the plain-HTTP proxy path).
func writeCapturedResponse(w http.ResponseWriter, f *Flow) {
	dst := w.Header()
	for k, vs := range f.Response.Headers {
		if _, hop := hopByHopHeaders[http.CanonicalHeaderKey(k)]; hop {
			continue
		}
		if http.CanonicalHeaderKey(k) == "Content-Length" {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	dst.Set("Content-Length", fmt.Sprintf("%d", len(f.Response.Body)))
	status := f.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(f.Response.Body)
}

// writeCapturedResponseConn writes a captured response directly onto a raw
// (decrypted-tunnel) connection. f.Response.Raw is already a well-formed
// HTTP/1.1 message with a corrected Content-Length.
func writeCapturedResponseConn(conn net.Conn, f *Flow) error {
	_, err := conn.Write(f.Response.Raw)
	return err
}

// writeRawError sends a minimal 502 back over a raw connection.
func writeRawError(conn net.Conn, msg string) {
	body := []byte(msg)
	fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	_, _ = conn.Write(body)
}
