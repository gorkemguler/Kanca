package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
)

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
	status := f.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	if f.Response.Truncated && f.responseStream != nil {
		// The stored body is only the inspected prefix; stream the complete
		// upstream payload so the client receives what the server sent.
		if f.Response.ContentLength >= 0 {
			dst.Set("Content-Length", fmt.Sprintf("%d", f.Response.ContentLength))
		}
		w.WriteHeader(status)
		_, _ = io.Copy(w, f.responseStream)
		_ = f.responseStream.Close()
		return
	}
	dst.Set("Content-Length", fmt.Sprintf("%d", len(f.Response.Body)))
	w.WriteHeader(status)
	_, _ = w.Write(f.Response.Body)
}

// writeCapturedResponseConn writes a captured response directly onto a raw
// (decrypted-tunnel) connection. f.Response.Raw is already a well-formed
// HTTP/1.1 message with a corrected Content-Length, but it only holds the
// stored prefix; truncated responses are relayed as a head plus their live
// body stream.
func writeCapturedResponseConn(conn net.Conn, f *Flow) error {
	if !f.Response.Truncated || f.responseStream == nil {
		_, err := conn.Write(f.Response.Raw)
		return err
	}

	var head bytes.Buffer
	proto := f.responseProto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	status := f.responseStatus
	if status == "" {
		status = fmt.Sprintf("%d %s", f.StatusCode, http.StatusText(f.StatusCode))
	}
	fmt.Fprintf(&head, "%s %s\r\n", proto, status)
	n := f.Response.ContentLength
	if n < 0 {
		// No declared length: delimit the body by closing the connection.
		f.responseClose = true
		head.WriteString("Connection: close\r\n")
	}
	writeHeadersLen(&head, f.Response.Headers, n)
	head.WriteString("\r\n")

	if _, err := conn.Write(head.Bytes()); err != nil {
		_ = f.responseStream.Close()
		return err
	}
	_, err := io.Copy(conn, f.responseStream)
	_ = f.responseStream.Close()
	return err
}

// writeRawError sends a minimal 502 back over a raw connection.
func writeRawError(conn net.Conn, msg string) {
	body := []byte(msg)
	fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	_, _ = conn.Write(body)
}
