package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// hopByHopHeaders are connection-scoped and must not be forwarded to the
// upstream server or back to the client verbatim.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// requestToRaw serialises req into on-the-wire HTTP/1.1 bytes using origin
// form (the request line carries only the path). body is the already-buffered
// request body. The result is what the interceptor exposes for editing.
func requestToRaw(req *http.Request, body []byte) []byte {
	var b bytes.Buffer
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, path)
	// Host header first for readability, mirroring how servers expect it.
	fmt.Fprintf(&b, "Host: %s\r\n", req.Host)
	writeHeaders(&b, req.Header, body)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

// responseToRaw serialises resp into on-the-wire bytes for display/editing.
func responseToRaw(resp *http.Response, body []byte) []byte {
	var b bytes.Buffer
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&b, "%s %s\r\n", proto, resp.Status)
	writeHeaders(&b, resp.Header, body)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func writeHeaders(b *bytes.Buffer, h http.Header, body []byte) {
	for key, vals := range h {
		if key == "Host" {
			continue // written explicitly by the caller
		}
		if _, hop := hopByHopHeaders[http.CanonicalHeaderKey(key)]; hop {
			continue
		}
		if http.CanonicalHeaderKey(key) == "Content-Length" {
			continue // recomputed below to match the actual body
		}
		for _, v := range vals {
			fmt.Fprintf(b, "%s: %s\r\n", key, v)
		}
	}
	fmt.Fprintf(b, "Content-Length: %d\r\n", len(body))
}

// rawToRequest parses possibly user-edited raw bytes back into a request bound
// for the given scheme and default authority. The caller supplies scheme
// ("http"/"https") and host so an origin-form request line can be resolved to
// an absolute upstream target.
func rawToRequest(raw []byte, scheme, host string) (*http.Request, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, fmt.Errorf("proxy: parse edited request: %w", err)
	}
	authority := req.Host
	if authority == "" {
		authority = host
	}
	u, err := url.Parse(req.RequestURI)
	if err != nil || !u.IsAbs() {
		// Origin-form: rebuild an absolute URL from scheme + authority.
		u = &url.URL{Scheme: scheme, Host: authority, Opaque: ""}
		if parsed, perr := url.ParseRequestURI(req.RequestURI); perr == nil {
			u.Path = parsed.Path
			u.RawQuery = parsed.RawQuery
		} else {
			u.Path = req.RequestURI
		}
	}
	req.URL = u
	req.RequestURI = "" // must be cleared for client-side requests
	req.Host = authority
	return req, nil
}

// rawToResponse parses raw bytes back into a response associated with req.
func rawToResponse(raw []byte, req *http.Request) (*http.Response, error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse edited response: %w", err)
	}
	return resp, nil
}

// stripHopByHop removes connection-scoped headers from h in place.
func stripHopByHop(h http.Header) {
	// Honour any hop-by-hop headers named in the Connection header too.
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for name := range hopByHopHeaders {
		h.Del(name)
	}
}

// drain fully reads and closes r, discarding the contents. Used to release
// upstream connections back to the transport's pool on error paths.
func drain(r io.ReadCloser) {
	if r == nil {
		return
	}
	_, _ = io.Copy(io.Discard, r)
	_ = r.Close()
}
