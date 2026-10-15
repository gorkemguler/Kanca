package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
)

// DecodeBody returns a human-readable form of body given the message headers,
// transparently undoing Content-Encoding when it recognises the scheme
// (gzip, deflate). It returns the decoded bytes and the encoding that was
// removed; when nothing is decoded it returns the original body and "".
//
// This is display-only: the proxy always forwards the original on-the-wire
// bytes untouched. Encodings it cannot handle (e.g. br, zstd) are left as-is;
// LimitAcceptEncoding keeps servers from choosing them.
func DecodeBody(headers http.Header, body []byte) (decoded []byte, encoding string) {
	enc := strings.ToLower(strings.TrimSpace(headers.Get("Content-Encoding")))
	if enc == "" || len(body) == 0 {
		return body, ""
	}
	switch enc {
	case "gzip", "x-gzip":
		if out, err := readAllFrom(func() (io.ReadCloser, error) {
			return gzip.NewReader(bytes.NewReader(body))
		}); err == nil {
			return out, enc
		}
	case "deflate":
		// Prefer zlib-wrapped (the spec), fall back to a raw DEFLATE stream
		// which some servers send instead.
		if out, err := readAllFrom(func() (io.ReadCloser, error) {
			return zlib.NewReader(bytes.NewReader(body))
		}); err == nil {
			return out, enc
		}
		if out, err := io.ReadAll(flate.NewReader(bytes.NewReader(body))); err == nil {
			return out, enc
		}
	}
	return body, ""
}

func readAllFrom(open func() (io.ReadCloser, error)) ([]byte, error) {
	r, err := open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// decodable are the content codings DecodeBody can undo.
var decodable = map[string]bool{"gzip": true, "x-gzip": true, "deflate": true, "identity": true}

// LimitAcceptEncoding drops the codings DecodeBody can't undo (br, zstd, *) from
// an Accept-Encoding header, so servers answer in a form Kanca can show, search
// and scan. Browsers ask for br and zstd, and CDNs such as Cloudflare use them,
// which left captured bodies unreadable. It reports whether h changed.
func LimitAcceptEncoding(h http.Header) bool {
	values := h.Values("Accept-Encoding")
	if len(values) == 0 {
		return false
	}
	var keep []string
	changed := false
	for _, line := range values {
		for _, part := range strings.Split(line, ",") {
			tok := strings.TrimSpace(part)
			if tok == "" {
				continue
			}
			name, _, _ := strings.Cut(tok, ";")
			if decodable[strings.ToLower(strings.TrimSpace(name))] {
				keep = append(keep, tok)
			} else {
				changed = true
			}
		}
	}
	if !changed {
		return false
	}
	if len(keep) == 0 {
		keep = []string{"identity"}
	}
	h.Set("Accept-Encoding", strings.Join(keep, ", "))
	return true
}

// DecodedBody is m's body with any Content-Encoding DecodeBody understands
// undone, for code that inspects content (scanners, searches, grep).
func (m Message) DecodedBody() []byte {
	body, _ := DecodeBody(m.Headers, m.Body)
	return body
}
