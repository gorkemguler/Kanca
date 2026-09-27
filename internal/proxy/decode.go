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
// bytes untouched. Encodings it cannot handle (e.g. br) are left as-is.
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
