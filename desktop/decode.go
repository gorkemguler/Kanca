package main

import (
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// decodeForDisplay decodes a response body for display. It delegates gzip and
// deflate to the dependency-free core (proxy.DecodeBody) and additionally
// handles brotli ("br") here, so the core module stays stdlib-only while the
// desktop app can still render brotli-compressed responses (common on modern
// sites) as readable text.
func decodeForDisplay(headers http.Header, body []byte) (decoded []byte, encoding string) {
	if out, enc := proxy.DecodeBody(headers, body); enc != "" {
		return out, enc
	}
	enc := strings.ToLower(strings.TrimSpace(headers.Get("Content-Encoding")))
	if (enc == "br" || enc == "brotli") && len(body) > 0 {
		if out, err := io.ReadAll(brotli.NewReader(strings.NewReader(string(body)))); err == nil {
			return out, "br"
		}
	}
	return body, ""
}
