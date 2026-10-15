package proxy_test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"net/http"
	"testing"

	"github.com/gorkemguler/kanca/internal/proxy"
)

func TestDecodeBodyGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("hello gzip world"))
	_ = zw.Close()

	h := http.Header{}
	h.Set("Content-Encoding", "gzip")
	out, enc := proxy.DecodeBody(h, buf.Bytes())
	if enc != "gzip" || string(out) != "hello gzip world" {
		t.Fatalf("decode gzip: enc=%q out=%q", enc, out)
	}
}

func TestDecodeBodyDeflate(t *testing.T) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write([]byte("hello deflate"))
	_ = zw.Close()

	h := http.Header{}
	h.Set("Content-Encoding", "deflate")
	out, enc := proxy.DecodeBody(h, buf.Bytes())
	if enc != "deflate" || string(out) != "hello deflate" {
		t.Fatalf("decode deflate: enc=%q out=%q", enc, out)
	}
}

func TestDecodeBodyPassthrough(t *testing.T) {
	h := http.Header{} // no Content-Encoding
	out, enc := proxy.DecodeBody(h, []byte("plain"))
	if enc != "" || string(out) != "plain" {
		t.Fatalf("passthrough: enc=%q out=%q", enc, out)
	}
	// Unknown encoding (e.g. br) is left untouched.
	h.Set("Content-Encoding", "br")
	out, enc = proxy.DecodeBody(h, []byte("\x01\x02brotli"))
	if enc != "" || string(out) != "\x01\x02brotli" {
		t.Fatalf("br should pass through: enc=%q", enc)
	}
}

func TestLimitAcceptEncodingKeepsOnlyDecodableCodings(t *testing.T) {
	cases := []struct{ in, want string }{
		{"gzip, deflate, br, zstd", "gzip, deflate"},
		{"br", "identity"},
		{"gzip;q=1.0, *;q=0.5", "gzip;q=1.0"},
		{"zstd, identity", "identity"},
	}
	for _, c := range cases {
		h := http.Header{}
		h.Set("Accept-Encoding", c.in)
		if !proxy.LimitAcceptEncoding(h) || h.Get("Accept-Encoding") != c.want {
			t.Errorf("%q -> %q, want %q", c.in, h.Get("Accept-Encoding"), c.want)
		}
	}
	for _, in := range []string{"", "gzip, deflate"} {
		h := http.Header{}
		if in != "" {
			h.Set("Accept-Encoding", in)
		}
		if proxy.LimitAcceptEncoding(h) || h.Get("Accept-Encoding") != in {
			t.Errorf("%q should be left alone, got %q", in, h.Get("Accept-Encoding"))
		}
	}
}
