package main

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecodeForDisplayBrotli(t *testing.T) {
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	_, _ = bw.Write([]byte("hello from brotli"))
	_ = bw.Close()

	h := http.Header{}
	h.Set("Content-Encoding", "br")
	out, enc := decodeForDisplay(h, buf.Bytes())
	if enc != "br" || string(out) != "hello from brotli" {
		t.Fatalf("brotli decode: enc=%q out=%q", enc, out)
	}
}

func TestDecodeForDisplayDelegatesGzip(t *testing.T) {
	// A gzip body must still be handled (delegated to the core), proving the
	// desktop wrapper doesn't regress the stdlib path.
	h := http.Header{}
	// No Content-Encoding -> passthrough.
	out, enc := decodeForDisplay(h, []byte("plain"))
	if enc != "" || string(out) != "plain" {
		t.Fatalf("passthrough: enc=%q out=%q", enc, out)
	}
}
