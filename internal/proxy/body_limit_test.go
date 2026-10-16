package proxy

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestCaptureBodyTruncatesHugeBodies(t *testing.T) {
	big := bytes.Repeat([]byte("x"), maxBodyBytes+1024)
	var rc io.ReadCloser = io.NopCloser(bytes.NewReader(big))
	data, err := captureBody(&rc)
	if !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("err = %v, want errBodyTooLarge", err)
	}
	if len(data) != maxBodyBytes {
		t.Fatalf("len = %d, want %d", len(data), maxBodyBytes)
	}
	// The replacement reader must still serve the (truncated) bytes downstream.
	rest, rerr := io.ReadAll(rc)
	if rerr != nil || len(rest) != maxBodyBytes {
		t.Fatalf("replacement reader: len=%d err=%v", len(rest), rerr)
	}
}

func TestCaptureBodySmallPassthrough(t *testing.T) {
	var rc io.ReadCloser = io.NopCloser(bytes.NewReader([]byte("hello")))
	data, err := captureBody(&rc)
	if err != nil || string(data) != "hello" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}
