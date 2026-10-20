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
	// The replacement reader must still serve the complete payload downstream;
	// only the stored snapshot is capped.
	rest, rerr := io.ReadAll(rc)
	if rerr != nil || len(rest) != len(big) {
		t.Fatalf("replacement reader: len=%d err=%v, want %d", len(rest), rerr, len(big))
	}
	if !bytes.Equal(rest, big) {
		t.Fatal("replacement reader did not replay the original body")
	}
}

func TestCaptureBodySmallPassthrough(t *testing.T) {
	var rc io.ReadCloser = io.NopCloser(bytes.NewReader([]byte("hello")))
	data, err := captureBody(&rc)
	if err != nil || string(data) != "hello" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}
