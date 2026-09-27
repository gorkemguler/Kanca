package proxy

import (
	"bytes"
	"io"
	"testing"
)

func TestReadWSFrameUnmaskedText(t *testing.T) {
	var buf bytes.Buffer
	if err := writeWSFrame(&buf, WSOpText, false, []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, f, err := readWSFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if f.Opcode != WSOpText || !f.Final || f.Masked {
		t.Fatalf("frame = %+v", f)
	}
	if string(f.Payload) != "hello" {
		t.Fatalf("payload = %q", f.Payload)
	}
	// raw must be exactly the bytes we wrote (round-trip byte-transparency).
	var reencode bytes.Buffer
	_ = writeWSFrame(&reencode, WSOpText, false, []byte("hello"))
	if !bytes.Equal(raw, reencode.Bytes()) {
		t.Fatalf("raw bytes not preserved: got %x want %x", raw, reencode.Bytes())
	}
}

func TestReadWSFrameMaskedClientFrame(t *testing.T) {
	var buf bytes.Buffer
	_ = writeWSFrame(&buf, WSOpBinary, true, []byte{0x01, 0x02, 0x03, 0xFF})
	_, f, err := readWSFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !f.Masked || f.Opcode != WSOpBinary {
		t.Fatalf("frame = %+v", f)
	}
	if !bytes.Equal(f.Payload, []byte{0x01, 0x02, 0x03, 0xFF}) {
		t.Fatalf("unmasked payload wrong: %x", f.Payload)
	}
}

func TestReadWSFrameExtendedLength16(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 1000) // > 125, needs 16-bit extended length
	var buf bytes.Buffer
	_ = writeWSFrame(&buf, WSOpBinary, false, payload)
	_, f, err := readWSFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(f.Payload) != 1000 {
		t.Fatalf("payload len = %d", len(f.Payload))
	}
}

func TestReadWSFrameExtendedLength64(t *testing.T) {
	payload := bytes.Repeat([]byte("y"), 70000) // > 0xFFFF, needs 64-bit extended length
	var buf bytes.Buffer
	_ = writeWSFrame(&buf, WSOpBinary, false, payload)
	_, f, err := readWSFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(f.Payload) != 70000 {
		t.Fatalf("payload len = %d", len(f.Payload))
	}
}

func TestReadWSFrameControlOpcodes(t *testing.T) {
	for _, op := range []WSOpcode{WSOpClose, WSOpPing, WSOpPong} {
		var buf bytes.Buffer
		_ = writeWSFrame(&buf, op, true, []byte("x"))
		_, f, err := readWSFrame(&buf)
		if err != nil {
			t.Fatalf("%s: read: %v", op, err)
		}
		if f.Opcode != op {
			t.Fatalf("opcode = %v, want %v", f.Opcode, op)
		}
		if got := op.String(); got == "reserved" {
			t.Fatalf("opcode %v stringified as reserved", op)
		}
	}
}

func TestReadWSFrameTruncatedStillRelaysPartialBytes(t *testing.T) {
	var buf bytes.Buffer
	_ = writeWSFrame(&buf, WSOpText, false, []byte("hello world"))
	full := buf.Bytes()
	// Truncate mid-payload: header says a length we won't fully deliver.
	truncated := bytes.NewReader(full[:len(full)-3])
	raw, _, err := readWSFrame(truncated)
	if err == nil {
		t.Fatal("expected an error on truncated frame")
	}
	if err != io.ErrUnexpectedEOF && err != io.EOF {
		t.Fatalf("unexpected error type: %v", err)
	}
	// Every byte that WAS available must still come back for relay.
	if !bytes.Equal(raw, full[:len(full)-3]) {
		t.Fatalf("partial raw bytes lost: got %d bytes, want %d", len(raw), len(full)-3)
	}
}

func TestReadWSFrameOversizedRejected(t *testing.T) {
	// Hand-craft a header claiming a payload larger than the cap, without
	// actually allocating/sending that much data.
	var buf bytes.Buffer
	buf.WriteByte(0x82) // FIN=1, opcode=binary
	buf.WriteByte(127)  // 64-bit extended length follows
	ext := make([]byte, 8)
	// maxWSFramePayload+1
	big := uint64(maxWSFramePayload) + 1
	for i := 7; i >= 0; i-- {
		ext[i] = byte(big)
		big >>= 8
	}
	buf.Write(ext)
	_, _, err := readWSFrame(&buf)
	if err == nil {
		t.Fatal("expected oversized frame to be rejected")
	}
}

func TestPipeAndCaptureRelaysAndParses(t *testing.T) {
	var wire bytes.Buffer
	_ = writeWSFrame(&wire, WSOpText, true, []byte("ping-from-client"))
	_ = writeWSFrame(&wire, WSOpBinary, true, []byte{1, 2, 3})

	var relayed bytes.Buffer
	var got []WSFrame
	pipeAndCapture("client->server", bytes.NewReader(wire.Bytes()), &relayed, func(f WSFrame) {
		got = append(got, f)
	})

	if !bytes.Equal(relayed.Bytes(), wire.Bytes()) {
		t.Fatalf("relay not byte-identical: got %d bytes want %d", relayed.Len(), wire.Len())
	}
	if len(got) != 2 {
		t.Fatalf("captured %d frames, want 2", len(got))
	}
	if got[0].Direction != "client->server" || string(got[0].Payload) != "ping-from-client" {
		t.Fatalf("frame 0 wrong: %+v", got[0])
	}
	if got[1].Opcode != WSOpBinary || !bytes.Equal(got[1].Payload, []byte{1, 2, 3}) {
		t.Fatalf("frame 1 wrong: %+v", got[1])
	}
}

func TestPipeAndCaptureFallsBackToRawRelayOnParseError(t *testing.T) {
	// Garbage that isn't valid framing beyond the point where our length cap
	// rejects it: capture should stop parsing but still relay every byte.
	var wire bytes.Buffer
	wire.WriteByte(0x82)
	wire.WriteByte(127)
	ext := make([]byte, 8)
	big := uint64(maxWSFramePayload) + 1
	for i := 7; i >= 0; i-- {
		ext[i] = byte(big)
		big >>= 8
	}
	wire.Write(ext)
	tail := []byte("trailing-bytes-that-must-still-be-relayed")
	wire.Write(tail)

	var relayed bytes.Buffer
	var frameCount int
	pipeAndCapture("client->server", bytes.NewReader(wire.Bytes()), &relayed, func(WSFrame) { frameCount++ })

	if frameCount != 0 {
		t.Fatalf("expected no successfully parsed frames, got %d", frameCount)
	}
	if !bytes.Equal(relayed.Bytes(), wire.Bytes()) {
		t.Fatalf("fallback relay dropped bytes: got %d want %d", relayed.Len(), wire.Len())
	}
}
