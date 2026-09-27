package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// WSOpcode identifies a WebSocket frame's payload type (RFC 6455 §5.2).
type WSOpcode uint8

const (
	WSOpContinuation WSOpcode = 0x0
	WSOpText         WSOpcode = 0x1
	WSOpBinary       WSOpcode = 0x2
	WSOpClose        WSOpcode = 0x8
	WSOpPing         WSOpcode = 0x9
	WSOpPong         WSOpcode = 0xA
)

// String returns the opcode's RFC name, or "reserved" for unassigned values.
func (op WSOpcode) String() string {
	switch op {
	case WSOpContinuation:
		return "continuation"
	case WSOpText:
		return "text"
	case WSOpBinary:
		return "binary"
	case WSOpClose:
		return "close"
	case WSOpPing:
		return "ping"
	case WSOpPong:
		return "pong"
	default:
		return "reserved"
	}
}

// WSFrame is one decoded WebSocket frame, unmasked for display.
type WSFrame struct {
	Direction string   `json:"direction"` // "client->server" or "server->client"
	Opcode    WSOpcode `json:"opcode"`
	Final     bool     `json:"final"`
	Masked    bool     `json:"masked"`
	Payload   []byte   `json:"-"`
}

// maxWSFramePayload bounds how large a single frame's payload we will buffer
// in memory before giving up on parsing (falling back to a raw byte relay for
// the rest of that connection). It guards against a garbled or hostile length
// field causing an unbounded allocation; it does not limit how much data a
// WebSocket connection may carry in total, only per captured frame.
const maxWSFramePayload = 64 << 20 // 64 MiB

// readWSFrame reads exactly one WebSocket frame from r per RFC 6455 §5.2.
// It always returns the raw bytes it actually consumed (raw), even on error,
// so the caller can relay them verbatim and keep the tunnel byte-transparent
// regardless of whether parsing succeeded.
func readWSFrame(r io.Reader) (raw []byte, frame WSFrame, err error) {
	var buf bytes.Buffer

	header := make([]byte, 2)
	if err := readFullInto(r, header, &buf); err != nil {
		return buf.Bytes(), WSFrame{}, err
	}

	fin := header[0]&0x80 != 0
	opcode := WSOpcode(header[0] & 0x0F)
	masked := header[1]&0x80 != 0
	plen := uint64(header[1] & 0x7F)

	switch plen {
	case 126:
		ext := make([]byte, 2)
		if err := readFullInto(r, ext, &buf); err != nil {
			return buf.Bytes(), WSFrame{}, err
		}
		plen = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if err := readFullInto(r, ext, &buf); err != nil {
			return buf.Bytes(), WSFrame{}, err
		}
		plen = binary.BigEndian.Uint64(ext)
	}

	var maskKey [4]byte
	if masked {
		mk := make([]byte, 4)
		if err := readFullInto(r, mk, &buf); err != nil {
			return buf.Bytes(), WSFrame{}, err
		}
		copy(maskKey[:], mk)
	}

	if plen > maxWSFramePayload {
		return buf.Bytes(), WSFrame{}, fmt.Errorf("proxy: websocket frame too large (%d bytes)", plen)
	}

	payload := make([]byte, plen)
	if plen > 0 {
		if err := readFullInto(r, payload, &buf); err != nil {
			return buf.Bytes(), WSFrame{}, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return buf.Bytes(), WSFrame{Opcode: opcode, Final: fin, Masked: masked, Payload: payload}, nil
}

// readFullInto reads exactly len(dst) bytes from r into dst, appending
// whatever it actually managed to read (even a short read on error) to raw so
// the caller can still relay those bytes verbatim.
func readFullInto(r io.Reader, dst []byte, raw *bytes.Buffer) error {
	n, err := io.ReadFull(r, dst)
	raw.Write(dst[:n])
	return err
}

// writeWSFrame encodes a frame onto w using standard (non-extended) framing.
// It is used by tests to synthesize client and server frames; production code
// only ever relays bytes it read, never re-encodes them.
func writeWSFrame(w io.Writer, opcode WSOpcode, masked bool, payload []byte) error {
	var b bytes.Buffer
	b.WriteByte(0x80 | byte(opcode)) // FIN=1
	n := len(payload)
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		b.WriteByte(maskBit | byte(n))
	case n <= 0xFFFF:
		b.WriteByte(maskBit | 126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(n))
		b.Write(ext)
	default:
		b.WriteByte(maskBit | 127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(n))
		b.Write(ext)
	}
	body := payload
	if masked {
		var key [4]byte
		copy(key[:], []byte{0x12, 0x34, 0x56, 0x78})
		b.Write(key[:])
		body = make([]byte, n)
		for i, c := range payload {
			body[i] = c ^ key[i%4]
		}
	}
	b.Write(body)
	_, err := w.Write(b.Bytes())
	return err
}
