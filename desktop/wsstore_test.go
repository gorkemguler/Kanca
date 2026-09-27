package main

import (
	"testing"

	"github.com/gorkemguler/mimlec/internal/proxy"
)

func TestWSStoreLifecycle(t *testing.T) {
	s := newWSStore()
	var events []string
	s.onEvent = func(kind string, sess *WSSession, frame *WSFrameView) {
		events = append(events, kind)
	}

	s.onOpen(1, "example.com", "wss://example.com/ws")
	s.onFrame(1, "example.com", "wss://example.com/ws", proxy.WSFrame{
		Direction: "client->server", Opcode: proxy.WSOpText, Final: true, Payload: []byte("hi"),
	})
	s.onFrame(1, "example.com", "wss://example.com/ws", proxy.WSFrame{
		Direction: "server->client", Opcode: proxy.WSOpBinary, Final: true, Payload: []byte{0xff, 0x00},
	})
	s.onClose(1, "example.com", "wss://example.com/ws")

	if got := []string{"open", "frame", "frame", "close"}; len(events) != len(got) {
		t.Fatalf("events = %v", events)
	}

	sessions := s.List()
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d", len(sessions))
	}
	sess := sessions[0]
	if sess.Open {
		t.Fatal("session should be closed")
	}
	if len(sess.Frames) != 2 {
		t.Fatalf("frames = %d", len(sess.Frames))
	}
	if !sess.Frames[0].IsText || sess.Frames[0].Text != "hi" {
		t.Fatalf("text frame wrong: %+v", sess.Frames[0])
	}
	if sess.Frames[1].IsText {
		t.Fatalf("binary frame misclassified as text: %+v", sess.Frames[1])
	}
}

func TestWSStoreFrameCap(t *testing.T) {
	s := newWSStore()
	s.onOpen(1, "x", "wss://x/")
	for i := 0; i < maxWSFramesPerSession+50; i++ {
		s.onFrame(1, "x", "wss://x/", proxy.WSFrame{Direction: "client->server", Opcode: proxy.WSOpBinary, Payload: []byte{1}})
	}
	sess := s.List()[0]
	if len(sess.Frames) != maxWSFramesPerSession {
		t.Fatalf("frames = %d, want cap %d", len(sess.Frames), maxWSFramesPerSession)
	}
}

func TestWSStoreClear(t *testing.T) {
	s := newWSStore()
	s.onOpen(1, "x", "wss://x/")
	s.Clear()
	if len(s.List()) != 0 {
		t.Fatal("expected empty store after Clear")
	}
}
