package main

import (
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// maxWSFramesPerSession bounds how many frames a single connection's log
// retains in memory; older frames are dropped once the cap is hit so a
// long-lived, chatty WebSocket connection cannot grow without limit.
const maxWSFramesPerSession = 2000

// WSFrameView is the JSON-friendly projection of a captured WebSocket frame.
type WSFrameView struct {
	Direction string    `json:"direction"`
	Opcode    string    `json:"opcode"`
	Final     bool      `json:"final"`
	Masked    bool      `json:"masked"`
	Length    int       `json:"length"`
	Text      string    `json:"text"`
	IsText    bool      `json:"isText"`
	At        time.Time `json:"at"`
}

// WSSession tracks one bridged WebSocket connection and its captured frames.
type WSSession struct {
	ID       int64         `json:"id"`
	Host     string        `json:"host"`
	URL      string        `json:"url"`
	Open     bool          `json:"open"`
	OpenedAt time.Time     `json:"openedAt"`
	ClosedAt time.Time     `json:"closedAt,omitempty"`
	Frames   []WSFrameView `json:"frames"`
}

// wsStore is an in-memory, bounded log of WebSocket sessions and their
// frames, fed by the proxy's OnWSOpen/OnWSFrame/OnWSClose hooks.
type wsStore struct {
	mu       sync.Mutex
	order    []int64
	sessions map[int64]*WSSession
	onEvent  func(kind string, session *WSSession, frame *WSFrameView)
}

func newWSStore() *wsStore {
	return &wsStore{sessions: make(map[int64]*WSSession)}
}

func (s *wsStore) onOpen(id int64, host, url string) {
	s.mu.Lock()
	sess := &WSSession{ID: id, Host: host, URL: url, Open: true, OpenedAt: time.Now()}
	s.sessions[id] = sess
	s.order = append(s.order, id)
	cb := s.onEvent
	s.mu.Unlock()
	if cb != nil {
		cb("open", sess, nil)
	}
}

func (s *wsStore) onFrame(id int64, host, url string, f proxy.WSFrame) {
	view := WSFrameView{
		Direction: f.Direction,
		Opcode:    f.Opcode.String(),
		Final:     f.Final,
		Masked:    f.Masked,
		Length:    len(f.Payload),
		At:        time.Now(),
	}
	if f.Opcode == proxy.WSOpText && utf8.Valid(f.Payload) {
		view.IsText = true
		view.Text = string(f.Payload)
	}

	s.mu.Lock()
	sess, ok := s.sessions[id]
	if !ok {
		// Frame arrived before/without an open event; synthesize the session
		// so nothing is silently dropped.
		sess = &WSSession{ID: id, Host: host, URL: url, Open: true, OpenedAt: time.Now()}
		s.sessions[id] = sess
		s.order = append(s.order, id)
	}
	sess.Frames = append(sess.Frames, view)
	if over := len(sess.Frames) - maxWSFramesPerSession; over > 0 {
		sess.Frames = sess.Frames[over:]
	}
	cb := s.onEvent
	s.mu.Unlock()
	if cb != nil {
		cb("frame", sess, &view)
	}
}

func (s *wsStore) onClose(id int64, host, url string) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	sess.Open = false
	sess.ClosedAt = time.Now()
	cb := s.onEvent
	s.mu.Unlock()
	if cb != nil {
		cb("close", sess, nil)
	}
}

// List returns a snapshot of all sessions, oldest first.
func (s *wsStore) List() []WSSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WSSession, 0, len(s.order))
	for _, id := range s.order {
		if sess := s.sessions[id]; sess != nil {
			out = append(out, *sess)
		}
	}
	return out
}

// Clear discards all sessions and frames.
func (s *wsStore) Clear() {
	s.mu.Lock()
	s.order = nil
	s.sessions = make(map[int64]*WSSession)
	s.mu.Unlock()
}
