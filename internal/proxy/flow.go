package proxy

import (
	"bytes"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Flow captures a single request/response transaction observed by the proxy.
// It is the unit of data shared across the history log, the repeater and the
// intruder. A Flow is a plain value container; capturing code fills it and
// downstream consumers read it.
type Flow struct {
	ID       int64     `json:"id"`
	Scheme   string    `json:"scheme"` // "http" or "https"
	Method   string    `json:"method"`
	Host     string    `json:"host"` // authority, e.g. example.com:443
	Path     string    `json:"path"` // path + raw query
	URL      string    `json:"url"`  // full reconstructed URL
	Started  time.Time `json:"started"`
	Duration int64     `json:"durationMs"`

	Request  Message `json:"request"`
	Response Message `json:"response"`

	// StatusCode is duplicated out of Response for cheap list rendering.
	StatusCode int `json:"statusCode"`
	// Error holds a transport-level failure message, if the round trip failed.
	Error string `json:"error,omitempty"`
	// Comment and Highlight are user annotations set from the UI.
	Comment   string `json:"comment,omitempty"`
	Highlight string `json:"highlight,omitempty"`

	// responseClose mirrors the upstream response's Connection: close so the
	// tunnel loop knows not to reuse the decrypted connection.
	responseClose bool
}

// Message is a serialisable snapshot of one side of a transaction. Headers are
// stored raw so the exact on-the-wire ordering is preserved for editing and
// replay; Body holds the fully buffered payload.
type Message struct {
	// Raw is the complete message (start line + headers + CRLF + body) as
	// bytes. It is the source of truth the repeater edits and resends.
	Raw     []byte      `json:"-"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"-"`
	// ContentLength is the declared length; -1 when unknown.
	ContentLength int64 `json:"contentLength"`
}

// BodyString returns the body as text for display. Callers that need to know
// whether the payload is printable should inspect the content type first.
func (m Message) BodyString() string { return string(m.Body) }

var flowSeq int64

// nextFlowID hands out process-unique, monotonically increasing flow IDs.
func nextFlowID() int64 { return atomic.AddInt64(&flowSeq, 1) }

// captureBody reads and returns the full body, leaving a fresh reader in its
// place so the caller can still forward the message downstream. A nil body
// yields an empty slice.
func captureBody(rc *io.ReadCloser) ([]byte, error) {
	if rc == nil || *rc == nil {
		return []byte{}, nil
	}
	data, err := io.ReadAll(*rc)
	_ = (*rc).Close()
	if err != nil {
		return data, err
	}
	*rc = io.NopCloser(bytes.NewReader(data))
	return data, nil
}
