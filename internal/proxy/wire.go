package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"
)

// This file exposes the proxy's HTTP wire codec and a standalone sender so the
// repeater and intruder produce transactions identical to intercepted ones.

// ParseRawRequest converts raw HTTP/1.1 request bytes (as edited in the UI)
// into an *http.Request targeting scheme://host. It is the exported form of
// the parser the proxy uses for edited requests.
func ParseRawRequest(raw []byte, scheme, host string) (*http.Request, error) {
	return rawToRequest(raw, scheme, host)
}

// SerializeRequest renders req + body into the raw form shown in the UI.
func SerializeRequest(req *http.Request, body []byte) []byte {
	return requestToRaw(req, body)
}

// SerializeResponse renders resp + body into raw form.
func SerializeResponse(resp *http.Response, body []byte) []byte {
	return responseToRaw(resp, body)
}

// Sender issues one-off requests outside the intercepting listener, used by
// the repeater and intruder. Each Send is independent and fully buffered.
type Sender struct {
	client *http.Client
}

// SenderConfig tunes a Sender.
type SenderConfig struct {
	Timeout          time.Duration
	InsecureUpstream bool
	// FollowRedirects, when false (the default), returns 3xx responses as-is
	// so the operator sees exactly what the server sent.
	FollowRedirects bool
}

// NewSender builds a Sender. The zero SenderConfig yields a 30s timeout, no
// redirect following, and upstream TLS verification disabled (matching the
// proxy's interception posture).
func NewSender(cfg SenderConfig) *Sender {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureUpstream, //nolint:gosec // deliberate for testing
			MinVersion:         tls.VersionTLS10,
		},
	}
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: tr,
	}
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &Sender{client: client}
}

// Send parses raw request bytes, dispatches them to scheme://host and returns
// a fully-populated Flow describing the exchange.
func (s *Sender) Send(ctx context.Context, raw []byte, scheme, host string) *Flow {
	return s.send(ctx, raw, scheme, host, false)
}

// SendTo is Send, but always connects to scheme://addr, whatever the Host
// header says. The header goes out unchanged, so a scan can show a server a
// Host other than its own.
func (s *Sender) SendTo(ctx context.Context, raw []byte, scheme, addr string) *Flow {
	return s.send(ctx, raw, scheme, addr, true)
}

func (s *Sender) send(ctx context.Context, raw []byte, scheme, host string, pinned bool) *Flow {
	start := time.Now()
	f := &Flow{
		ID:      nextFlowID(),
		Scheme:  scheme,
		Host:    host,
		Started: start,
	}

	req, err := ParseRawRequest(raw, scheme, host)
	if err != nil {
		f.Error = err.Error()
		f.Duration = time.Since(start).Milliseconds()
		return f
	}
	if pinned {
		// The client dials URL.Host and sends req.Host as the header.
		req.URL.Host = host
	}
	reqBody, reqBodyErr := captureBody(&req.Body)
	reqTruncated := errors.Is(reqBodyErr, errBodyTooLarge)
	if reqBodyErr != nil && !reqTruncated {
		f.Error = "request body: " + reqBodyErr.Error()
	}
	// Only rebuild the raw snapshot when the body was fully captured; a
	// truncated snapshot would advertise the wrong Content-Length.
	if LimitAcceptEncoding(req.Header) && !reqTruncated {
		raw = requestToRaw(req, reqBody)
	}
	req = req.WithContext(ctx)
	// captureBody left req.Body replaying the complete payload; keep the
	// declared length so large requests are sent in full.

	f.Method = req.Method
	f.Path = req.URL.RequestURI()
	f.URL = scheme + "://" + host + req.URL.RequestURI()
	f.Request = Message{
		Raw: raw, Headers: req.Header.Clone(), Body: reqBody,
		ContentLength: req.ContentLength, Truncated: reqTruncated,
	}

	resp, err := s.client.Do(req)
	if err != nil {
		f.Error = err.Error()
		f.Duration = time.Since(start).Milliseconds()
		return f
	}
	respBody, respBodyErr := captureBody(&resp.Body)
	// A Send result is only the snapshot. Close the upstream so the rest of a
	// truncated (over 64 MiB) response doesn't hold the connection open.
	_ = resp.Body.Close()
	respTruncated := errors.Is(respBodyErr, errBodyTooLarge)
	if respBodyErr != nil && !respTruncated && f.Error == "" {
		f.Error = "response body: " + respBodyErr.Error()
	}
	f.StatusCode = resp.StatusCode
	f.Response = Message{
		Raw: responseToRaw(resp, respBody), Headers: resp.Header.Clone(), Body: respBody,
		ContentLength: resp.ContentLength, Truncated: respTruncated,
	}
	f.Duration = time.Since(start).Milliseconds()
	return f
}
