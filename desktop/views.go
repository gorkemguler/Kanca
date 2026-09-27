package main

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorkemguler/mimlec/internal/history"
	"github.com/gorkemguler/mimlec/internal/proxy"
)

// FlowView is a JSON-friendly projection of a proxy.Flow that exposes the raw
// request/response text (proxy.Flow keeps those as []byte with json:"-").
type FlowView struct {
	ID          int64             `json:"id"`
	Scheme      string            `json:"scheme"`
	Method      string            `json:"method"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	URL         string            `json:"url"`
	StatusCode  int               `json:"statusCode"`
	DurationMs  int64             `json:"durationMs"`
	Error       string            `json:"error,omitempty"`
	ReqHeaders  map[string]string `json:"reqHeaders"`
	RespHeaders map[string]string `json:"respHeaders"`
	RequestRaw  string            `json:"requestRaw"`
	ResponseRaw string            `json:"responseRaw"`
	RespLength  int               `json:"respLength"`
	MIME        string            `json:"mime"`
	// RespEncoding names the Content-Encoding that was transparently decoded
	// for display (e.g. "gzip"); empty when the body was shown verbatim.
	RespEncoding string `json:"respEncoding,omitempty"`
}

func toFlowView(f *proxy.Flow) *FlowView {
	respRaw, enc := displayResponse(f)
	return &FlowView{
		ID:           f.ID,
		Scheme:       f.Scheme,
		Method:       f.Method,
		Host:         f.Host,
		Path:         f.Path,
		URL:          f.URL,
		StatusCode:   f.StatusCode,
		DurationMs:   f.Duration,
		Error:        f.Error,
		ReqHeaders:   flatten(f.Request.Headers),
		RespHeaders:  flatten(f.Response.Headers),
		RequestRaw:   string(f.Request.Raw),
		ResponseRaw:  respRaw,
		RespLength:   len(f.Response.Body),
		MIME:         mimeOf(f.Response.Headers),
		RespEncoding: enc,
	}
}

// displayResponse returns the response as text for the UI, transparently
// decoding a compressed body so it is readable. When it decodes, it drops the
// Content-Encoding header and rewrites Content-Length to match the decoded
// body, preserving the original header order otherwise. The proxy still
// forwards the untouched on-the-wire bytes; this affects display only.
func displayResponse(f *proxy.Flow) (raw string, encoding string) {
	decoded, enc := decodeForDisplay(f.Response.Headers, f.Response.Body)
	if enc == "" {
		return string(f.Response.Raw), ""
	}
	sep := []byte("\r\n\r\n")
	i := bytes.Index(f.Response.Raw, sep)
	if i < 0 {
		return string(f.Response.Raw), ""
	}
	var out strings.Builder
	for _, line := range strings.Split(string(f.Response.Raw[:i]), "\r\n") {
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "content-encoding:"):
			continue
		case strings.HasPrefix(lower, "content-length:"):
			out.WriteString("Content-Length: " + strconv.Itoa(len(decoded)) + "\r\n")
		default:
			out.WriteString(line + "\r\n")
		}
	}
	out.WriteString("\r\n")
	out.Write(decoded)
	return out.String(), enc
}

// EntryView mirrors history.Entry but is defined here so Wails can bind it as
// a return type without importing internal packages into the frontend model.
type EntryView = history.Entry

func toEntryView(f *proxy.Flow) history.Entry {
	// Reuse the store's projection by listing a single-element view.
	return history.Entry{
		ID:         f.ID,
		Method:     f.Method,
		Scheme:     f.Scheme,
		Host:       f.Host,
		Path:       f.Path,
		StatusCode: f.StatusCode,
		Length:     len(f.Response.Body),
		MIME:       mimeOf(f.Response.Headers),
		DurationMs: f.Duration,
		Comment:    f.Comment,
		Highlight:  f.Highlight,
		Error:      f.Error,
	}
}

// HeldView is the frontend projection of an intercepted item.
type HeldView struct {
	ID        int64  `json:"id"`
	Direction string `json:"direction"`
	Host      string `json:"host"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Raw       string `json:"raw"`
}

func toHeldView(h *proxy.Held) HeldView {
	return HeldView{
		ID:        h.ID,
		Direction: string(h.Direction),
		Host:      h.Host,
		Method:    h.Method,
		URL:       h.URL,
		Raw:       string(h.Raw),
	}
}

func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

func mimeOf(h http.Header) string {
	ct := h.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		return strings.TrimSpace(ct[:i])
	}
	return ct
}
