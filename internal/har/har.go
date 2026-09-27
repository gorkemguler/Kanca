// Package har serialises captured flows to the HTTP Archive (HAR) 1.2 format,
// so traffic can be exported to other tools (browser dev-tools, other proxies,
// analysis scripts).
package har

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/gorkemguler/mimlec/internal/proxy"
)

const creatorName = "Mimlec"

// Marshal renders flows as an indented HAR 1.2 document.
func Marshal(flows []*proxy.Flow, version string) ([]byte, error) {
	return json.MarshalIndent(build(flows, version), "", "  ")
}

type doc struct {
	Log logSection `json:"log"`
}

type logSection struct {
	Version string  `json:"version"`
	Creator creator `json:"creator"`
	Entries []entry `json:"entries"`
}

type creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type entry struct {
	StartedDateTime string   `json:"startedDateTime"`
	Time            int64    `json:"time"`
	Request         request  `json:"request"`
	Response        response `json:"response"`
	Cache           struct{} `json:"cache"`
	Timings         timings  `json:"timings"`
}

type timings struct {
	Send    int   `json:"send"`
	Wait    int64 `json:"wait"`
	Receive int   `json:"receive"`
}

type nameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []nameValue `json:"headers"`
	QueryString []nameValue `json:"queryString"`
	Cookies     []nameValue `json:"cookies"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
	PostData    *postData   `json:"postData,omitempty"`
}

type postData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

type response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []nameValue `json:"headers"`
	Cookies     []nameValue `json:"cookies"`
	Content     content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type content struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

func build(flows []*proxy.Flow, version string) doc {
	if version == "" {
		version = "dev"
	}
	entries := make([]entry, 0, len(flows))
	for _, f := range flows {
		entries = append(entries, buildEntry(f))
	}
	return doc{Log: logSection{
		Version: "1.2",
		Creator: creator{Name: creatorName, Version: version},
		Entries: entries,
	}}
}

func buildEntry(f *proxy.Flow) entry {
	req := request{
		Method:      f.Method,
		URL:         f.URL,
		HTTPVersion: "HTTP/1.1",
		Headers:     headers(f.Request.Headers),
		QueryString: []nameValue{},
		Cookies:     []nameValue{},
		HeadersSize: -1,
		BodySize:    len(f.Request.Body),
	}
	if len(f.Request.Body) > 0 {
		text, enc := encodeBody(f.Request.Body)
		req.PostData = &postData{
			MimeType: f.Request.Headers.Get("Content-Type"),
			Text:     text,
			Encoding: enc,
		}
	}

	respText, respEnc := encodeBody(f.Response.Body)
	resp := response{
		Status:      f.StatusCode,
		StatusText:  http.StatusText(f.StatusCode),
		HTTPVersion: "HTTP/1.1",
		Headers:     headers(f.Response.Headers),
		Cookies:     []nameValue{},
		Content: content{
			Size:     len(f.Response.Body),
			MimeType: f.Response.Headers.Get("Content-Type"),
			Text:     respText,
			Encoding: respEnc,
		},
		RedirectURL: f.Response.Headers.Get("Location"),
		HeadersSize: -1,
		BodySize:    len(f.Response.Body),
	}

	started := f.Started
	if started.IsZero() {
		started = time.Now()
	}
	return entry{
		StartedDateTime: started.Format(time.RFC3339Nano),
		Time:            f.Duration,
		Request:         req,
		Response:        resp,
		Timings:         timings{Send: 0, Wait: f.Duration, Receive: 0},
	}
}

func headers(h http.Header) []nameValue {
	out := make([]nameValue, 0, len(h))
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable output for diffing exports
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, nameValue{Name: k, Value: v})
		}
	}
	return out
}

// encodeBody returns the body as UTF-8 text, or base64 with encoding "base64"
// when the bytes are not valid UTF-8 (HAR's mechanism for binary content).
func encodeBody(b []byte) (text, encoding string) {
	if len(b) == 0 {
		return "", ""
	}
	if utf8.Valid(b) {
		return string(b), ""
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}
