// Package har serialises captured flows to the HTTP Archive (HAR) 1.2 format,
// so traffic can be exported to other tools (browser dev-tools, other proxies,
// analysis scripts).
package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gorkemguler/kanca/internal/proxy"
)

const creatorName = "Kanca"

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

// Unmarshal parses a HAR 1.2 document (from any tool: browser dev-tools, other
// proxies, or Kanca itself) into flows suitable for the history view. Entries
// are assigned sequential ids starting at 1, so callers should treat the
// result as a fresh capture set (import replaces rather than merges).
func Unmarshal(data []byte) ([]*proxy.Flow, error) {
	var d doc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("har: parse: %w", err)
	}
	out := make([]*proxy.Flow, 0, len(d.Log.Entries))
	for i := range d.Log.Entries {
		f, err := entryToFlow(int64(i+1), &d.Log.Entries[i])
		if err != nil {
			return nil, fmt.Errorf("har: entry %d: %w", i, err)
		}
		out = append(out, f)
	}
	return out, nil
}

func entryToFlow(id int64, e *entry) (*proxy.Flow, error) {
	reqBody := decodeBody(e.Request.PostData.textAndEnc())
	respBody := decodeBody(e.Response.Content.Text, e.Response.Content.Encoding)

	u, _ := url.Parse(e.Request.URL)
	scheme, host, path := "http", "", "/"
	if u != nil {
		if u.Scheme != "" {
			scheme = u.Scheme
		}
		host = u.Host
		if p := u.RequestURI(); p != "" {
			path = p
		}
	}
	switch scheme {
	case "ws":
		scheme = "http"
	case "wss":
		scheme = "https"
	}

	method := orDefault(e.Request.Method, "GET")
	reqHeaders := toHeader(e.Request.Headers)
	respHeaders := toHeader(e.Response.Headers)

	return &proxy.Flow{
		ID:         id,
		Scheme:     scheme,
		Method:     method,
		Host:       host,
		Path:       path,
		URL:        e.Request.URL,
		StatusCode: e.Response.Status,
		Duration:   e.Time,
		Started:    parseTime(e.StartedDateTime),
		Request: proxy.Message{
			Raw:           buildRequestRaw(method, path, host, reqHeaders, reqBody),
			Headers:       reqHeaders,
			Body:          reqBody,
			ContentLength: int64(len(reqBody)),
		},
		Response: proxy.Message{
			Raw:           buildResponseRaw(e.Response.Status, e.Response.StatusText, respHeaders, respBody),
			Headers:       respHeaders,
			Body:          respBody,
			ContentLength: int64(len(respBody)),
		},
	}, nil
}

func (p *postData) textAndEnc() (string, string) {
	if p == nil {
		return "", ""
	}
	return p.Text, p.Encoding
}

func decodeBody(text, encoding string) []byte {
	if text == "" {
		return nil
	}
	if strings.EqualFold(encoding, "base64") {
		if b, err := base64.StdEncoding.DecodeString(text); err == nil {
			return b
		}
	}
	return []byte(text)
}

func toHeader(nvs []nameValue) http.Header {
	h := http.Header{}
	for _, nv := range nvs {
		// Skip HTTP/2 pseudo-headers (":method", ":path", …) which some tools
		// export; they aren't valid in a raw HTTP/1.1 message.
		if strings.HasPrefix(nv.Name, ":") {
			continue
		}
		h.Add(nv.Name, nv.Value)
	}
	return h
}

func buildRequestRaw(method, path, host string, h http.Header, body []byte) []byte {
	var b bytes.Buffer
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	if host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", host)
	}
	writeHeaderLines(&b, h, "Host")
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func buildResponseRaw(status int, statusText string, h http.Header, body []byte) []byte {
	var b bytes.Buffer
	if statusText == "" {
		statusText = http.StatusText(status)
	}
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, statusText)
	writeHeaderLines(&b, h, "")
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func writeHeaderLines(b *bytes.Buffer, h http.Header, skip string) {
	keys := make([]string, 0, len(h))
	for k := range h {
		if skip != "" && http.CanonicalHeaderKey(k) == http.CanonicalHeaderKey(skip) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
