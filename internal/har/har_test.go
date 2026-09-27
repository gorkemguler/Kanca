package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorkemguler/mimlec/internal/proxy"
)

func TestMarshalHAR(t *testing.T) {
	reqH := http.Header{}
	reqH.Set("Content-Type", "application/json")
	respH := http.Header{}
	respH.Set("Content-Type", "text/html")
	respH.Set("Location", "/next")

	f := &proxy.Flow{
		ID: 1, Scheme: "https", Method: "POST",
		Host: "api.example.com:443", Path: "/login",
		URL: "https://api.example.com:443/login", StatusCode: 200,
		Duration: 42, Started: time.Unix(1700000000, 0).UTC(),
		Request:  proxy.Message{Headers: reqH, Body: []byte(`{"u":"a"}`)},
		Response: proxy.Message{Headers: respH, Body: []byte("<h1>ok</h1>")},
	}
	out, err := Marshal([]*proxy.Flow{f}, "1.0")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	log := parsed["log"].(map[string]any)
	if log["version"] != "1.2" {
		t.Fatalf("version = %v", log["version"])
	}
	entries := log["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	e := entries[0].(map[string]any)
	req := e["request"].(map[string]any)
	if req["method"] != "POST" || req["url"] != "https://api.example.com:443/login" {
		t.Fatalf("request wrong: %v", req)
	}
	if req["postData"].(map[string]any)["text"] != `{"u":"a"}` {
		t.Fatalf("postData wrong: %v", req["postData"])
	}
	resp := e["response"].(map[string]any)
	if int(resp["status"].(float64)) != 200 || resp["statusText"] != "OK" {
		t.Fatalf("response status wrong: %v", resp)
	}
	if resp["redirectURL"] != "/next" {
		t.Fatalf("redirectURL = %v", resp["redirectURL"])
	}
}

func TestBinaryBodyBase64(t *testing.T) {
	binary := []byte{0xff, 0xfe, 0x00, 0x01}
	f := &proxy.Flow{
		Method: "GET", URL: "http://x/", StatusCode: 200,
		Response: proxy.Message{Headers: http.Header{}, Body: binary},
	}
	out, _ := Marshal([]*proxy.Flow{f}, "1.0")
	var parsed map[string]any
	_ = json.Unmarshal(out, &parsed)
	content := parsed["log"].(map[string]any)["entries"].([]any)[0].(map[string]any)["response"].(map[string]any)["content"].(map[string]any)
	if content["encoding"] != "base64" {
		t.Fatalf("expected base64 encoding, got %v", content["encoding"])
	}
	dec, err := base64.StdEncoding.DecodeString(content["text"].(string))
	if err != nil || string(dec) != string(binary) {
		t.Fatalf("base64 roundtrip failed: %v", err)
	}
}

func TestUnmarshalRoundTrip(t *testing.T) {
	reqH := http.Header{"User-Agent": {"mimlec"}, "Content-Type": {"application/json"}}
	respH := http.Header{"Content-Type": {"text/html"}, "Set-Cookie": {"a=1"}}
	orig := &proxy.Flow{
		ID: 1, Scheme: "https", Method: "POST", Host: "api.example.com",
		Path: "/login?x=1", URL: "https://api.example.com/login?x=1", StatusCode: 200,
		Duration: 33, Started: time.Unix(1700000000, 0).UTC(),
		Request:  proxy.Message{Headers: reqH, Body: []byte(`{"u":"a"}`)},
		Response: proxy.Message{Headers: respH, Body: []byte("<h1>ok</h1>")},
	}

	data, err := Marshal([]*proxy.Flow{orig}, "1.0")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	flows, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	got := flows[0]
	if got.Method != "POST" || got.Scheme != "https" || got.Host != "api.example.com" {
		t.Fatalf("meta lost: %+v", got)
	}
	if got.StatusCode != 200 || got.URL != orig.URL {
		t.Fatalf("meta2 lost: %+v", got)
	}
	if string(got.Request.Body) != `{"u":"a"}` {
		t.Fatalf("request body lost: %q", got.Request.Body)
	}
	if string(got.Response.Body) != "<h1>ok</h1>" {
		t.Fatalf("response body lost: %q", got.Response.Body)
	}
	if got.Request.Headers.Get("User-Agent") != "mimlec" {
		t.Fatalf("request headers lost: %v", got.Request.Headers)
	}
	if got.Response.Headers.Get("Set-Cookie") != "a=1" {
		t.Fatalf("response headers lost: %v", got.Response.Headers)
	}
	// Reconstructed raw request must be a well-formed HTTP/1.1 message.
	raw := string(got.Request.Raw)
	if !strings.HasPrefix(raw, "POST /login?x=1 HTTP/1.1\r\n") {
		t.Fatalf("request raw malformed: %q", raw)
	}
	if !strings.Contains(raw, "Host: api.example.com\r\n") {
		t.Fatalf("request raw missing Host: %q", raw)
	}
}

func TestUnmarshalBinaryBody(t *testing.T) {
	binary := []byte{0x00, 0xff, 0x10}
	orig := &proxy.Flow{
		Method: "GET", URL: "http://x/img", StatusCode: 200,
		Request:  proxy.Message{Headers: http.Header{}},
		Response: proxy.Message{Headers: http.Header{"Content-Type": {"image/png"}}, Body: binary},
	}
	data, _ := Marshal([]*proxy.Flow{orig}, "1.0")
	flows, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(flows[0].Response.Body, binary) {
		t.Fatalf("binary body not restored: %x", flows[0].Response.Body)
	}
}

func TestUnmarshalSkipsPseudoHeaders(t *testing.T) {
	// A HAR exported from a browser dev-tools capture of an HTTP/2 request
	// carries pseudo-headers like ":method"; they must be dropped from the
	// reconstructed HTTP/1.1 message rather than emitted as invalid lines.
	harDoc := `{"log":{"version":"1.2","creator":{"name":"x","version":"1"},"entries":[{
		"startedDateTime":"2023-11-14T00:00:00Z","time":1,
		"request":{"method":"GET","url":"https://h2.example.com/","httpVersion":"HTTP/2",
			"headers":[{"name":":method","value":"GET"},{"name":":authority","value":"h2.example.com"},{"name":"accept","value":"*/*"}],
			"queryString":[],"cookies":[],"headersSize":-1,"bodySize":0},
		"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/2",
			"headers":[{"name":"content-type","value":"text/plain"}],"cookies":[],
			"content":{"size":2,"mimeType":"text/plain","text":"hi"},"redirectURL":"","headersSize":-1,"bodySize":2},
		"cache":{},"timings":{"send":0,"wait":1,"receive":0}}]}}`
	flows, err := Unmarshal([]byte(harDoc))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw := string(flows[0].Request.Raw)
	if strings.Contains(raw, ":method") || strings.Contains(raw, ":authority") {
		t.Fatalf("pseudo-headers leaked into raw request: %q", raw)
	}
	if !strings.Contains(raw, "Accept: */*") { // canonicalised by net/http
		t.Fatalf("normal header lost: %q", raw)
	}
}
