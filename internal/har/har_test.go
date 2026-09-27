package har

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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
