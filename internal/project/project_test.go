package project

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/rules"
	"github.com/gorkemguler/kanca/internal/scanner"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	reqH := http.Header{"User-Agent": {"kanca"}}
	respH := http.Header{"Content-Type": {"text/html"}}
	orig := &proxy.Flow{
		ID: 7, Scheme: "https", Method: "GET", Host: "example.com:443",
		Path: "/a", URL: "https://example.com:443/a", StatusCode: 200,
		Duration: 12, Started: time.Unix(1700000000, 0).UTC(),
		Request:  proxy.Message{Raw: []byte("GET /a HTTP/1.1\r\n\r\n"), Headers: reqH, Body: []byte("q=1")},
		Response: proxy.Message{Raw: []byte("HTTP/1.1 200 OK\r\n\r\nhi"), Headers: respH, Body: []byte("hi")},
	}

	f := File{
		Version: "1.0",
		Flows:   []FlowDTO{FromFlow(orig)},
		Rules:   []rules.Rule{{Name: "r", Enabled: true, Phase: rules.PhaseRequest, Part: rules.PartHeaders, Match: "a", Replace: "b"}},
		Findings: []scanner.Finding{
			{ID: 1, Severity: scanner.Medium, Title: "Missing HSTS", Host: "example.com:443"},
		},
		ScopeOn:    true,
		ScopeHosts: []string{"example.com"},
	}

	path := filepath.Join(t.TempDir(), "session.kanca.json")
	if err := Save(path, f); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.SavedAt.IsZero() {
		t.Error("SavedAt not stamped")
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Name != "r" {
		t.Fatalf("rules lost: %+v", loaded.Rules)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].Title != "Missing HSTS" {
		t.Fatalf("findings lost: %+v", loaded.Findings)
	}
	if !loaded.ScopeOn || len(loaded.ScopeHosts) != 1 {
		t.Fatalf("scope lost: %+v", loaded)
	}

	flows := loaded.FlowList()
	if len(flows) != 1 {
		t.Fatalf("flow count = %d", len(flows))
	}
	got := flows[0]
	if got.ID != 7 || got.URL != orig.URL || got.StatusCode != 200 {
		t.Fatalf("flow meta lost: %+v", got)
	}
	if string(got.Request.Raw) != string(orig.Request.Raw) {
		t.Fatalf("request raw lost: %q", got.Request.Raw)
	}
	if string(got.Response.Body) != "hi" {
		t.Fatalf("response body lost: %q", got.Response.Body)
	}
	if got.Request.Headers.Get("User-Agent") != "kanca" {
		t.Fatalf("request headers lost: %v", got.Request.Headers)
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "weird.kanca.json")
	if err := Save(path, File{Flows: []FlowDTO{}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Rewrite with a foreign version marker.
	rewritten := strings.Replace(string(data), `"version": "1"`, `"version": "v99-foreign"`, 1)
	if rewritten == string(data) {
		t.Fatal("version stamp not found in saved file")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a foreign version, want an error")
	}
	// A newer major ("2") must also fail, while the 0.x/1.x lineage loads.
	for _, v := range []string{"2", "10.0"} {
		rewritten2 := strings.Replace(string(data), `"version": "1"`, `"version": "`+v+`"`, 1)
		if err := os.WriteFile(path, []byte(rewritten2), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("Load accepted newer-major version %q, want an error", v)
		}
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.kanca.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted garbage, want an error")
	}
}
