package project

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorkemguler/mimlec/internal/proxy"
	"github.com/gorkemguler/mimlec/internal/rules"
	"github.com/gorkemguler/mimlec/internal/scanner"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	reqH := http.Header{"User-Agent": {"mimlec"}}
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

	path := filepath.Join(t.TempDir(), "session.mimlec.json")
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
	if got.Request.Headers.Get("User-Agent") != "mimlec" {
		t.Fatalf("request headers lost: %v", got.Request.Headers)
	}
}
