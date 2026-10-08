package extension

import (
	"encoding/json"
	"io/fs"
	"testing"
)

func TestEmbedHasLoadableExtension(t *testing.T) {
	raw, err := fs.ReadFile(Files, "manifest.json")
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var m struct {
		Action     struct{ DefaultPopup string `json:"default_popup"` } `json:"action"`
		Background struct{ ServiceWorker string `json:"service_worker"` } `json:"background"`
		Icons      map[string]string `json:"icons"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	// Every file the manifest points at must be embedded, or Chrome refuses to load it.
	want := []string{m.Action.DefaultPopup, m.Background.ServiceWorker, "lib/proxy-config.js", "lib/browser.js"}
	for _, p := range m.Icons {
		want = append(want, p)
	}
	for _, p := range want {
		if _, err := fs.Stat(Files, p); err != nil {
			t.Errorf("embedded extension is missing %s", p)
		}
	}
	if _, err := fs.Stat(Files, "test"); err == nil {
		t.Error("tests should not be embedded")
	}
}
