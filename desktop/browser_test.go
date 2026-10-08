package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteExtensionProducesLoadableFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "browser-extension")
	// A stale file from an older version must not survive a re-export.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stale.js"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeExtension(dir); err != nil {
		t.Fatalf("writeExtension: %v", err)
	}
	for _, p := range []string{"manifest.json", "popup.html", "background.js", "lib/browser.js", "icons/on-16.png"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "stale.js")); !os.IsNotExist(err) {
		t.Error("stale file from a previous export was kept")
	}
}
