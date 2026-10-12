package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAddDesktopEntryKeepsOtherServersAndBacksUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Claude", "claude_desktop_config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := `{"mcpServers":{"other":{"command":"x"}},"theme":"dark"}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	entry := map[string]any{"command": "/Applications/kanca.app/Contents/MacOS/kanca", "args": []string{"mcp-stdio"}}
	if err := addDesktopEntry(path, entry); err != nil {
		t.Fatalf("addDesktopEntry: %v", err)
	}

	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
		Theme string `json:"theme"`
	}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("result isn't JSON: %v\n%s", err, data)
	}
	if cfg.MCPServers["other"].Command != "x" || cfg.Theme != "dark" {
		t.Fatalf("existing settings were lost:\n%s", data)
	}
	if k := cfg.MCPServers["kanca"]; k.Command != entry["command"] || len(k.Args) != 1 || k.Args[0] != "mcp-stdio" {
		t.Fatalf("kanca entry = %+v", k)
	}
	if bak, _ := os.ReadFile(path + ".bak"); string(bak) != original {
		t.Fatalf("backup = %q, want the original file", bak)
	}
}

func TestAddDesktopEntryCreatesMissingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Claude", "claude_desktop_config.json")
	if err := addDesktopEntry(path, map[string]any{"command": "kanca", "args": []string{"mcp-stdio"}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !json.Valid(data) {
		t.Fatalf("config not created as JSON: %v %s", err, data)
	}
}

func TestAddDesktopEntryLeavesInvalidConfigUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	broken := `{"mcpServers": {` // e.g. hand-edited and left broken
	_ = os.WriteFile(path, []byte(broken), 0o600)
	if err := addDesktopEntry(path, map[string]any{"command": "kanca"}); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
	if data, _ := os.ReadFile(path); string(data) != broken {
		t.Fatalf("invalid config was modified: %q", data)
	}
}
