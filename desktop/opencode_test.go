package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOpencodeRemoteEntryUsesEnvPlaceholderAndDisablesOAuth(t *testing.T) {
	entry := opencodeRemoteEntry("http://127.0.0.1:8765/mcp")
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var cfg struct {
		MCP map[string]struct {
			Type    string            `json:"type"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			OAuth   *bool             `json:"oauth"`
			Enabled bool              `json:"enabled"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("result isn't JSON: %v\n%s", err, raw)
	}
	k, ok := cfg.MCP["kanca"]
	if !ok {
		t.Fatalf("missing mcp.kanca:\n%s", raw)
	}
	if k.Type != "remote" || k.URL != "http://127.0.0.1:8765/mcp" {
		t.Fatalf("type/url = %q %q, want remote + endpoint", k.Type, k.URL)
	}
	auth := k.Headers["Authorization"]
	if !strings.Contains(auth, "{env:KANCA_MCP_TOKEN}") {
		t.Fatalf("Authorization header embeds a real token or wrong placeholder: %q", auth)
	}
	if k.OAuth == nil || *k.OAuth != false {
		t.Fatalf("oauth must be false (else opencode starts an OAuth flow on 401):\n%s", raw)
	}
	if !k.Enabled {
		t.Fatalf("entry should be enabled:\n%s", raw)
	}
}

func TestOpencodeLocalEntryIsSingleCommandArray(t *testing.T) {
	entry := opencodeLocalEntry()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var cfg struct {
		MCP map[string]struct {
			Type    string   `json:"type"`
			Command []string `json:"command"`
			Enabled bool     `json:"enabled"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("result isn't JSON: %v\n%s", err, raw)
	}
	k, ok := cfg.MCP["kanca"]
	if !ok {
		t.Fatalf("missing mcp.kanca:\n%s", raw)
	}
	if k.Type != "local" {
		t.Fatalf("type = %q, want local", k.Type)
	}
	if len(k.Command) != 2 || k.Command[1] != "mcp-stdio" || k.Command[0] == "" {
		t.Fatalf("command must be [binary \"mcp-stdio\"], got %q", k.Command)
	}
	if !k.Enabled {
		t.Fatalf("entry should be enabled:\n%s", raw)
	}
}

func TestGetMCPStatusCarriesOpencodeSnippets(t *testing.T) {
	a := &App{}
	a.mcpCfg.Enabled = true
	st := a.GetMCPStatus()
	for name, snippet := range map[string]string{"remote": st.OpencodeRemote, "local": st.OpencodeLocal} {
		if snippet == "" {
			t.Fatalf("Opencode %s snippet is empty", name)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(snippet), &v); err != nil {
			t.Fatalf("Opencode %s isn't JSON: %v\n%s", name, err, snippet)
		}
		mcp, _ := v["mcp"].(map[string]any)
		if mcp == nil || mcp["kanca"] == nil {
			t.Fatalf("Opencode %s misses mcp.kanca:\n%s", name, snippet)
		}
	}
	if st.OpencodeExport == "" || !strings.Contains(st.OpencodeExport, "KANCA_MCP_TOKEN") {
		t.Fatalf("OpencodeExport should export KANCA_MCP_TOKEN, got %q", st.OpencodeExport)
	}
	// The remote snippet must never contain the real bearer token.
	if strings.Contains(st.OpencodeRemote, a.mcpCfg.Token) && a.mcpCfg.Token != "" {
		t.Fatalf("remote snippet leaks the real token")
	}
}

func TestGetMCPStatusNeverLeaksTokenEvenWhenSet(t *testing.T) {
	a := &App{}
	a.mcpCfg.Enabled = true
	a.mcpCfg.Token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	a.mcpCfg.Addr = "127.0.0.1:8765"
	st := a.GetMCPStatus()
	if strings.Contains(st.OpencodeRemote, a.mcpCfg.Token) {
		t.Fatalf("remote snippet leaks the real token")
	}
	if !strings.Contains(st.OpencodeRemote, "{env:KANCA_MCP_TOKEN}") {
		t.Fatalf("remote snippet lost the env placeholder")
	}
}

func TestOpencodeSnippetsSurviveEmptyConfig(t *testing.T) {
	a := &App{} // zero cfg: Token/Addr empty
	st := a.GetMCPStatus()
	for name, s := range map[string]string{"remote": st.OpencodeRemote, "local": st.OpencodeLocal} {
		var v map[string]any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatalf("%s not JSON on empty cfg: %v", name, err)
		}
	}
	// The remote snippet must still carry the url key (possibly empty),
	// so consumers can tell "no endpoint" from "broken snippet".
	var remote struct {
		MCP map[string]struct {
			URL string `json:"url"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal([]byte(st.OpencodeRemote), &remote); err != nil {
		t.Fatalf("remote not JSON: %v", err)
	}
	if _, ok := remote.MCP["kanca"]; !ok {
		t.Fatalf("remote misses mcp.kanca on empty cfg")
	}
}

func TestOpencodeExportWinIsPowerShellWithoutSecrets(t *testing.T) {
	a := &App{}
	a.mcpCfg.Token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	st := a.GetMCPStatus()
	if st.OpencodeExportWin == "" {
		t.Fatal("OpencodeExportWin is empty")
	}
	for _, want := range []string{"$env:KANCA_MCP_TOKEN", "mcp.json"} {
		if !strings.Contains(st.OpencodeExportWin, want) {
			t.Fatalf("OpencodeExportWin misses %q: %q", want, st.OpencodeExportWin)
		}
	}
	if strings.Contains(st.OpencodeExportWin, a.mcpCfg.Token) {
		t.Fatal("OpencodeExportWin leaks the real token")
	}
	if strings.Contains(st.OpencodeExportWin, "jq") {
		t.Fatalf("Windows command must not need jq: %q", st.OpencodeExportWin)
	}
}
