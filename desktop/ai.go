package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gorkemguler/kanca/internal/mcp"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// MCPStatus describes the AI assistant endpoint for the settings screen.
type MCPStatus struct {
	Enabled     bool   `json:"enabled"`
	Running     bool   `json:"running"`
	Level       string `json:"level"`
	Mask        bool   `json:"mask"`
	AllowDelete bool   `json:"allowDelete"`
	URL         string `json:"url"`
	Error       string `json:"error,omitempty"`
	Sent        int    `json:"sent"`
	Budget      int    `json:"budget"`
	// ClaudeCode is the command that registers Kanca with Claude Code.
	ClaudeCode string `json:"claudeCode"`
	// ClaudeDesktop is the config entry for Claude Desktop, which launches this
	// binary as a stdio bridge.
	ClaudeDesktop     string `json:"claudeDesktop"`
	ClaudeDesktopPath string `json:"claudeDesktopPath"`
	// OpencodeRemote is a ready-to-copy opencode.json snippet for the
	// remote/HTTP route (same endpoint Claude Code uses). The token is NOT
	// embedded: it references {env:KANCA_MCP_TOKEN} so the secret never lands
	// in the config file.
	OpencodeRemote string `json:"opencodeRemote"`
	// OpencodeLocal is a ready-to-copy opencode.json snippet for the
	// local/stdio route (same bridge Claude Desktop uses: kanca mcp-stdio).
	// No secret is needed: the bridge reads ~/.kanca/mcp.json itself.
	OpencodeLocal string `json:"opencodeLocal"`
	// OpencodeExport fills KANCA_MCP_TOKEN from the saved config without
	// printing the secret, for the remote route.
	OpencodeExport string `json:"opencodeExport"`
	// OpencodeExportWin is the same for Windows PowerShell (no jq/~ there).
	OpencodeExportWin string `json:"opencodeExportWin"`
}

func (a *App) newMCPServer() *mcp.Server {
	return mcp.NewServer(mcp.Deps{
		Store:      a.store,
		Scanner:    a.scanner,
		Scope:      a.targetMatcher,
		ScopeHosts: func() []string { return a.GetScope().Hosts },
		Version:    appVersion,
		OnActivity: func(act mcp.Activity) { wruntime.EventsEmit(a.ctx, "mcp:activity", act) },
	}, func() mcp.Options {
		a.mcpMu.Lock()
		defer a.mcpMu.Unlock()
		return mcp.Options{
			Level: a.mcpCfg.Level, Mask: a.mcpCfg.Mask,
			AllowDelete: a.mcpCfg.AllowDelete,
		}
	})
}

// initMCP loads the saved settings and starts the endpoint if it was on.
func (a *App) initMCP() {
	cfg, err := mcp.LoadConfig(configDir())
	a.mcpMu.Lock()
	a.mcpCfg = cfg
	if err != nil {
		a.mcpErr = err.Error()
	}
	a.mcpMu.Unlock()
	if err == nil && cfg.Enabled {
		a.restartMCP()
	}
}

// restartMCP (re)starts the endpoint with a fresh session (request budget and
// secret placeholders), or stops it when disabled.
func (a *App) restartMCP() {
	a.mcpMu.Lock()
	cfg, old := a.mcpCfg, a.mcpSvc
	a.mcpSvc, a.mcpErr = nil, ""
	a.mcpMu.Unlock()
	if old != nil {
		_ = old.Stop()
	}
	if !cfg.Enabled {
		return
	}
	svc := &mcp.Service{Server: a.newMCPServer()}
	err := svc.Start(cfg.Addr, cfg.Token)
	a.mcpMu.Lock()
	if err != nil {
		a.mcpErr = err.Error()
	} else {
		a.mcpSvc = svc
	}
	a.mcpMu.Unlock()
}

// GetMCPStatus reports the endpoint's settings and state.
func (a *App) GetMCPStatus() MCPStatus {
	a.mcpMu.Lock()
	cfg, svc, errText := a.mcpCfg, a.mcpSvc, a.mcpErr
	a.mcpMu.Unlock()
	st := MCPStatus{
		Enabled: cfg.Enabled, Level: cfg.Level, Mask: cfg.Mask,
		AllowDelete: cfg.AllowDelete, URL: cfg.URL(),
		Error: errText, Budget: mcp.DefaultBudget,
		ClaudeCode:        fmt.Sprintf(`claude mcp add --transport http kanca %s --header "Authorization: Bearer %s"`, cfg.URL(), cfg.Token),
		ClaudeDesktopPath: claudeDesktopConfigPath(),
		OpencodeExport:    `export KANCA_MCP_TOKEN="$(jq -r .token ~/.kanca/mcp.json)"`,
		OpencodeExportWin: `$env:KANCA_MCP_TOKEN = (Get-Content $HOME/.kanca/mcp.json | ConvertFrom-Json).token`,
	}
	if svc != nil && svc.Addr() != "" {
		st.Running = true
		st.Sent = svc.Server.Sent()
	}
	if entry, err := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{"kanca": desktopEntry()}}, "", "  "); err == nil {
		st.ClaudeDesktop = string(entry)
	}
	st.OpencodeRemote = marshalSnippet(opencodeRemoteEntry(cfg.URL()))
	st.OpencodeLocal = marshalSnippet(opencodeLocalEntry())
	return st
}

// marshalSnippet encodes a ready-to-copy config snippet. String maps cannot
// fail in practice, but a silent "" would confuse Copy downstream, so failures
// are logged instead of swallowed.
func marshalSnippet(v map[string]any) string {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kanca: encoding MCP snippet: %v\n", err)
		return ""
	}
	return string(out)
}

// GetMCPActivity returns what the assistant did this session, oldest first.
func (a *App) GetMCPActivity() []mcp.Activity {
	a.mcpMu.Lock()
	svc := a.mcpSvc
	a.mcpMu.Unlock()
	if svc == nil {
		return []mcp.Activity{}
	}
	return svc.Server.Activity()
}

// SetMCPSettings turns AI access on or off and sets its level, masking and
// whether assistants may send DELETE. Settings apply immediately; toggling
// restarts the endpoint.
func (a *App) SetMCPSettings(enabled bool, level string, mask, allowDelete bool) (MCPStatus, error) {
	if level != mcp.LevelRead && level != mcp.LevelReadWrite {
		return a.GetMCPStatus(), fmt.Errorf("unknown access level %q", level)
	}
	a.mcpMu.Lock()
	toggled := a.mcpCfg.Enabled != enabled
	a.mcpCfg.Enabled, a.mcpCfg.Level, a.mcpCfg.Mask = enabled, level, mask
	a.mcpCfg.AllowDelete = allowDelete
	cfg := a.mcpCfg
	a.mcpMu.Unlock()
	if err := mcp.SaveConfig(configDir(), cfg); err != nil {
		return a.GetMCPStatus(), err
	}
	if toggled {
		a.restartMCP()
	}
	return a.GetMCPStatus(), nil
}

// RegenerateMCPToken replaces the token, disconnecting clients that use the
// old one; Claude Code must be registered again (Claude Desktop needs nothing).
// Opencode remote users must re-export KANCA_MCP_TOKEN; Opencode local/stdio
// users need nothing.
func (a *App) RegenerateMCPToken() (MCPStatus, error) {
	tok, err := mcp.NewToken()
	if err != nil {
		return a.GetMCPStatus(), err
	}
	a.mcpMu.Lock()
	a.mcpCfg.Token = tok
	cfg := a.mcpCfg
	a.mcpMu.Unlock()
	if err := mcp.SaveConfig(configDir(), cfg); err != nil {
		return a.GetMCPStatus(), err
	}
	a.restartMCP()
	return a.GetMCPStatus(), nil
}

// AddToClaudeDesktop registers Kanca in Claude Desktop's config, keeping every
// other entry and saving a backup first. Claude Desktop must be restarted.
func (a *App) AddToClaudeDesktop() (string, error) {
	path := claudeDesktopConfigPath()
	if path == "" {
		return "", errors.New("Claude Desktop isn't available on this platform; add the config shown here by hand")
	}
	return path, addDesktopEntry(path, desktopEntry())
}

func desktopEntry() map[string]any {
	exe, err := os.Executable()
	if err != nil {
		exe = "kanca"
	}
	return map[string]any{"command": exe, "args": []string{"mcp-stdio"}}
}

// opencodeRemoteEntry builds the opencode.json snippet for the remote/HTTP
// route. It mirrors `claude mcp add --transport http` but keeps the secret
// out of the file via {env:KANCA_MCP_TOKEN}. oauth:false stops opencode from
// starting an OAuth flow when the bearer is missing/wrong (it should 401).
func opencodeRemoteEntry(url string) map[string]any {
	return map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"mcp": map[string]any{
			"kanca": map[string]any{
				"type":    "remote",
				"url":     url,
				"headers": map[string]any{"Authorization": "Bearer {env:KANCA_MCP_TOKEN}"},
				"oauth":   false,
				"enabled": true,
			},
		},
	}
}

// opencodeLocalEntry builds the opencode.json snippet for the local/stdio
// route. It mirrors the Claude Desktop bridge (kanca mcp-stdio): no secret
// is needed because the bridge reads ~/.kanca/mcp.json itself. opencode
// wants command as a single array (binary + args together).
func opencodeLocalEntry() map[string]any {
	exe, err := os.Executable()
	if err != nil {
		exe = "kanca"
	}
	return map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"mcp": map[string]any{
			"kanca": map[string]any{
				"type":    "local",
				"command": []string{exe, "mcp-stdio"},
				"enabled": true,
			},
		},
	}
}

func addDesktopEntry(path string, entry map[string]any) error {
	cfg := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		if len(data) > 0 {
			if err := json.Unmarshal(data, &cfg); err != nil {
				return fmt.Errorf("Claude Desktop's config at %s isn't valid JSON, so it was left untouched: %w", path, err)
			}
			if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
				return fmt.Errorf("couldn't back up %s: %w", path, err)
			}
		}
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers["kanca"] = entry
	cfg["mcpServers"] = servers
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
}

func claudeDesktopConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		if dir := os.Getenv("APPDATA"); dir != "" {
			return filepath.Join(dir, "Claude", "claude_desktop_config.json")
		}
	}
	return "" // Claude Desktop isn't released for Linux
}
