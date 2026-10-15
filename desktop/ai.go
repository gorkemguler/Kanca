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
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Level   string `json:"level"`
	Mask    bool   `json:"mask"`
	URL     string `json:"url"`
	Error   string `json:"error,omitempty"`
	Sent    int    `json:"sent"`
	Budget  int    `json:"budget"`
	// ClaudeCode is the command that registers Kanca with Claude Code.
	ClaudeCode string `json:"claudeCode"`
	// ClaudeDesktop is the config entry for Claude Desktop, which launches this
	// binary as a stdio bridge.
	ClaudeDesktop     string `json:"claudeDesktop"`
	ClaudeDesktopPath string `json:"claudeDesktopPath"`
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
		return mcp.Options{Level: a.mcpCfg.Level, Mask: a.mcpCfg.Mask}
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
		Enabled: cfg.Enabled, Level: cfg.Level, Mask: cfg.Mask, URL: cfg.URL(),
		Error: errText, Budget: mcp.DefaultBudget,
		ClaudeCode:        fmt.Sprintf(`claude mcp add --transport http kanca %s --header "Authorization: Bearer %s"`, cfg.URL(), cfg.Token),
		ClaudeDesktopPath: claudeDesktopConfigPath(),
	}
	if svc != nil && svc.Addr() != "" {
		st.Running = true
		st.Sent = svc.Server.Sent()
	}
	if entry, err := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{"kanca": desktopEntry()}}, "", "  "); err == nil {
		st.ClaudeDesktop = string(entry)
	}
	return st
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

// SetMCPSettings turns AI access on or off and sets its level and masking.
// Level and masking apply immediately; toggling restarts the endpoint.
func (a *App) SetMCPSettings(enabled bool, level string, mask bool) (MCPStatus, error) {
	if level != mcp.LevelRead && level != mcp.LevelReadWrite {
		return a.GetMCPStatus(), fmt.Errorf("unknown access level %q", level)
	}
	a.mcpMu.Lock()
	toggled := a.mcpCfg.Enabled != enabled
	a.mcpCfg.Enabled, a.mcpCfg.Level, a.mcpCfg.Mask = enabled, level, mask
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
func (a *App) RegenerateMCPToken() (MCPStatus, error) {
	a.mcpMu.Lock()
	a.mcpCfg.Token = mcp.NewToken()
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
