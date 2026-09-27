package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gorkemguler/mimlec/internal/cert"
	"github.com/gorkemguler/mimlec/internal/history"
	"github.com/gorkemguler/mimlec/internal/intruder"
	"github.com/gorkemguler/mimlec/internal/proxy"
	"github.com/gorkemguler/mimlec/internal/repeater"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails-bound backend. Every exported method is callable from the
// TypeScript frontend; live updates are pushed as Wails events.
type App struct {
	ctx context.Context

	ca    *cert.Authority
	store *history.Store
	rep   *repeater.Repeater

	mu      sync.Mutex
	proxy   *proxy.Proxy
	running bool
	addr    string

	attackMu     sync.Mutex
	attackCancel context.CancelFunc

	scopeMu      sync.Mutex
	scopeEnabled bool
	scopeHosts   []string
}

// NewApp constructs the application backend, loading (or creating) the root CA.
func NewApp() (*App, error) {
	dir := configDir()
	ca, err := cert.NewAuthority(dir)
	if err != nil {
		return nil, err
	}
	return &App{
		ca:    ca,
		store: history.New(0),
		rep:   repeater.New(true),
		addr:  "127.0.0.1:8080",
	}, nil
}

// startup is invoked by Wails once the frontend is ready.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.store.Subscribe(func(id int64) {
		if f, ok := a.store.Get(id); ok {
			wruntime.EventsEmit(a.ctx, "proxy:flow", toEntryView(f))
		}
	})
}

// ---- Proxy lifecycle -------------------------------------------------------

// ProxyStatus reports the listener state.
type ProxyStatus struct {
	Running bool   `json:"running"`
	Addr    string `json:"addr"`
}

// GetStatus returns whether the proxy is running and on what address.
func (a *App) GetStatus() ProxyStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ProxyStatus{Running: a.running, Addr: a.addr}
}

// StartProxy binds and starts the intercepting proxy on addr.
func (a *App) StartProxy(addr string) (ProxyStatus, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return ProxyStatus{Running: true, Addr: a.addr}, nil
	}
	if addr == "" {
		addr = a.addr
	}
	p, err := proxy.New(proxy.Config{Addr: addr, CA: a.ca, InsecureUpstream: true})
	if err != nil {
		return ProxyStatus{}, err
	}
	p.OnFlow(func(f *proxy.Flow) { a.store.Add(f) })
	p.OnHold(func(h *proxy.Held) {
		wruntime.EventsEmit(a.ctx, "intercept:hold", toHeldView(h))
	})
	p.SetScope(a.scopeMatcher())
	if err := p.Start(); err != nil {
		return ProxyStatus{}, err
	}
	a.proxy = p
	a.running = true
	a.addr = p.Addr()
	return ProxyStatus{Running: true, Addr: a.addr}, nil
}

// StopProxy stops the listener.
func (a *App) StopProxy() error {
	a.mu.Lock()
	p := a.proxy
	a.running = false
	a.proxy = nil
	a.mu.Unlock()
	if p == nil {
		return nil
	}
	return p.Stop(context.Background())
}

// ---- Certificate authority -------------------------------------------------

// GetRootCAPEM returns the PEM-encoded root certificate for the user to import.
func (a *App) GetRootCAPEM() string { return string(a.ca.RootCertPEM()) }

// ExportRootCA writes the root certificate to path.
func (a *App) ExportRootCA(path string) error {
	return os.WriteFile(path, a.ca.RootCertPEM(), 0o644)
}

// ---- Scope -----------------------------------------------------------------

// ScopeConfig is the frontend-facing target scope.
type ScopeConfig struct {
	Enabled bool     `json:"enabled"`
	Hosts   []string `json:"hosts"`
}

// GetScope returns the current scope configuration.
func (a *App) GetScope() ScopeConfig {
	a.scopeMu.Lock()
	defer a.scopeMu.Unlock()
	return ScopeConfig{Enabled: a.scopeEnabled, Hosts: append([]string(nil), a.scopeHosts...)}
}

// SetScope updates which hosts are recorded. When enabled, only traffic whose
// host matches one of the patterns is added to the history; everything else is
// still proxied but not recorded. Patterns match a host exactly, as a parent
// domain ("example.com" covers "api.example.com"), or via a "*." wildcard.
func (a *App) SetScope(cfg ScopeConfig) {
	a.scopeMu.Lock()
	a.scopeEnabled = cfg.Enabled
	a.scopeHosts = normalizeHosts(cfg.Hosts)
	a.scopeMu.Unlock()
	a.withProxy(func(p *proxy.Proxy) { p.SetScope(a.scopeMatcher()) })
}

// scopeMatcher builds the host predicate for the proxy, or nil to record all.
func (a *App) scopeMatcher() func(host string) bool {
	a.scopeMu.Lock()
	enabled := a.scopeEnabled
	hosts := append([]string(nil), a.scopeHosts...)
	a.scopeMu.Unlock()
	if !enabled || len(hosts) == 0 {
		return nil
	}
	return func(host string) bool {
		host = strings.ToLower(host)
		for _, pat := range hosts {
			if hostMatches(host, pat) {
				return true
			}
		}
		return false
	}
}

func hostMatches(host, pat string) bool {
	if pat == "" {
		return false
	}
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[1:] // ".example.com"
		return strings.HasSuffix(host, suffix)
	}
	return host == pat || strings.HasSuffix(host, "."+pat)
}

func normalizeHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

// ---- History ---------------------------------------------------------------

// ListHistory returns filtered, newest-first history entries.
func (a *App) ListHistory(text string, methods []string) []history.Entry {
	return a.store.List(history.Filter{Text: text, Methods: methods})
}

// ClearHistory discards all captured flows.
func (a *App) ClearHistory() { a.store.Clear() }

// GetFlow returns the full detail (raw request/response) for a flow id.
func (a *App) GetFlow(id int64) (*FlowView, error) {
	f, ok := a.store.Get(id)
	if !ok {
		return nil, fmt.Errorf("flow %d not found", id)
	}
	return toFlowView(f), nil
}

// ---- Interception ----------------------------------------------------------

// SetIntercept toggles request interception.
func (a *App) SetIntercept(enabled bool) {
	a.withProxy(func(p *proxy.Proxy) { p.Interceptor().SetEnabled(enabled) })
}

// SetInterceptResponses toggles response interception.
func (a *App) SetInterceptResponses(enabled bool) {
	a.withProxy(func(p *proxy.Proxy) { p.Interceptor().SetInterceptResponses(enabled) })
}

// ForwardHeld forwards a held item, optionally replacing its bytes with raw.
func (a *App) ForwardHeld(id int64, raw string) {
	a.withProxy(func(p *proxy.Proxy) {
		var edited []byte
		if raw != "" {
			edited = []byte(raw)
		}
		p.Interceptor().Resolve(id, proxy.DecisionForward, edited)
	})
}

// DropHeld drops a held item.
func (a *App) DropHeld(id int64) {
	a.withProxy(func(p *proxy.Proxy) { p.Interceptor().Resolve(id, proxy.DecisionDrop, nil) })
}

// ForwardAll releases every held item.
func (a *App) ForwardAll() {
	a.withProxy(func(p *proxy.Proxy) { p.Interceptor().ForwardAll() })
}

// ---- Repeater --------------------------------------------------------------

// RepeaterFromFlow opens a new repeater tab seeded from a captured flow.
func (a *App) RepeaterFromFlow(id int64) (*repeater.Tab, error) {
	f, ok := a.store.Get(id)
	if !ok {
		return nil, fmt.Errorf("flow %d not found", id)
	}
	// Expose the raw request as a string-friendly tab.
	return a.rep.NewTab("", f.Scheme, f.Host, f.Request.Raw), nil
}

// RepeaterNewTab creates an empty tab with a starter request line.
func (a *App) RepeaterNewTab(scheme, host, raw string) *repeater.Tab {
	return a.rep.NewTab("", scheme, host, []byte(raw))
}

// RepeaterUpdate stores edits to a tab.
func (a *App) RepeaterUpdate(id int64, scheme, host, raw string) bool {
	return a.rep.Update(id, scheme, host, []byte(raw))
}

// RepeaterSend dispatches a tab's request and returns the resulting flow view.
func (a *App) RepeaterSend(id int64) (*FlowView, error) {
	f, ok := a.rep.Send(context.Background(), id)
	if !ok {
		return nil, fmt.Errorf("repeater tab %d not found", id)
	}
	return toFlowView(f), nil
}

// RepeaterClose removes a tab.
func (a *App) RepeaterClose(id int64) { a.rep.Close(id) }

// ---- Intruder --------------------------------------------------------------

// IntruderConfig is the frontend-facing attack description.
type IntruderConfig struct {
	Type      string     `json:"type"`
	Scheme    string     `json:"scheme"`
	Host      string     `json:"host"`
	Template  string     `json:"template"`
	Marker    string     `json:"marker"`
	Payloads  [][]string `json:"payloads"`
	GrepMatch string     `json:"grepMatch"`
	Threads   int        `json:"threads"`
}

// IntruderPreview reports how many requests a config would issue and how many
// positions the template defines, for confirmation before launching.
type IntruderPreview struct {
	Positions int `json:"positions"`
	Requests  int `json:"requests"`
}

// PreviewIntruder validates a config and returns its size without running.
func (a *App) PreviewIntruder(cfg IntruderConfig) (*IntruderPreview, error) {
	att, tmpl, err := a.buildAttack(cfg)
	if err != nil {
		return nil, err
	}
	return &IntruderPreview{Positions: tmpl.Positions(), Requests: att.Count()}, nil
}

// StartIntruder launches an attack, streaming each result as an
// "intruder:result" event and an "intruder:done" event on completion.
func (a *App) StartIntruder(cfg IntruderConfig) error {
	att, _, err := a.buildAttack(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())

	a.attackMu.Lock()
	if a.attackCancel != nil {
		a.attackCancel() // stop any previous attack
	}
	a.attackCancel = cancel
	a.attackMu.Unlock()

	go func() {
		for res := range att.Run(ctx) {
			wruntime.EventsEmit(a.ctx, "intruder:result", res)
		}
		wruntime.EventsEmit(a.ctx, "intruder:done", att.Count())
		a.attackMu.Lock()
		if a.attackCancel != nil {
			a.attackCancel = nil
		}
		a.attackMu.Unlock()
	}()
	return nil
}

// StopIntruder cancels a running attack.
func (a *App) StopIntruder() {
	a.attackMu.Lock()
	if a.attackCancel != nil {
		a.attackCancel()
		a.attackCancel = nil
	}
	a.attackMu.Unlock()
}

func (a *App) buildAttack(cfg IntruderConfig) (*intruder.Attack, *intruder.Template, error) {
	tmpl, err := intruder.Parse([]byte(cfg.Template), cfg.Marker)
	if err != nil {
		return nil, nil, err
	}
	att, err := intruder.NewAttack(tmpl, intruder.Config{
		Type:             intruder.AttackType(cfg.Type),
		Scheme:           cfg.Scheme,
		Host:             cfg.Host,
		Payloads:         cfg.Payloads,
		Concurrency:      cfg.Threads,
		GrepMatch:        cfg.GrepMatch,
		InsecureUpstream: true,
	})
	if err != nil {
		return nil, nil, err
	}
	return att, tmpl, nil
}

// ---- helpers ---------------------------------------------------------------

func (a *App) withProxy(fn func(*proxy.Proxy)) {
	a.mu.Lock()
	p := a.proxy
	a.mu.Unlock()
	if p != nil {
		fn(p)
	}
}

func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".mimlec"
	}
	return filepath.Join(home, ".mimlec")
}
