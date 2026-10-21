package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gorkemguler/kanca/internal/activescan"
	"github.com/gorkemguler/kanca/internal/cert"
	"github.com/gorkemguler/kanca/internal/diff"
	"github.com/gorkemguler/kanca/internal/har"
	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/intruder"
	"github.com/gorkemguler/kanca/internal/mcp"
	"github.com/gorkemguler/kanca/internal/project"
	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/repeater"
	"github.com/gorkemguler/kanca/internal/rules"
	"github.com/gorkemguler/kanca/internal/scanner"
	"github.com/gorkemguler/kanca/internal/scope"
	"github.com/gorkemguler/kanca/internal/sitemap"
	"github.com/gorkemguler/kanca/internal/trust"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// appVersion is stamped into exported HAR and project files.
const appVersion = "0.3.2"

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
	// attack is the running attack, kept so the UI can pause/resume it.
	attack *intruder.Attack

	scopeMu      sync.Mutex
	scopeEnabled bool // record only target traffic
	scopeHosts   []string

	siteScanMu     sync.Mutex
	siteScanCancel context.CancelFunc
	siteScanLast   *SiteScanProgress
	// siteScanStopped is set by StopSiteScan so the done event can tell an
	// explicit stop apart from a clean finish.
	siteScanStopped bool

	// activeScanMu guards one cancellable single-flow scan per flow ID.
	activeScanMu     sync.Mutex
	activeScanCancel map[int64]*activeScanHandle

	rules   *rules.Set
	scanner *scanner.Scanner
	ws      *wsStore

	// AI assistant (MCP) endpoint.
	mcpMu  sync.Mutex
	mcpCfg mcp.Config
	mcpSvc *mcp.Service
	mcpErr string
}

// activeScanHandle identifies one single-flow scan so a stale completion
// cannot forget its replacement.
type activeScanHandle struct {
	cancel context.CancelFunc
}

// NewApp constructs the application backend, loading (or creating) the root CA.
func NewApp() (*App, error) {
	dir := configDir()
	ca, err := cert.NewAuthority(dir)
	if err != nil {
		return nil, err
	}
	return &App{
		ca:               ca,
		store:            history.New(0),
		rep:              repeater.New(true),
		addr:             "127.0.0.1:8080",
		rules:            rules.NewSet(),
		scanner:          scanner.New(),
		ws:               newWSStore(),
		activeScanCancel: map[int64]*activeScanHandle{},
	}, nil
}

// startup is invoked by Wails once the frontend is ready.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.store.Subscribe(func(id int64) {
		if f, ok := a.store.Get(id); ok {
			wruntime.EventsEmit(a.ctx, "proxy:flow", toEntryView(f))
			a.scanner.Inspect(f)
		}
	})
	a.scanner.OnFinding(func(fnd scanner.Finding) {
		wruntime.EventsEmit(a.ctx, "scanner:finding", fnd)
	})
	a.ws.onEvent = func(kind string, session *WSSession, frame *WSFrameView) {
		wruntime.EventsEmit(a.ctx, "ws:"+kind, session)
	}
	a.initMCP()
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
	p.SetScope(a.recordMatcher())
	p.SetRewriter(a.rulesRewriter())
	p.OnWSOpen(a.ws.onOpen)
	p.OnWSFrame(a.ws.onFrame)
	p.OnWSClose(a.ws.onClose)
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

// ExportRootCA asks where to save the root certificate and writes it there,
// returning the chosen path ("" when the dialog is cancelled). A dialog is
// needed because an app launched from Finder runs with "/" as its working
// directory, where a relative path can't be written.
func (a *App) ExportRootCA() (string, error) {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "Save Kanca root certificate",
		DefaultFilename: "kanca-ca.crt",
		Filters:         []wruntime.FileFilter{{DisplayName: "Certificate (*.crt)", Pattern: "*.crt;*.pem"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	return path, os.WriteFile(path, a.ca.RootCertPEM(), 0o644)
}

// TrustStatus says whether this computer trusts the certificates Kanca issues,
// and whether one-click install is available here.
type TrustStatus struct {
	Supported bool `json:"supported"`
	Trusted   bool `json:"trusted"`
}

// GetTrustStatus checks trust with the operating system's own verifier.
func (a *App) GetTrustStatus() TrustStatus {
	return TrustStatus{Supported: trust.Supported(), Trusted: trust.Trusted(a.ca)}
}

// InstallCA adds the root certificate to the login keychain as trusted. macOS
// shows its own authorisation prompt.
func (a *App) InstallCA() (TrustStatus, error) {
	if err := trust.Install(a.ca); err != nil {
		return a.trustChanged(), err
	}
	st := a.trustChanged()
	if !st.Trusted {
		return st, fmt.Errorf("the certificate was added, but the system still doesn't trust it; open Keychain Access, find \"Kanca Root CA\" and set it to Always Trust")
	}
	return st, nil
}

// RemoveCA removes the trust setting and the root certificate from the keychain.
func (a *App) RemoveCA() (TrustStatus, error) {
	err := trust.Remove(a.ca)
	st := a.trustChanged()
	if err == nil && st.Trusted {
		err = fmt.Errorf("removed from your login keychain, but this Mac still trusts Kanca's certificate because it is also installed system-wide: in Keychain Access, open the System keychain and delete \"Kanca Root CA\"")
	}
	return st, err
}

// trustChanged re-checks trust and tells every view, so the trust banner and
// CA / Settings agree.
func (a *App) trustChanged() TrustStatus {
	st := a.GetTrustStatus()
	wruntime.EventsEmit(a.ctx, "trust:status", st)
	return st
}

// ---- Scope -----------------------------------------------------------------

// ScopeConfig is the frontend-facing target list. Hosts are the targets:
// active scans, site scans and the AI assistant may only test these. Enabled
// additionally limits recording to them; otherwise everything is recorded.
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

// SetScope sets the targets and whether only their traffic is recorded (the
// rest is still proxied). Patterns match a host exactly, as a parent domain
// ("example.com" covers "api.example.com"), or via a "*." wildcard; URLs and
// host:port are reduced to the host.
func (a *App) SetScope(cfg ScopeConfig) {
	a.scopeMu.Lock()
	a.scopeEnabled = cfg.Enabled
	a.scopeHosts = scope.Normalize(cfg.Hosts)
	a.scopeMu.Unlock()
	a.withProxy(func(p *proxy.Proxy) { p.SetScope(a.recordMatcher()) })
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, "scope:changed", a.GetScope())
	}
}

// AddTarget adds host (a host, host:port or URL) to the targets.
func (a *App) AddTarget(host string) ScopeConfig {
	cfg := a.GetScope()
	cfg.Hosts = append(cfg.Hosts, host)
	a.SetScope(cfg)
	return a.GetScope()
}

// recordMatcher is the proxy's recording filter, or nil to record everything.
func (a *App) recordMatcher() func(host string) bool {
	a.scopeMu.Lock()
	enabled := a.scopeEnabled
	hosts := append([]string(nil), a.scopeHosts...)
	a.scopeMu.Unlock()
	if !enabled {
		return nil
	}
	return scope.Matcher(hosts)
}

// targetMatcher reports which hosts may be tested, or nil when no targets are
// set (then nothing may be).
func (a *App) targetMatcher() func(host string) bool {
	a.scopeMu.Lock()
	hosts := append([]string(nil), a.scopeHosts...)
	a.scopeMu.Unlock()
	return scope.Matcher(hosts)
}

// checkTarget explains that a host has to be added to the targets first.
func (a *App) checkTarget(authority string) error {
	if m := a.targetMatcher(); m != nil && m(hostOnlyApp(authority)) {
		return nil
	}
	return fmt.Errorf("%s is not one of your targets; add it in the Scanner tab to scan it", hostOnlyApp(authority))
}

// ---- Match & replace rules -------------------------------------------------

// GetRules returns the current match-and-replace rules.
func (a *App) GetRules() []rules.Rule { return a.rules.List() }

// SetRules replaces the rule set. Invalid regexps are rejected as a whole.
func (a *App) SetRules(in []rules.Rule) error { return a.rules.Replace(in) }

// rulesRewriter adapts the rule set to the proxy's rewrite hook.
func (a *App) rulesRewriter() func(phase, host string, raw []byte) []byte {
	return func(phase, host string, raw []byte) []byte {
		return a.rules.Apply(rules.Phase(phase), host, raw)
	}
}

// ---- Passive scanner -------------------------------------------------------

// GetFindings returns all passive scanner findings.
func (a *App) GetFindings() []scanner.Finding { return a.scanner.Findings() }

// SetFindingStatus moves a finding through the triage workflow
// (new/confirmed/resolved/false-positive).
func (a *App) SetFindingStatus(id int64, status string) error {
	if !a.scanner.SetStatus(id, scanner.Status(status)) {
		return fmt.Errorf("finding %d not found or invalid status %q", id, status)
	}
	return nil
}

// ClearFindings discards recorded findings.
func (a *App) ClearFindings() { a.scanner.Clear() }

// ActiveScanDone is emitted as "activescan:done" when a single-flow scan ends.
type ActiveScanDone struct {
	FlowID  int64  `json:"flowId"`
	Message string `json:"message"`
}

// ActiveScan runs a bounded set of probes against a single captured request and
// merges any findings into the Findings list. Only targets may be scanned.
// When aggressive is true it additionally runs
// boolean/time-based SQLi and time-based command-injection probes, which make the
// target do observable work; plus adds the checks ported from ActiveScan++.
// Probing runs in the background; results arrive as scanner:finding events, then
// activescan:done.
func (a *App) ActiveScan(flowID int64, aggressive, plus bool) error {
	f, ok := a.store.Get(flowID)
	if !ok {
		return fmt.Errorf("flow %d not found", flowID)
	}
	if err := a.checkTarget(f.Host); err != nil {
		return err
	}
	cfg := activescan.Config{
		Scheme:           f.Scheme,
		Host:             f.Host,
		Raw:              f.Request.Raw,
		InsecureUpstream: true,
		Aggressive:       aggressive,
		Plus:             plus,
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &activeScanHandle{cancel: cancel}
	a.activeScanMu.Lock()
	if prev := a.activeScanCancel[flowID]; prev != nil {
		prev.cancel()
	}
	a.activeScanCancel[flowID] = h
	a.activeScanMu.Unlock()
	go func() {
		defer func() {
			a.activeScanMu.Lock()
			if a.activeScanCancel[flowID] == h {
				delete(a.activeScanCancel, flowID)
			}
			a.activeScanMu.Unlock()
			cancel()
		}()
		findings, err := activescan.Run(ctx, cfg)
		for _, fnd := range findings {
			fnd.FlowID = flowID
			a.scanner.Add(fnd)
		}
		if a.ctx != nil {
			msg := ""
			if err != nil {
				msg = err.Error()
			} else if ctx.Err() != nil {
				msg = "stopped"
			}
			wruntime.EventsEmit(a.ctx, "activescan:done", ActiveScanDone{FlowID: flowID, Message: msg})
		}
	}()
	return nil
}

// StopActiveScan cancels a running single-flow scan.
func (a *App) StopActiveScan(flowID int64) {
	a.activeScanMu.Lock()
	defer a.activeScanMu.Unlock()
	if h := a.activeScanCancel[flowID]; h != nil {
		h.cancel()
		delete(a.activeScanCancel, flowID)
	}
}

// hostOnlyApp strips a port from an authority for scope matching.
func hostOnlyApp(authority string) string {
	if i := strings.LastIndexByte(authority, ':'); i > 0 && !strings.Contains(authority[i:], "]") {
		return authority[:i]
	}
	return authority
}

// ---- WebSocket sessions -----------------------------------------------------

// GetWSSessions returns all captured WebSocket connections and their frames.
func (a *App) GetWSSessions() []WSSession { return a.ws.List() }

// ClearWSSessions discards all captured WebSocket sessions and frames.
func (a *App) ClearWSSessions() { a.ws.Clear() }

// ---- Export & project ------------------------------------------------------

// ExportHAR prompts for a location and writes the captured history as a HAR
// 1.2 archive. A cancelled dialog is a no-op.
func (a *App) ExportHAR() error {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "Export HAR",
		DefaultFilename: "kanca-export.har",
		Filters:         []wruntime.FileFilter{{DisplayName: "HAR archive (*.har)", Pattern: "*.har"}},
	})
	if err != nil || path == "" {
		return err
	}
	data, err := har.Marshal(a.store.Snapshot(), appVersion)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// SaveProject prompts for a location and writes flows, rules, findings and
// scope to a project file. A cancelled dialog is a no-op.
func (a *App) SaveProject() error {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "Save Kanca project",
		DefaultFilename: "session.kanca.json",
		Filters:         []wruntime.FileFilter{{DisplayName: "Kanca project (*.json)", Pattern: "*.json"}},
	})
	if err != nil || path == "" {
		return err
	}
	return a.saveProjectTo(path)
}

func (a *App) saveProjectTo(path string) error {
	flows := a.store.Snapshot()
	dtos := make([]project.FlowDTO, 0, len(flows))
	for _, f := range flows {
		dtos = append(dtos, project.FromFlow(f))
	}
	sc := a.GetScope()
	return project.Save(path, project.File{
		Version:    appVersion,
		Flows:      dtos,
		Rules:      a.rules.List(),
		Findings:   a.scanner.Findings(),
		ScopeOn:    sc.Enabled,
		ScopeHosts: sc.Hosts,
	})
}

// LoadProject prompts for a project file, replaces the current session with
// its contents, and tells the frontend to refresh. A cancelled dialog is a
// no-op.
func (a *App) LoadProject() error {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title:   "Open Kanca project",
		Filters: []wruntime.FileFilter{{DisplayName: "Kanca project (*.json)", Pattern: "*.json"}},
	})
	if err != nil || path == "" {
		return err
	}
	return a.loadProjectFrom(path)
}

func (a *App) loadProjectFrom(path string) error {
	f, err := project.Load(path)
	if err != nil {
		return err
	}
	a.store.Clear()
	a.scanner.Clear()
	// Re-inspecting each loaded flow regenerates findings deterministically.
	for _, fl := range f.FlowList() {
		a.store.Add(fl)
	}
	if err := a.rules.Replace(f.Rules); err != nil {
		return fmt.Errorf("load project rules: %w", err)
	}
	a.SetScope(ScopeConfig{Enabled: f.ScopeOn, Hosts: f.ScopeHosts})
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, "project:loaded", len(f.Flows))
	}
	return nil
}

// ImportHAR prompts for a HAR file and loads its entries into the history,
// replacing the current capture (a HAR has no rules/scope of its own). The
// scanner re-inspects imported flows. A cancelled dialog is a no-op.
func (a *App) ImportHAR() error {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title:   "Import HAR",
		Filters: []wruntime.FileFilter{{DisplayName: "HAR archive (*.har, *.json)", Pattern: "*.har;*.json"}},
	})
	if err != nil || path == "" {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	flows, err := har.Unmarshal(data)
	if err != nil {
		return err
	}
	a.store.Clear()
	a.scanner.Clear()
	for _, fl := range flows {
		a.store.Add(fl)
	}
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, "project:loaded", len(flows))
	}
	return nil
}

// ---- Site map ---------------------------------------------------------------

// GetSiteMap returns the captured traffic arranged as a per-host path tree.
func (a *App) GetSiteMap() []*sitemap.Node {
	return sitemap.Build(a.store.Snapshot())
}

// ---- Diff -------------------------------------------------------------------

// maxDiffInputBytes caps each side of a UI diff so a huge response cannot
// stall the desktop thread (diff.Lines caps the comparison itself too).
const maxDiffInputBytes = 2 << 20

// DiffText returns a line-oriented diff of two texts (e.g. two repeater
// responses), for side-by-side comparison in the UI.
func (a *App) DiffText(before, after string) diff.Result {
	return diff.Lines(
		diff.CapInput(before, maxDiffInputBytes),
		diff.CapInput(after, maxDiffInputBytes),
	)
}

// ---- History ---------------------------------------------------------------

// ListHistory returns filtered, newest-first history entries. When
// searchBodies is true, the text also matches request/response bodies;
// hideStatus omits those status codes (e.g. 404 noise).
func (a *App) ListHistory(text string, methods []string, searchBodies bool, hideStatus []int) []history.Entry {
	hide := map[int]bool{}
	for _, s := range hideStatus {
		hide[s] = true
	}
	return a.store.List(history.Filter{Text: text, Methods: methods, SearchBodies: searchBodies, HideStatus: hide})
}

// ClearHistory discards all captured flows.
func (a *App) ClearHistory() { a.store.Clear() }

// AnnotateFlow sets a flow's user comment and highlight colour (empty clears).
func (a *App) AnnotateFlow(id int64, comment, highlight string) error {
	if !a.store.Annotate(id, comment, highlight) {
		return fmt.Errorf("flow %d not found", id)
	}
	return nil
}

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

// RepeaterTabView is a repeater tab as the frontend sees it. Raw must be a
// string: encoding/json would serialise repeater.Tab's []byte as base64.
type RepeaterTabView struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Raw    string `json:"raw"`
}

func toRepeaterTabView(t *repeater.Tab) *RepeaterTabView {
	return &RepeaterTabView{ID: t.ID, Name: t.Name, Scheme: t.Scheme, Host: t.Host, Raw: string(t.Raw)}
}

// RepeaterFromFlow opens a new repeater tab seeded from a captured flow.
func (a *App) RepeaterFromFlow(id int64) (*RepeaterTabView, error) {
	f, ok := a.store.Get(id)
	if !ok {
		return nil, fmt.Errorf("flow %d not found", id)
	}
	return toRepeaterTabView(a.rep.NewTab("", f.Scheme, f.Host, f.Request.Raw)), nil
}

// RepeaterNewTab creates an empty tab with a starter request line.
func (a *App) RepeaterNewTab(scheme, host, raw string) *RepeaterTabView {
	return toRepeaterTabView(a.rep.NewTab("", scheme, host, []byte(raw)))
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
	Type     string `json:"type"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Template string `json:"template"`
	Marker   string `json:"marker"`
	// Payloads is the literal, pre-expanded form (kept for compatibility).
	Payloads [][]string `json:"payloads"`
	// Specs, when non-empty, is expanded (numeric ranges + processors) into
	// the payload sets and takes precedence over Payloads.
	Specs     []intruder.PayloadSpec `json:"specs,omitempty"`
	GrepMatch string                 `json:"grepMatch"`
	// ExtractGrep harvests the first match (or capture group) per response.
	ExtractGrep string `json:"extractGrep"`
	Threads     int    `json:"threads"`
	// DelayMs waits this long between dispatches (WAF/rate-limit courtesy).
	DelayMs int `json:"delayMs"`
}

// resolvePayloads expands Specs when present, otherwise returns the literal
// Payloads unchanged.
func (cfg IntruderConfig) resolvePayloads() [][]string {
	if len(cfg.Specs) == 0 {
		return cfg.Payloads
	}
	out := make([][]string, 0, len(cfg.Specs))
	for _, s := range cfg.Specs {
		out = append(out, s.Generate())
	}
	return out
}

// IntruderPreview reports how many requests a config would issue and how many
// positions the template defines, for confirmation before launching.
type IntruderPreview struct {
	Positions int `json:"positions"`
	Requests  int `json:"requests"`
	// Capped is true when the combination space exceeded
	// intruder.MaxPlannedRequests and the tail was dropped.
	Capped bool `json:"capped"`
}

// PreviewIntruder validates a config and returns its size without running.
func (a *App) PreviewIntruder(cfg IntruderConfig) (*IntruderPreview, error) {
	att, tmpl, err := a.buildAttack(cfg)
	if err != nil {
		return nil, err
	}
	return &IntruderPreview{Positions: tmpl.Positions(), Requests: att.Count(), Capped: att.Truncated()}, nil
}

// StartIntruder launches an attack, streaming each result as an
// "intruder:result" event and an "intruder:done" event on completion.
func (a *App) StartIntruder(cfg IntruderConfig) error {
	att, _, err := a.buildAttack(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	total := att.Count()

	a.attackMu.Lock()
	if a.attackCancel != nil {
		a.attackCancel() // stop any previous attack
	}
	a.attackCancel = cancel
	a.attack = att
	a.attackMu.Unlock()

	go func() {
		defer cancel() // release the context once the run drains
		for res := range att.Run(ctx) {
			wruntime.EventsEmit(a.ctx, "intruder:result", res)
		}
		wruntime.EventsEmit(a.ctx, "intruder:done", total)
		a.attackMu.Lock()
		if a.attack == att {
			a.attack = nil
		}
		if a.attackCancel != nil {
			a.attackCancel = nil
		}
		a.attackMu.Unlock()
	}()
	return nil
}

// PauseIntruder freezes (true) or resumes (false) dispatching on the running
// attack. In-flight requests still finish.
func (a *App) PauseIntruder(paused bool) {
	a.attackMu.Lock()
	att := a.attack
	a.attackMu.Unlock()
	if att != nil {
		att.SetPaused(paused)
	}
}

// StopIntruder cancels a running attack.
func (a *App) StopIntruder() {
	a.attackMu.Lock()
	if a.attackCancel != nil {
		a.attackCancel()
		a.attackCancel = nil
	}
	a.attack = nil
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
		Payloads:         cfg.resolvePayloads(),
		Concurrency:      cfg.Threads,
		GrepMatch:        cfg.GrepMatch,
		ExtractGrep:      cfg.ExtractGrep,
		DelayMs:          cfg.DelayMs,
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
		return ".kanca"
	}
	return filepath.Join(home, ".kanca")
}
