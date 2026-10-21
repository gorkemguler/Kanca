package main

import (
	"context"
	"errors"
	"strings"

	"github.com/gorkemguler/kanca/internal/activescan"
	"github.com/gorkemguler/kanca/internal/proxy"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// SiteScanPlan tells the user what a site scan would probe before it starts.
type SiteScanPlan struct {
	Host string `json:"host"`
	// Safe counts GET requests with parameters; Unsafe counts state-changing
	// ones (forms, API writes), which are only scanned when asked.
	Safe   int `json:"safe"`
	Unsafe int `json:"unsafe"`
}

// SiteScanProgress is emitted as "sitescan:progress" before each request.
type SiteScanProgress struct {
	Host    string `json:"host"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Current string `json:"current"`
	Found   int    `json:"found"`
}

// SiteScanDone is emitted as "sitescan:done" when a site scan ends.
type SiteScanDone struct {
	Host    string `json:"host"`
	Scanned int    `json:"scanned"`
	Found   int    `json:"found"`
	Stopped bool   `json:"stopped"`
	// Errors counts requests whose probes failed to run (network/target
	// errors); ErrorSample holds the first one for display.
	Errors      int    `json:"errors"`
	ErrorSample string `json:"errorSample,omitempty"`
}

// SiteScanOptions tunes ScanSite from the UI.
type SiteScanOptions struct {
	// IncludeUnsafe adds state-changing requests (each probe repeats them).
	IncludeUnsafe bool `json:"includeUnsafe"`
	// IncludeDelete adds DELETE requests (as unsafe). Off by default.
	IncludeDelete bool `json:"includeDelete"`
	// Aggressive adds boolean/time SQLi and time command-injection probes.
	Aggressive bool `json:"aggressive"`
	// Plus adds the ActiveScan++ checks, and with them requests without
	// parameters.
	Plus bool `json:"plus"`
	// SkipQuery/SkipBody/SkipJSON restrict insertion points.
	SkipQuery bool `json:"skipQuery"`
	SkipBody  bool `json:"skipBody"`
	SkipJSON  bool `json:"skipJson"`
}

// PlanSiteScan counts the captured requests a scan would probe: on host
// (host:port, as the site map shows it), which must be a target, or on every
// target when host is "". The same options as ScanSite apply, so the preview
// matches what ScanSite would probe.
func (a *App) PlanSiteScan(host string, opts SiteScanOptions) (SiteScanPlan, error) {
	include, err := a.scanFilter(host)
	if err != nil {
		return SiteScanPlan{Host: host}, err
	}
	p := activescan.PlanSite(a.store.Snapshot(), include, activescan.SiteOptions{
		IncludeDelete: opts.IncludeDelete, Plus: opts.Plus,
		SkipQuery: opts.SkipQuery, SkipBody: opts.SkipBody, SkipJSON: opts.SkipJSON,
	})
	return SiteScanPlan{Host: host, Safe: len(p.Safe), Unsafe: len(p.Unsafe)}, nil
}

// scanFilter selects the flows a scan of host may probe ("" = all targets).
func (a *App) scanFilter(host string) (func(authority string) bool, error) {
	if host != "" {
		if err := a.checkTarget(host); err != nil {
			return nil, err
		}
		return func(authority string) bool { return strings.EqualFold(authority, host) }, nil
	}
	m := a.targetMatcher()
	if m == nil {
		return nil, errors.New("add the sites you're allowed to test as targets first")
	}
	return func(authority string) bool { return m(hostOnlyApp(authority)) }, nil
}

// ScanSite actively scans every captured request with parameters on host, or
// on every target when host is "", one at a time in the background, adding
// what it finds to Findings. Forms and other state-changing requests are
// included only with opts.IncludeUnsafe, DELETE only with opts.IncludeDelete,
// since each probe repeats them. Progress arrives as sitescan:progress events,
// then sitescan:done.
func (a *App) ScanSite(host string, opts SiteScanOptions) error {
	include, err := a.scanFilter(host)
	if err != nil {
		return err
	}
	plan := activescan.PlanSite(a.store.Snapshot(), include, activescan.SiteOptions{
		IncludeDelete: opts.IncludeDelete, Plus: opts.Plus,
		SkipQuery: opts.SkipQuery, SkipBody: opts.SkipBody, SkipJSON: opts.SkipJSON,
	})
	// Copy: appending Unsafe onto plan.Safe directly could write into the
	// plan's backing array.
	flows := make([]*proxy.Flow, len(plan.Safe))
	copy(flows, plan.Safe)
	if opts.IncludeUnsafe {
		flows = append(flows, plan.Unsafe...)
	}
	if len(flows) == 0 {
		return errors.New("Kanca hasn't captured any requests with parameters to scan yet: browse the site through Kanca first")
	}
	// Host-level checks run once per host for the whole scan.
	plusHosts := &activescan.HostSet{}

	ctx, cancel := context.WithCancel(context.Background())
	a.siteScanMu.Lock()
	if a.siteScanCancel != nil {
		a.siteScanMu.Unlock()
		cancel()
		return errors.New("a site scan is already running")
	}
	a.siteScanCancel, a.siteScanStopped = cancel, false
	a.siteScanMu.Unlock()

	go func() {
		defer func() {
			a.siteScanMu.Lock()
			a.siteScanCancel, a.siteScanLast, a.siteScanStopped = nil, nil, false
			a.siteScanMu.Unlock()
			cancel()
		}()
		scanned, found, scanErrs := 0, 0, 0
		var errSample string
		for _, f := range flows {
			if ctx.Err() != nil {
				break
			}
			a.setSiteScanProgress(&SiteScanProgress{
				Host: host, Done: scanned, Total: len(flows), Current: f.Method + " " + f.Path, Found: found,
			})
			res, runErr := activescan.Run(ctx, activescan.Config{
				Scheme: f.Scheme, Host: f.Host, Raw: f.Request.Raw,
				InsecureUpstream: true, Aggressive: opts.Aggressive,
				Plus: opts.Plus, PlusHosts: plusHosts,
				SkipQuery: opts.SkipQuery, SkipBody: opts.SkipBody, SkipJSON: opts.SkipJSON,
			})
			if runErr != nil {
				scanErrs++
				if errSample == "" {
					errSample = runErr.Error()
				}
			}
			for _, fnd := range res {
				fnd.FlowID = f.ID
				if a.scanner.Add(fnd) {
					found++
				}
			}
			scanned++
			a.setSiteScanProgress(&SiteScanProgress{
				Host: host, Done: scanned, Total: len(flows), Current: f.Method + " " + f.Path, Found: found,
			})
		}
		a.siteScanMu.Lock()
		stopped := a.siteScanStopped || ctx.Err() != nil
		a.siteScanMu.Unlock()
		a.emit("sitescan:done", SiteScanDone{Host: host, Scanned: scanned, Found: found, Stopped: stopped, Errors: scanErrs, ErrorSample: errSample})
	}()
	return nil
}

// SiteScanStatus returns the running site scan's progress, or nil, so a view
// opened mid-scan can show it.
func (a *App) SiteScanStatus() *SiteScanProgress {
	a.siteScanMu.Lock()
	defer a.siteScanMu.Unlock()
	if a.siteScanLast == nil {
		return nil
	}
	p := *a.siteScanLast
	return &p
}

func (a *App) setSiteScanProgress(p *SiteScanProgress) {
	a.siteScanMu.Lock()
	a.siteScanLast = p
	a.siteScanMu.Unlock()
	a.emit("sitescan:progress", *p)
}

// StopSiteScan stops a running site scan after the current request.
func (a *App) StopSiteScan() {
	a.siteScanMu.Lock()
	defer a.siteScanMu.Unlock()
	if a.siteScanCancel != nil {
		a.siteScanStopped = true
		a.siteScanCancel()
	}
}

func (a *App) emit(event string, data any) {
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, event, data)
	}
}
