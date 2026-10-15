package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/gorkemguler/kanca/internal/activescan"
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
}

// PlanSiteScan counts the captured requests a scan of host (host:port, as the
// site map shows it) would probe. host must be a target.
func (a *App) PlanSiteScan(host string) (SiteScanPlan, error) {
	if err := a.checkTarget(host); err != nil {
		return SiteScanPlan{Host: host}, err
	}
	p := activescan.PlanSite(a.store.Snapshot(), host)
	return SiteScanPlan{Host: host, Safe: len(p.Safe), Unsafe: len(p.Unsafe)}, nil
}

// ScanSite actively scans every captured request with parameters on host, one
// at a time in the background, adding what it finds to Findings. Forms and
// other state-changing requests are included only with includeUnsafe, since
// each probe repeats them. Progress arrives as sitescan:progress events, then
// sitescan:done.
func (a *App) ScanSite(host string, includeUnsafe, aggressive bool) error {
	if err := a.checkTarget(host); err != nil {
		return err
	}
	plan := activescan.PlanSite(a.store.Snapshot(), host)
	flows := plan.Safe
	if includeUnsafe {
		flows = append(flows, plan.Unsafe...)
	}
	if len(flows) == 0 {
		return fmt.Errorf("Kanca hasn't captured any requests with parameters on %s yet: browse the site through Kanca first", hostOnlyApp(host))
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.siteScanMu.Lock()
	if a.siteScanCancel != nil {
		a.siteScanMu.Unlock()
		cancel()
		return errors.New("a site scan is already running")
	}
	a.siteScanCancel = cancel
	a.siteScanMu.Unlock()

	go func() {
		defer func() {
			a.siteScanMu.Lock()
			a.siteScanCancel, a.siteScanLast = nil, nil
			a.siteScanMu.Unlock()
			cancel()
		}()
		scanned, found := 0, 0
		for _, f := range flows {
			if ctx.Err() != nil {
				break
			}
			a.setSiteScanProgress(&SiteScanProgress{
				Host: host, Done: scanned, Total: len(flows), Current: f.Method + " " + f.Path, Found: found,
			})
			res, _ := activescan.Run(ctx, activescan.Config{
				Scheme: f.Scheme, Host: f.Host, Raw: f.Request.Raw,
				InsecureUpstream: true, Aggressive: aggressive,
			})
			for _, fnd := range res {
				fnd.FlowID = f.ID
				if a.scanner.Add(fnd) {
					found++
				}
			}
			scanned++
		}
		a.emit("sitescan:done", SiteScanDone{Host: host, Scanned: scanned, Found: found, Stopped: ctx.Err() != nil})
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
		a.siteScanCancel()
	}
}

func (a *App) emit(event string, data any) {
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, event, data)
	}
}
