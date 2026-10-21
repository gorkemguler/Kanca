package activescan

import (
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// SitePlan is what a site scan would probe on one host: the captured requests
// that have parameters to inject into (with Plus, any request), one per method,
// path and parameter set, without static files.
type SitePlan struct {
	// Safe holds GET and HEAD requests, which only read.
	Safe []*proxy.Flow
	// Unsafe holds requests that change state (POST, PUT, PATCH and, when
	// opted in, DELETE). Probing one repeats its action for every payload
	// (e.g. sends a contact form again), so callers include them only when
	// asked.
	Unsafe []*proxy.Flow
}

// SiteOptions tunes PlanSite.
type SiteOptions struct {
	// IncludeDelete plans DELETE requests (as unsafe). Off by default: a
	// probe never deletes anything unless the operator explicitly asks.
	IncludeDelete bool
	// SkipQuery/SkipBody/SkipJSON drop those insertion points from planning.
	SkipQuery bool
	SkipBody  bool
	SkipJSON  bool
	// Plus also plans requests without parameters, for the request- and
	// host-level Plus checks.
	Plus bool
}

// staticExt are file types whose parameters are cache busters, not input.
var staticExt = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true, ".png": true, ".jpg": true,
	".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true, ".avif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp4": true, ".webm": true, ".mp3": true, ".pdf": true,
}

// PlanSite picks the requests worth probing among flows whose authority
// (host:port, as flows record it) include accepts, oldest first.
func PlanSite(flows []*proxy.Flow, include func(authority string) bool, opts SiteOptions) SitePlan {
	var plan SitePlan
	seen := map[string]bool{}
	for _, f := range flows {
		if !include(f.Host) || f.Error != "" || f.StatusCode == 0 {
			continue
		}
		method := strings.ToUpper(f.Method)
		if method == http.MethodOptions || method == http.MethodConnect || method == http.MethodTrace {
			continue
		}
		if method == http.MethodDelete && !opts.IncludeDelete {
			continue
		}
		req, err := proxy.ParseRawRequest(f.Request.Raw, f.Scheme, f.Host)
		if err != nil || staticExt[strings.ToLower(path.Ext(req.URL.Path))] {
			continue
		}
		points := filterPoints(collectPoints(req, readBody(req), 50), opts.SkipQuery, opts.SkipBody, opts.SkipJSON)
		if len(points) == 0 && !opts.Plus {
			continue
		}
		names := make([]string, 0, len(points))
		for _, p := range points {
			names = append(names, p.where+":"+p.label)
		}
		sort.Strings(names)
		key := strings.ToLower(f.Host) + " " + method + " " + req.URL.Path + " " + strings.Join(names, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		if method == http.MethodGet || method == http.MethodHead {
			plan.Safe = append(plan.Safe, f)
		} else {
			plan.Unsafe = append(plan.Unsafe, f)
		}
	}
	return plan
}
