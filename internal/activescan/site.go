package activescan

import (
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// SitePlan is what a site scan would probe on one host: the captured requests
// that have parameters to inject into, one per method, path and parameter set,
// without static files.
type SitePlan struct {
	// Safe holds GET and HEAD requests, which only read.
	Safe []*proxy.Flow
	// Unsafe holds requests that change state (POST, PUT, PATCH). Probing one
	// repeats its action for every payload (e.g. sends a contact form again),
	// so callers include them only when asked. DELETE is never planned.
	Unsafe []*proxy.Flow
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
func PlanSite(flows []*proxy.Flow, include func(authority string) bool) SitePlan {
	var plan SitePlan
	seen := map[string]bool{}
	for _, f := range flows {
		if !include(f.Host) || f.Error != "" || f.StatusCode == 0 {
			continue
		}
		method := strings.ToUpper(f.Method)
		if method == http.MethodDelete || method == http.MethodOptions || method == http.MethodConnect || method == http.MethodTrace {
			continue
		}
		req, err := proxy.ParseRawRequest(f.Request.Raw, f.Scheme, f.Host)
		if err != nil || staticExt[strings.ToLower(path.Ext(req.URL.Path))] {
			continue
		}
		points := collectPoints(req, readBody(req), 50)
		if len(points) == 0 {
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
