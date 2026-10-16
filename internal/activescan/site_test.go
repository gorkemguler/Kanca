package activescan

import (
	"testing"

	"github.com/gorkemguler/kanca/internal/proxy"
)

func flowOf(method, host, target, extra string) *proxy.Flow {
	raw := method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\n" + extra + "\r\n"
	return &proxy.Flow{Method: method, Scheme: "https", Host: host + ":443", StatusCode: 200, Request: proxy.Message{Raw: []byte(raw)}}
}

func TestPlanSitePicksParameterisedRequestsOncePerShape(t *testing.T) {
	const host = "shop.example"
	form := "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nemail=a%40b.com"
	flows := []*proxy.Flow{
		flowOf("GET", host, "/search?q=socks", ""),
		flowOf("GET", host, "/search?q=hats", ""), // same shape as the first
		flowOf("GET", host, "/search?q=hats&page=2", ""),
		flowOf("GET", host, "/about", ""),                 // nothing to inject into
		flowOf("GET", host, "/app.js?v=20250624", ""),     // cache buster on a static file
		flowOf("POST", host, "/api/contact", ""),          // state-changing; body set below
		flowOf("DELETE", host, "/api/item?id=3", ""),      // only with IncludeDelete
		flowOf("GET", "other.example", "/search?q=x", ""), // another host
	}
	flows[5].Request.Raw = []byte("POST /api/contact HTTP/1.1\r\nHost: " + host + "\r\n" + form)
	failed := flowOf("GET", host, "/broken?id=1", "")
	failed.Error, failed.StatusCode = "connection refused", 0
	flows = append(flows, failed)

	plan := PlanSite(flows, func(a string) bool { return a == host+":443" }, SiteOptions{})
	if len(plan.Safe) != 2 || plan.Safe[0] != flows[0] || plan.Safe[1] != flows[2] {
		t.Fatalf("safe = %d requests, want /search?q and /search?q&page once each", len(plan.Safe))
	}
	if len(plan.Unsafe) != 1 || plan.Unsafe[0] != flows[5] {
		t.Fatalf("unsafe = %d requests, want only the contact form", len(plan.Unsafe))
	}

	// The same path on another host is a separate request to probe.
	both := PlanSite(flows, func(string) bool { return true }, SiteOptions{})
	if len(both.Safe) != 3 {
		t.Fatalf("across hosts, safe = %d requests, want 3", len(both.Safe))
	}
}

func TestPlanSiteDeleteOptIn(t *testing.T) {
	const host = "shop.example"
	flows := []*proxy.Flow{
		flowOf("DELETE", host, "/api/item?id=3", ""),
	}
	off := PlanSite(flows, func(string) bool { return true }, SiteOptions{})
	if len(off.Safe)+len(off.Unsafe) != 0 {
		t.Fatalf("DELETE planned without opt-in: %+v", off)
	}
	on := PlanSite(flows, func(string) bool { return true }, SiteOptions{IncludeDelete: true})
	if len(on.Unsafe) != 1 {
		t.Fatalf("DELETE not planned with opt-in: %+v", on)
	}
	if len(on.Safe) != 0 {
		t.Fatalf("DELETE planned as safe: %+v", on)
	}
}

func TestPlanSiteSkipPoints(t *testing.T) {
	const host = "shop.example"
	form := "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nemail=a%40b.com"
	flows := []*proxy.Flow{
		flowOf("GET", host, "/search?q=socks", ""),
	}
	flows = append(flows, &proxy.Flow{Method: "POST", Scheme: "https", Host: host + ":443", StatusCode: 200,
		Request: proxy.Message{Raw: []byte("POST /api/contact HTTP/1.1\r\nHost: " + host + "\r\n" + form)}})
	skipQ := PlanSite(flows, func(string) bool { return true }, SiteOptions{SkipQuery: true})
	if len(skipQ.Safe) != 0 {
		t.Fatalf("query point planned despite SkipQuery: %+v", skipQ)
	}
	skipB := PlanSite(flows, func(string) bool { return true }, SiteOptions{SkipBody: true})
	if len(skipB.Safe) != 1 || len(skipB.Unsafe) != 0 {
		t.Fatalf("body skip wrong: safe=%d unsafe=%d", len(skipB.Safe), len(skipB.Unsafe))
	}
}
