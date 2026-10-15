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
		flowOf("DELETE", host, "/api/item?id=3", ""),      // never probed
		flowOf("GET", "other.example", "/search?q=x", ""), // another host
	}
	flows[5].Request.Raw = []byte("POST /api/contact HTTP/1.1\r\nHost: " + host + "\r\n" + form)
	failed := flowOf("GET", host, "/broken?id=1", "")
	failed.Error, failed.StatusCode = "connection refused", 0
	flows = append(flows, failed)

	plan := PlanSite(flows, host+":443")
	if len(plan.Safe) != 2 || plan.Safe[0] != flows[0] || plan.Safe[1] != flows[2] {
		t.Fatalf("safe = %d requests, want /search?q and /search?q&page once each", len(plan.Safe))
	}
	if len(plan.Unsafe) != 1 || plan.Unsafe[0] != flows[5] {
		t.Fatalf("unsafe = %d requests, want only the contact form", len(plan.Unsafe))
	}
}
