package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
)

func TestScanSiteProbesTargetGETsOnly(t *testing.T) {
	var posts atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		fmt.Fprintf(w, "<p>results for %s</p>", r.URL.Query().Get("q"))
	}))
	defer backend.Close()
	host := strings.TrimPrefix(backend.URL, "http://")

	a := &App{store: history.New(0), scanner: scanner.New()}
	send := proxy.NewSender(proxy.SenderConfig{})
	for _, raw := range []string{
		"GET /search?q=socks HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"POST /contact HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nmsg=hey",
	} {
		a.store.Add(send.Send(context.Background(), []byte(raw), "http", host))
	}
	posts.Store(0)

	if _, err := a.PlanSiteScan(host); err == nil {
		t.Fatal("a host that isn't a target must not be scanned")
	}
	if _, err := a.PlanSiteScan(""); err == nil {
		t.Fatal("scanning all targets needs targets")
	}
	a.AddTarget(host)
	plan, err := a.PlanSiteScan(host)
	if err != nil || plan.Safe != 1 || plan.Unsafe != 1 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if all, err := a.PlanSiteScan(""); err != nil || all.Safe != 1 || all.Unsafe != 1 {
		t.Fatalf("plan for all targets = %+v, %v", all, err)
	}

	if err := a.ScanSite("", false, false); err != nil {
		t.Fatal(err)
	}
	if err := a.ScanSite(host, false, false); err == nil {
		t.Fatal("a second scan should wait for the first")
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		a.siteScanMu.Lock()
		running := a.siteScanCancel != nil
		a.siteScanMu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("site scan did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}

	var reflected bool
	for _, f := range a.scanner.Findings() {
		reflected = reflected || strings.Contains(f.Title, "Reflected input in q")
	}
	if !reflected {
		t.Fatalf("site scan should find the reflection, got %+v", a.scanner.Findings())
	}
	if n := posts.Load(); n != 0 {
		t.Fatalf("the contact form was submitted %d times without asking", n)
	}
}
