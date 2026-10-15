package main

import (
	"strings"
	"testing"
)

func TestTargetsAreSeparateFromRecording(t *testing.T) {
	a := &App{}
	if a.recordMatcher() != nil || a.targetMatcher() != nil {
		t.Fatal("with nothing set, everything is recorded and nothing may be tested")
	}
	if err := a.checkTarget("example.com:443"); err == nil {
		t.Fatal("scanning must need a target")
	}

	// Targets without "record only targets": still record everything, but only
	// targets may be tested.
	a.SetScope(ScopeConfig{Hosts: []string{"https://Example.COM/app", ""}})
	if a.recordMatcher() != nil {
		t.Fatal("recording should stay unfiltered")
	}
	if err := a.checkTarget("api.example.com:443"); err != nil {
		t.Fatalf("subdomain of a target should be testable: %v", err)
	}
	if err := a.checkTarget("other.org:443"); err == nil || !strings.Contains(err.Error(), "not one of your targets") {
		t.Fatalf("other.org should be refused, got %v", err)
	}

	a.SetScope(ScopeConfig{Enabled: true, Hosts: []string{"example.com"}})
	if m := a.recordMatcher(); m == nil || !m("api.example.com") || m("other.org") {
		t.Fatal("record-only-targets should filter recording to targets")
	}

	if got := a.AddTarget("https://shop.test:8443/x").Hosts; len(got) != 2 || got[1] != "shop.test" {
		t.Fatalf("AddTarget = %q", got)
	}
}
