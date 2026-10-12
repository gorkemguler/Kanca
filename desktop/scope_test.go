package main

import "testing"

func TestScopeMatcher(t *testing.T) {
	a := &App{}
	// Disabled scope records everything (nil matcher).
	if a.scopeMatcher() != nil {
		t.Fatal("disabled scope should return nil matcher")
	}
	a.SetScope(ScopeConfig{Enabled: true, Hosts: []string{" Example.COM ", ""}})
	m := a.scopeMatcher()
	if m == nil {
		t.Fatal("enabled scope should return a matcher")
	}
	if !m("api.example.com") {
		t.Error("expected api.example.com in scope (normalised host)")
	}
	if m("other.org") {
		t.Error("other.org should be out of scope")
	}
}
