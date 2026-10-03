package intruder

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseAndRender(t *testing.T) {
	raw := []byte("GET /?id=§1§&q=§a§ HTTP/1.1\r\nHost: x\r\n\r\n")
	tmpl, err := Parse(raw, DefaultMarker)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tmpl.Positions() != 2 {
		t.Fatalf("positions = %d", tmpl.Positions())
	}
	if bv := tmpl.BaseValues(); bv[0] != "1" || bv[1] != "a" {
		t.Fatalf("base values = %v", bv)
	}
	out := string(tmpl.Render([]string{"99", "z"}))
	if !strings.Contains(out, "id=99&q=z") {
		t.Fatalf("render = %q", out)
	}
}

func TestParseUnbalanced(t *testing.T) {
	if _, err := Parse([]byte("id=§1"), DefaultMarker); err == nil {
		t.Fatal("expected error on unbalanced markers")
	}
}

func TestPlanCounts(t *testing.T) {
	raw := []byte("GET /?a=§1§&b=§2§ HTTP/1.1\r\nHost: x\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	set := []string{"p", "q", "r"} // 3 payloads

	cases := []struct {
		typ  AttackType
		sets [][]string
		want int
	}{
		{Sniper, [][]string{set}, 2 * 3},                        // positions * payloads
		{BatteringRam, [][]string{set}, 3},                      // payloads
		{Pitchfork, [][]string{{"a", "b"}, {"c", "d", "e"}}, 2}, // min length
		{ClusterBomb, [][]string{{"a", "b"}, {"c", "d", "e"}}, 6},
	}
	for _, tc := range cases {
		a, err := NewAttack(tmpl, Config{Type: tc.typ, Payloads: tc.sets, Scheme: "http", Host: "x"})
		if err != nil {
			t.Fatalf("%s: new: %v", tc.typ, err)
		}
		if got := a.Count(); got != tc.want {
			t.Fatalf("%s: count = %d, want %d", tc.typ, got, tc.want)
		}
	}
}

func TestAttackRunsAgainstServer(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		id := r.URL.Query().Get("id")
		if id == "admin" {
			fmt.Fprint(w, "SECRET-FLAG")
			return
		}
		fmt.Fprint(w, "denied")
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)

	raw := []byte("GET /?id=§guest§ HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	a, err := NewAttack(tmpl, Config{
		Type:        Sniper,
		Scheme:      "http",
		Host:        u.Host,
		Payloads:    [][]string{{"user", "admin", "guest"}},
		GrepMatch:   "SECRET-FLAG",
		Concurrency: 4,
	})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}

	var matched int
	for res := range a.Run(context.Background()) {
		if res.Error != "" {
			t.Fatalf("request error: %s", res.Error)
		}
		if res.Matched {
			matched++
			if res.Payloads[0] != "admin" {
				t.Fatalf("unexpected match payload %v", res.Payloads)
			}
		}
	}
	if matched != 1 {
		t.Fatalf("matched = %d, want 1", matched)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("backend hits = %d, want 3", got)
	}
}
