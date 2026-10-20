package intruder

import (
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseAndRender(t *testing.T) {
	raw := []byte("GET /?id=§1§&q=§two§ HTTP/1.1\r\nHost: x\r\n\r\n")
	tmpl, err := Parse(raw, DefaultMarker)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tmpl.Positions() != 2 {
		t.Fatalf("positions = %d", tmpl.Positions())
	}
	if got := tmpl.BaseValues(); len(got) != 2 || got[0] != "1" || got[1] != "two" {
		t.Fatalf("base values = %v, want [1 two]", got)
	}
	out := string(tmpl.Render([]string{"99", "z"}))
	if !strings.Contains(out, "id=99&q=z") {
		t.Fatalf("render = %q", out)
	}
	// Missing values fall back to the captured base value.
	if out := string(tmpl.Render([]string{"99"})); !strings.Contains(out, "id=99&q=two") {
		t.Fatalf("fallback render = %q", out)
	}
}

func TestParseSinglePairIsOnePosition(t *testing.T) {
	tmpl, err := Parse([]byte("id=§1§"), DefaultMarker)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tmpl.Positions() != 1 {
		t.Fatalf("positions = %d, want 1", tmpl.Positions())
	}
	if bv := tmpl.BaseValues(); len(bv) != 1 || bv[0] != "1" {
		t.Fatalf("base values = %v, want [1]", bv)
	}
}

func TestParseRejectsUnbalancedMarkers(t *testing.T) {
	if _, err := Parse([]byte("id=§1 HTTP/1.1"), DefaultMarker); err == nil {
		t.Fatal("Parse accepted an unclosed marker")
	}
	// An unbalanced § must not fall through to the FUZZ syntax.
	if _, err := Parse([]byte("id=§1&q=FUZZ HTTP/1.1"), DefaultMarker); err == nil {
		t.Fatal("Parse accepted an unclosed marker alongside FUZZ")
	}
}

func TestParseKeepsLegacyFUZZKeyword(t *testing.T) {
	tmpl, err := Parse([]byte("GET /?id=FUZZ&q=FUZZ HTTP/1.1"), DefaultMarker)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tmpl.Positions() != 2 {
		t.Fatalf("positions = %d, want 2", tmpl.Positions())
	}
	if got := tmpl.BaseValues(); len(got) != 2 || got[0] != "" || got[1] != "" {
		t.Fatalf("legacy base values = %v, want empty", got)
	}
	if out := string(tmpl.Render([]string{"a", "b"})); out != "GET /?id=a&q=b HTTP/1.1" {
		t.Fatalf("legacy render = %q", out)
	}
	// An explicit FUZZ marker is the legacy keyword syntax, not a pair.
	if legacy, err := Parse([]byte("id=FUZZ&q=FUZZ"), "FUZZ"); err != nil || legacy.Positions() != 2 {
		t.Fatalf("explicit FUZZ marker: positions=%d err=%v", legacy.Positions(), err)
	}
	// A custom marker is explicit: FUZZ stays literal text.
	if other, err := Parse([]byte("id=FUZZ"), "%%"); err != nil || other.Positions() != 0 {
		t.Fatalf("custom marker parsed FUZZ: positions=%d err=%v", other.Positions(), err)
	}
}

func TestSniperKeepsOtherPositionsAtBase(t *testing.T) {
	raw := []byte("GET /?a=§A§&b=§B§ HTTP/1.1\r\nHost: x\r\n\r\n")
	tmpl, err := Parse(raw, DefaultMarker)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	a, err := NewAttack(tmpl, Config{
		Type:     Sniper,
		Payloads: [][]string{{"x"}},
		Scheme:   "http",
		Host:     "x",
	})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}
	jobs := a.plan()
	if len(jobs) != 2 {
		t.Fatalf("jobs = %d, want 2", len(jobs))
	}
	if got := string(tmpl.Render(jobs[0].values)); !strings.Contains(got, "a=x&b=B") {
		t.Fatalf("first job = %q, want sibling base value preserved", got)
	}
	if got := string(tmpl.Render(jobs[1].values)); !strings.Contains(got, "a=A&b=x") {
		t.Fatalf("second job = %q, want sibling base value preserved", got)
	}
}

func TestParseWithoutMarkerHasNoPositions(t *testing.T) {
	tmpl, err := Parse([]byte("GET /?id=1 HTTP/1.1\r\nHost: x\r\n\r\n"), DefaultMarker)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tmpl.Positions() != 0 {
		t.Fatalf("positions = %d, want 0", tmpl.Positions())
	}
}

func TestPlanCounts(t *testing.T) {
	raw := []byte("GET /?a=§1§&b=§1§ HTTP/1.1\r\nHost: x\r\n\r\n")
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

	raw := []byte("GET /?id=§1§ HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
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

func TestGrepMatchLooksInsideCompressedResponses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		body := strings.Repeat("<li>row</li>", 100) + "denied"
		if r.URL.Query().Get("id") == "admin" {
			body = strings.Repeat("<li>row</li>", 100) + "SECRET-FLAG"
		}
		fmt.Fprint(zw, body)
		zw.Close()
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	tmpl, _ := Parse([]byte("GET /?id=§1§ HTTP/1.1\r\nHost: "+u.Host+"\r\nAccept-Encoding: gzip, br\r\n\r\n"), DefaultMarker)
	a, err := NewAttack(tmpl, Config{Type: Sniper, Scheme: "http", Host: u.Host,
		Payloads: [][]string{{"user", "admin"}}, GrepMatch: "SECRET-FLAG", Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	var matched []string
	for res := range a.Run(context.Background()) {
		if res.Matched {
			matched = append(matched, res.Payloads[0])
		}
	}
	if len(matched) != 1 || matched[0] != "admin" {
		t.Fatalf("grep should match inside gzip responses, matched %v", matched)
	}
}

func TestClusterBombCapped(t *testing.T) {
	raw := []byte("GET /?a=§1§&b=§1§&c=§1§ HTTP/1.1\r\nHost: x\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	big := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		big = append(big, fmt.Sprintf("p%d", i))
	}
	a, err := NewAttack(tmpl, Config{Type: ClusterBomb, Payloads: [][]string{big, big, big}, Scheme: "http", Host: "x"})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}
	if got := a.Count(); got != MaxPlannedRequests {
		t.Fatalf("count = %d, want cap %d", got, MaxPlannedRequests)
	}
	if !a.Truncated() {
		t.Fatal("Truncated() = false, want true for a 27M combination space")
	}
	// Every planned job must carry one value per position (full arity).
	for _, j := range a.plan() {
		if len(j.values) != 3 {
			t.Fatalf("job has %d values, want 3 (full arity)", len(j.values))
		}
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)

	raw := []byte("GET /?id=§1§ HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	payloads := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		payloads = append(payloads, fmt.Sprintf("v%d", i))
	}
	a, err := NewAttack(tmpl, Config{Type: Sniper, Scheme: "http", Host: u.Host, Payloads: [][]string{payloads}, Concurrency: 2})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the first job is planned
	n := 0
	for range a.Run(ctx) {
		n++
		if n > 4 {
			t.Fatalf("run kept dispatching after cancel: %d results", n)
		}
	}
}

func TestExtractGrepHarvestsFirstGroup(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `session abcdef1234567890 ok`)
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	raw := []byte("GET /?id=§1§ HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	a, err := NewAttack(tmpl, Config{Type: Sniper, Scheme: "http", Host: u.Host, Payloads: [][]string{{"1"}}, ExtractGrep: `session ([a-z0-9]+)`})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}
	n := 0
	for res := range a.Run(context.Background()) {
		n++
		if res.Extracted != "abcdef1234567890" {
			t.Fatalf("extracted = %q, want the captured token", res.Extracted)
		}
	}
	if n != 1 {
		t.Fatalf("results = %d, want 1", n)
	}
}

func TestExtractGrepCapsGreedyMatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "prefix "+strings.Repeat("y", 500)+" suffix")
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	raw := []byte("GET /?a=§1§ HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	a, err := NewAttack(tmpl, Config{Type: Sniper, Scheme: "http", Host: u.Host, Payloads: [][]string{{"1"}}, ExtractGrep: `prefix (.+) suffix`})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}
	for res := range a.Run(context.Background()) {
		if len(res.Extracted) != maxExtractLen {
			t.Fatalf("extracted len = %d, want cap %d", len(res.Extracted), maxExtractLen)
		}
	}
}

func TestPauseFreezesDispatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Millisecond)
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	raw := []byte("GET /?id=§1§ HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	payloads := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		payloads = append(payloads, fmt.Sprintf("v%d", i))
	}
	a, err := NewAttack(tmpl, Config{Type: Sniper, Scheme: "http", Host: u.Host, Payloads: [][]string{payloads}, Concurrency: 2})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.SetPaused(true)
	if !a.Paused() {
		t.Fatal("Paused() = false after SetPaused(true)")
	}
	ch := a.Run(ctx)
	// While paused, (almost) nothing may dispatch: allow in-flight slack.
	time.Sleep(120 * time.Millisecond)
	select {
	case <-ch:
		t.Fatal("Run dispatched while paused")
	default:
	}
	a.SetPaused(false)
	n := 0
	done := make(chan struct{})
	go func() {
		for range ch {
			n++
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not finish after resume")
	}
	if n != 60 {
		t.Fatalf("results = %d, want 60 after resume", n)
	}
}

func TestDelaySlowsDispatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	raw := []byte("GET /?id=§1§ HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	payloads := []string{"a", "b", "c", "d"}
	a, err := NewAttack(tmpl, Config{Type: Sniper, Scheme: "http", Host: u.Host, Payloads: [][]string{payloads}, Concurrency: 4, DelayMs: 60})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}
	start := time.Now()
	n := 0
	for range a.Run(context.Background()) {
		n++
	}
	// 4 dispatches with a 60ms pre-delay each need ~240ms of pacing.
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("4 delayed dispatches took %v, want >= 150ms", elapsed)
	}
	if n != 4 {
		t.Fatalf("results = %d, want 4", n)
	}
}
