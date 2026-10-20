package main

import (
	"strings"
	"testing"

	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/rules"
	"github.com/gorkemguler/kanca/internal/scanner"
)

func testApp() *App {
	return &App{store: history.New(0), scanner: scanner.New(), rules: rules.NewSet()}
}

func TestSetFindingStatusBinding(t *testing.T) {
	a := testApp()
	if err := a.SetFindingStatus(1, "confirmed"); err == nil {
		t.Fatal("SetFindingStatus accepted an unknown ID")
	}
	a.scanner.Add(scanner.Finding{Severity: scanner.Low, Title: "T", Host: "h", URL: "http://h/"})
	id := a.scanner.Findings()[0].ID
	if err := a.SetFindingStatus(id, "bogus"); err == nil {
		t.Fatal("SetFindingStatus accepted an invalid status")
	}
	if err := a.SetFindingStatus(id, "resolved"); err != nil {
		t.Fatalf("SetFindingStatus: %v", err)
	}
	if got := a.scanner.Findings()[0].Status; got != scanner.StatusResolved {
		t.Fatalf("status = %q", got)
	}
}

func TestAnnotateFlowBinding(t *testing.T) {
	a := testApp()
	if err := a.AnnotateFlow(9, "x", "red"); err == nil {
		t.Fatal("AnnotateFlow accepted an unknown ID")
	}
	a.store.Add(&proxy.Flow{ID: 9, Method: "GET", Host: "h", Path: "/"})
	if err := a.AnnotateFlow(9, "look", "red"); err != nil {
		t.Fatalf("AnnotateFlow: %v", err)
	}
	f, _ := a.store.Get(9)
	if f.Comment != "look" || f.Highlight != "red" {
		t.Fatalf("annotation lost: %+v", f)
	}
}

func TestJWTBindingsRoundTrip(t *testing.T) {
	a := testApp()
	tok, err := a.SignJWT(`{"typ":"JWT"}`, `{"sub":9007199254740993}`, "HS256", "s3cret")
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	dec, err := a.DecodeJWT(tok)
	if err != nil {
		t.Fatalf("DecodeJWT: %v", err)
	}
	if dec.Algorithm != "HS256" {
		t.Fatalf("decoded wrong: %+v", dec)
	}
	if !strings.Contains(dec.PayloadJSON, "9007199254740993") {
		t.Fatalf("64-bit claim lost precision: %s", dec.PayloadJSON)
	}
	ok, err := a.VerifyJWT(tok, "s3cret")
	if err != nil || !ok {
		t.Fatalf("VerifyJWT good = %v, %v", ok, err)
	}
	if ok, _ := a.VerifyJWT(tok, "wrong"); ok {
		t.Fatal("VerifyJWT accepted a wrong secret")
	}
	if _, err := a.DecodeJWT("garbage"); err == nil {
		t.Fatal("DecodeJWT accepted garbage")
	}
	if _, err := a.SignJWT("{bad", "{}", "HS256", "s"); err == nil {
		t.Fatal("SignJWT accepted bad header JSON")
	}
}

func TestDiffTextCapBinding(t *testing.T) {
	a := testApp()
	big := strings.Repeat("abcdefghij\n", 6000)
	res := a.DiffText(big, big+"x\n")
	if len(res.Lines) == 0 {
		t.Fatal("empty diff")
	}
	// Bounded: 4M cells max plus marker lines, never the full 6000+6000.
	if len(res.Lines) > 20000 {
		t.Fatalf("diff lines = %d, want bounded", len(res.Lines))
	}
}

func TestListHistoryHideStatusBinding(t *testing.T) {
	a := testApp()
	a.store.Add(&proxy.Flow{ID: 1, Method: "GET", Host: "h", Path: "/ok", StatusCode: 200})
	a.store.Add(&proxy.Flow{ID: 2, Method: "GET", Host: "h", Path: "/missing", StatusCode: 404})
	a.store.Add(&proxy.Flow{ID: 3, Method: "POST", Host: "h", Path: "/api", StatusCode: 201})
	all := a.ListHistory("", nil, false, nil)
	if len(all) != 3 {
		t.Fatalf("unfiltered = %d, want 3", len(all))
	}
	hidden := a.ListHistory("", nil, false, []int{404})
	if len(hidden) != 2 {
		t.Fatalf("hide-404 = %d, want 2", len(hidden))
	}
	for _, e := range hidden {
		if e.StatusCode == 404 {
			t.Fatalf("404 leaked: %+v", e)
		}
	}
	posts := a.ListHistory("", []string{"POST"}, false, nil)
	if len(posts) != 1 || posts[0].ID != 3 {
		t.Fatalf("method filter wrong: %+v", posts)
	}
}

func TestPauseStopIdleNoPanic(t *testing.T) {
	a := testApp()
	a.PauseIntruder(true) // no attack running: must be a no-op, not a panic
	a.PauseIntruder(false)
	a.StopActiveScan(123) // unknown flow: no-op
	a.StopIntruder()      // nothing running: no-op
}
