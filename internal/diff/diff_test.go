package diff

import (
	"strconv"
	"strings"
	"testing"
)

func opsString(r Result) string {
	s := ""
	for _, l := range r.Lines {
		switch l.Op {
		case Equal:
			s += "="
		case Insert:
			s += "+"
		case Delete:
			s += "-"
		}
	}
	return s
}

func TestIdentical(t *testing.T) {
	r := Lines("a\nb\nc", "a\nb\nc")
	if opsString(r) != "===" {
		t.Fatalf("ops = %q", opsString(r))
	}
	if r.Stats.Added != 0 || r.Stats.Removed != 0 {
		t.Fatalf("stats = %+v", r.Stats)
	}
}

func TestInsertAndDelete(t *testing.T) {
	// a,b,c -> a,x,c : b removed, x added.
	r := Lines("a\nb\nc", "a\nx\nc")
	if r.Stats.Added != 1 || r.Stats.Removed != 1 {
		t.Fatalf("stats = %+v (ops %s)", r.Stats, opsString(r))
	}
	// The equal anchors a and c must be preserved.
	if r.Lines[0].Op != Equal || r.Lines[0].Text != "a" {
		t.Fatalf("first line = %+v", r.Lines[0])
	}
	last := r.Lines[len(r.Lines)-1]
	if last.Op != Equal || last.Text != "c" {
		t.Fatalf("last line = %+v", last)
	}
}

func TestCRLFNormalised(t *testing.T) {
	// Same content, different line endings -> no differences.
	r := Lines("a\r\nb\r\n", "a\nb\n")
	if r.Stats.Added != 0 || r.Stats.Removed != 0 {
		t.Fatalf("CRLF should normalise; stats = %+v", r.Stats)
	}
}

func TestAppendedLines(t *testing.T) {
	r := Lines("a\nb", "a\nb\nc\nd")
	if r.Stats.Added != 2 || r.Stats.Removed != 0 {
		t.Fatalf("stats = %+v", r.Stats)
	}
	// Line numbers should be assigned on the correct side.
	tail := r.Lines[len(r.Lines)-1]
	if tail.Op != Insert || tail.BLine != 4 || tail.ALine != 0 {
		t.Fatalf("appended line = %+v", tail)
	}
}

func TestHugeInputsAreClipped(t *testing.T) {
	var sbA, sbB strings.Builder
	for i := 0; i < 6000; i++ {
		sbA.WriteString("line alpha " + strconv.Itoa(i) + "\n")
		sbB.WriteString("line beta " + strconv.Itoa(i) + "\n")
	}
	res := Lines(sbA.String(), sbB.String())
	if len(res.Lines) == 0 {
		t.Fatal("empty diff for huge inputs")
	}
	last := res.Lines[len(res.Lines)-1]
	if last.Text != truncatedMarker {
		t.Fatalf("last line = %q, want truncation marker", last.Text)
	}
}
