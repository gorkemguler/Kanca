package intruder

import (
	"reflect"
	"testing"
)

func TestNumberRange(t *testing.T) {
	spec := PayloadSpec{Numbers: &NumberRange{From: 1, To: 5, Step: 2}}
	if got := spec.Generate(); !reflect.DeepEqual(got, []string{"1", "3", "5"}) {
		t.Fatalf("range = %v", got)
	}
}

func TestNumberRangeDescendingAndPad(t *testing.T) {
	spec := PayloadSpec{Numbers: &NumberRange{From: 3, To: 1, Step: -1, Pad: 3}}
	if got := spec.Generate(); !reflect.DeepEqual(got, []string{"003", "002", "001"}) {
		t.Fatalf("descending padded = %v", got)
	}
}

func TestNumberRangeEmpty(t *testing.T) {
	// From > To with a positive step yields nothing.
	spec := PayloadSpec{Numbers: &NumberRange{From: 5, To: 1, Step: 1}}
	if got := spec.Generate(); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestListWithProcessors(t *testing.T) {
	spec := PayloadSpec{
		List:       []string{"Hello World", "AB"},
		Processors: []Processor{ProcLower, ProcURLEncode},
	}
	got := spec.Generate()
	// "Hello World" -> lower "hello world" -> url "hello+world"
	if got[0] != "hello+world" {
		t.Fatalf("processor chain wrong: %q", got[0])
	}
	if got[1] != "ab" {
		t.Fatalf("second value: %q", got[1])
	}
}

func TestProcessorsBase64AndHashes(t *testing.T) {
	if got := ApplyProcessors("abc", []Processor{ProcBase64}); got != "YWJj" {
		t.Fatalf("base64 = %q", got)
	}
	if got := ApplyProcessors("abc", []Processor{ProcSHA256}); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256 = %q", got)
	}
	if got := ApplyProcessors("abc", []Processor{ProcMD5}); got != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("md5 = %q", got)
	}
	// Unknown/none processor is identity.
	if got := ApplyProcessors("abc", []Processor{ProcNone}); got != "abc" {
		t.Fatalf("none = %q", got)
	}
}

func TestGenerateIntegratesWithAttack(t *testing.T) {
	// A generated numeric set should drive an attack's plan count.
	raw := []byte("GET /?id=§1§ HTTP/1.1\r\nHost: x\r\n\r\n")
	tmpl, _ := Parse(raw, DefaultMarker)
	payloads := PayloadSpec{Numbers: &NumberRange{From: 1, To: 10}}.Generate()
	a, err := NewAttack(tmpl, Config{Type: Sniper, Scheme: "http", Host: "x", Payloads: [][]string{payloads}})
	if err != nil {
		t.Fatalf("new attack: %v", err)
	}
	if a.Count() != 10 {
		t.Fatalf("count = %d, want 10", a.Count())
	}
}
