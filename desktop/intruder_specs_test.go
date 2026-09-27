package main

import (
	"testing"

	"github.com/gorkemguler/mimlec/internal/intruder"
)

func TestResolvePayloadsExpandsSpecs(t *testing.T) {
	cfg := IntruderConfig{
		Specs: []intruder.PayloadSpec{
			{Numbers: &intruder.NumberRange{From: 1, To: 3}},
			{List: []string{"a", "b"}, Processors: []intruder.Processor{intruder.ProcUpper}},
		},
	}
	got := cfg.resolvePayloads()
	if len(got) != 2 {
		t.Fatalf("sets = %d", len(got))
	}
	if len(got[0]) != 3 || got[0][2] != "3" {
		t.Fatalf("numeric set = %v", got[0])
	}
	if got[1][0] != "A" || got[1][1] != "B" {
		t.Fatalf("processed list = %v", got[1])
	}
}

func TestResolvePayloadsFallsBackToLiteral(t *testing.T) {
	cfg := IntruderConfig{Payloads: [][]string{{"x", "y"}}}
	got := cfg.resolvePayloads()
	if len(got) != 1 || got[0][1] != "y" {
		t.Fatalf("literal fallback = %v", got)
	}
}
