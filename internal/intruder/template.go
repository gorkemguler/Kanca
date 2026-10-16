// Package intruder performs automated request generation ("fuzzing") by
// substituting payloads into marked positions of a request template and
// dispatching the results concurrently. It is meant for authorised testing of
// systems the operator is permitted to assess.
package intruder

import (
	"bytes"
)

// DefaultMarker flags payload positions in a template: every occurrence is
// one position, e.g. "id=FUZZ&q=FUZZ" has two. It is the same keyword
// convention ffuf, gobuster and wfuzz use, so wordlists and habits transfer
// over. Matching is a case-sensitive literal.
const DefaultMarker = "FUZZ"

// Template is a parsed request with N payload positions. Rebuilding it with a
// set of N values is cheap and allocation-light.
type Template struct {
	// segments has len(positions)+1 elements; the final request is
	// segments[0] + values[0] + segments[1] + values[1] + ... + segments[N].
	segments [][]byte
	// baseValues holds the original text found at each position.
	baseValues []string
}

// Positions reports how many payload positions the template defines.
func (t *Template) Positions() int { return len(t.baseValues) }

// BaseValues returns the original text at each position.
func (t *Template) BaseValues() []string {
	out := make([]string, len(t.baseValues))
	copy(out, t.baseValues)
	return out
}

// Parse splits raw on every marker occurrence. Each occurrence is one payload
// position whose base value is empty (the keyword replaces the original
// value, ffuf-style). A template without markers has no positions
// (Positions()==0), which callers should reject.
func Parse(raw []byte, marker string) (*Template, error) {
	if marker == "" {
		marker = DefaultMarker
	}
	parts := bytes.Split(raw, []byte(marker))
	t := &Template{}
	for i, p := range parts {
		t.segments = append(t.segments, append([]byte(nil), p...))
		if i < len(parts)-1 {
			t.baseValues = append(t.baseValues, "")
		}
	}
	return t, nil
}

// Render substitutes values into the template. len(values) must equal
// Positions(); extra values are ignored and missing ones fall back to the
// base value.
func (t *Template) Render(values []string) []byte {
	var b bytes.Buffer
	for i, seg := range t.segments {
		b.Write(seg)
		if i < len(t.baseValues) {
			if i < len(values) {
				b.WriteString(values[i])
			} else {
				b.WriteString(t.baseValues[i])
			}
		}
	}
	return b.Bytes()
}
