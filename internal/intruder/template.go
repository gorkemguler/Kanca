// Package intruder performs automated request generation ("fuzzing") by
// substituting payloads into marked positions of a request template and
// dispatching the results concurrently. It is meant for authorised testing of
// systems the operator is permitted to assess.
package intruder

import (
	"bytes"
	"errors"
)

// DefaultMarker delimits payload positions in a template. A position is the
// text between a pair of markers, e.g. "id=§1§" marks the position whose base
// value is "1". The section sign is the same convention Burp uses.
const DefaultMarker = "§"

// legacyMarker is the keyword syntax earlier Kanca releases wrote. It is
// accepted only when a template carries no DefaultMarker, so existing saved
// requests keep working; it marks a position but has no base value to restore.
const legacyMarker = "FUZZ"

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

// Parse splits raw around marker pairs. An odd number of markers is an error.
// When no markers are present the whole request is treated as a single
// position-free template (Positions()==0), which callers should reject.
func Parse(raw []byte, marker string) (*Template, error) {
	if marker == "" {
		marker = DefaultMarker
	}
	m := []byte(marker)
	if marker == legacyMarker {
		// An explicit FUZZ marker keeps the keyword semantics old callers
		// configured; it is not a pair delimiter.
		return parseKeyword(raw, legacyMarker), nil
	}
	if marker == DefaultMarker && !bytes.Contains(raw, m) && bytes.Contains(raw, []byte(legacyMarker)) {
		return parseKeyword(raw, legacyMarker), nil
	}
	t := &Template{}
	rest := raw
	open := true // next marker opens a position
	var cur bytes.Buffer
	for {
		idx := bytes.Index(rest, m)
		if idx < 0 {
			cur.Write(rest)
			break
		}
		if open {
			// Everything up to the marker is literal segment text.
			cur.Write(rest[:idx])
			t.segments = append(t.segments, append([]byte(nil), cur.Bytes()...))
			cur.Reset()
		} else {
			// Everything up to the marker is the position's base value.
			t.baseValues = append(t.baseValues, string(rest[:idx]))
		}
		open = !open
		rest = rest[idx+len(m):]
	}
	if !open {
		// We opened a position but never closed it.
		return nil, errors.New("intruder: unbalanced payload markers")
	}
	// The trailing literal collected in cur is the final segment.
	t.segments = append(t.segments, append([]byte(nil), cur.Bytes()...))
	return t, nil
}

// parseKeyword implements the legacy FUZZ syntax: every keyword occurrence is
// a position with an empty base value.
func parseKeyword(raw []byte, marker string) *Template {
	parts := bytes.Split(raw, []byte(marker))
	t := &Template{}
	for i, p := range parts {
		t.segments = append(t.segments, append([]byte(nil), p...))
		if i < len(parts)-1 {
			t.baseValues = append(t.baseValues, "")
		}
	}
	return t
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
