// Package diff produces a line-oriented comparison of two texts using a
// longest-common-subsequence backtrace. It is used to compare two responses
// (e.g. successive repeater sends) so differences stand out.
package diff

import "strings"

// Op is the kind of change a line represents.
type Op string

const (
	Equal  Op = "equal"
	Insert Op = "insert" // present only in B
	Delete Op = "delete" // present only in A
)

// Line is one line of the diff, tagged with how it relates to the two inputs.
// ALine/BLine are 1-based line numbers, or 0 when the line is absent on that
// side.
type Line struct {
	Op    Op     `json:"op"`
	Text  string `json:"text"`
	ALine int    `json:"aLine"`
	BLine int    `json:"bLine"`
}

// Stats summarises a diff.
type Stats struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
}

// Result is the full diff of two texts.
type Result struct {
	Lines []Line `json:"lines"`
	Stats Stats  `json:"stats"`
}

// Bounds for Lines: the LCS table costs O(n*m) memory, so inputs are capped
// before the table is built. Diffing truncated prefixes is still useful for
// spotting response differences, and the marker line says so.
const (
	maxDiffBytes = 2 << 20 // per input
	maxDiffCells = 4_000_000
)

const truncatedMarker = "[... diff truncated: input exceeds safe comparison size ...]"

// Lines computes the line diff between a and b. Inputs are split on "\n" with
// a trailing "\r" trimmed so CRLF and LF texts compare cleanly.
func Lines(a, b string) Result {
	a = cutToLineBoundary(a, maxDiffBytes)
	b = cutToLineBoundary(b, maxDiffBytes)
	as := splitLines(a)
	bs := splitLines(b)

	if clipped := clipToCells(&as, &bs); clipped {
		as = append(as, truncatedMarker)
		bs = append(bs, truncatedMarker)
	}

	// LCS length table.
	n, m := len(as), len(bs)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if as[i] == bs[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var out []Line
	var stats Stats
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case as[i] == bs[j]:
			out = append(out, Line{Op: Equal, Text: as[i], ALine: i + 1, BLine: j + 1})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, Line{Op: Delete, Text: as[i], ALine: i + 1})
			stats.Removed++
			i++
		default:
			out = append(out, Line{Op: Insert, Text: bs[j], BLine: j + 1})
			stats.Added++
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, Line{Op: Delete, Text: as[i], ALine: i + 1})
		stats.Removed++
	}
	for ; j < m; j++ {
		out = append(out, Line{Op: Insert, Text: bs[j], BLine: j + 1})
		stats.Added++
	}
	return Result{Lines: out, Stats: stats}
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\n")
	for i, p := range parts {
		parts[i] = strings.TrimSuffix(p, "\r")
	}
	return parts
}

// CapInput truncates s to max bytes at a line boundary, so UI callers can
// bound a diff input without splitting a line (or UTF-8 sequence) mid-way.
func CapInput(s string, max int) string { return cutToLineBoundary(s, max) }

// cutToLineBoundary caps s at max bytes without splitting a line (or a UTF-8
// sequence mid-line, since the cut lands on a "\n").
func cutToLineBoundary(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if i := strings.LastIndex(s[:max], "\n"); i >= 0 {
		return s[:i+1]
	}
	return s[:max]
}

// clipToCells shrinks the longer side until len(as)*len(bs) fits maxDiffCells
// (or a side drops to 100 lines). It reports whether anything was cut.
func clipToCells(as, bs *[]string) bool {
	clipped := false
	for len(*as)*len(*bs) > maxDiffCells && (len(*as) > 100 || len(*bs) > 100) {
		if len(*as) >= len(*bs) {
			*as = (*as)[:len(*as)/2]
		} else {
			*bs = (*bs)[:len(*bs)/2]
		}
		clipped = true
	}
	return clipped
}
