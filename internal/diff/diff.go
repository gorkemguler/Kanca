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

// Lines computes the line diff between a and b. Inputs are split on "\n" with
// a trailing "\r" trimmed so CRLF and LF texts compare cleanly.
func Lines(a, b string) Result {
	as := splitLines(a)
	bs := splitLines(b)

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
