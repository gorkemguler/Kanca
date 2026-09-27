package intruder

import (
	"crypto/md5"  //nolint:gosec // offered as a payload transform, not for security
	"crypto/sha1" //nolint:gosec // offered as a payload transform, not for security
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// PayloadSpec describes how to produce one payload set, either from an explicit
// list or by generating a numeric range. Exactly one mode is used: if Numbers
// is non-nil it takes precedence, otherwise List is used.
type PayloadSpec struct {
	// List is an explicit set of payloads (one per line in the UI).
	List []string `json:"list"`
	// Numbers, when set, generates a numeric sequence.
	Numbers *NumberRange `json:"numbers,omitempty"`
	// Processors are applied in order to every generated payload.
	Processors []Processor `json:"processors,omitempty"`
}

// NumberRange generates From, From+Step, … up to and including To (when the
// step lands on it). Step defaults to 1; a From greater than To with a
// positive step yields nothing.
type NumberRange struct {
	From int `json:"from"`
	To   int `json:"to"`
	Step int `json:"step"`
	// Pad, when > 0, zero-pads each number to that width ("007").
	Pad int `json:"pad"`
}

// Processor names a transform applied to each payload value. Unknown or empty
// processors are treated as identity.
type Processor string

const (
	ProcNone      Processor = ""
	ProcURLEncode Processor = "url"
	ProcBase64    Processor = "base64"
	ProcLower     Processor = "lower"
	ProcUpper     Processor = "upper"
	ProcMD5       Processor = "md5"
	ProcSHA1      Processor = "sha1"
	ProcSHA256    Processor = "sha256"
)

// Generate expands a spec into concrete payloads, with processors applied.
func (s PayloadSpec) Generate() []string {
	var base []string
	if s.Numbers != nil {
		base = s.Numbers.expand()
	} else {
		base = append(base, s.List...)
	}
	if len(s.Processors) == 0 {
		return base
	}
	out := make([]string, len(base))
	for i, v := range base {
		out[i] = ApplyProcessors(v, s.Processors)
	}
	return out
}

func (r NumberRange) expand() []string {
	step := r.Step
	if step == 0 {
		step = 1
	}
	var out []string
	// Bound the count so a pathological range can't allocate without limit.
	const maxCount = 1_000_000
	n := 0
	if step > 0 {
		for v := r.From; v <= r.To && n < maxCount; v += step {
			out = append(out, r.format(v))
			n++
		}
	} else {
		for v := r.From; v >= r.To && n < maxCount; v += step {
			out = append(out, r.format(v))
			n++
		}
	}
	return out
}

func (r NumberRange) format(v int) string {
	if r.Pad > 0 {
		return fmt.Sprintf("%0*d", r.Pad, v)
	}
	return fmt.Sprintf("%d", v)
}

// ApplyProcessors runs each processor over value in order.
func ApplyProcessors(value string, procs []Processor) string {
	for _, p := range procs {
		value = applyOne(value, p)
	}
	return value
}

func applyOne(value string, p Processor) string {
	switch p {
	case ProcURLEncode:
		return url.QueryEscape(value)
	case ProcBase64:
		return base64.StdEncoding.EncodeToString([]byte(value))
	case ProcLower:
		return strings.ToLower(value)
	case ProcUpper:
		return strings.ToUpper(value)
	case ProcMD5:
		sum := md5.Sum([]byte(value)) //nolint:gosec
		return hex.EncodeToString(sum[:])
	case ProcSHA1:
		sum := sha1.Sum([]byte(value)) //nolint:gosec
		return hex.EncodeToString(sum[:])
	case ProcSHA256:
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	default:
		return value
	}
}
