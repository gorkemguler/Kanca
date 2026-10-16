package intruder

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// AttackType selects how payloads are distributed across positions.
type AttackType string

const (
	// Sniper uses one payload set and injects into a single position at a
	// time, leaving the others at their base value.
	Sniper AttackType = "sniper"
	// BatteringRam injects the same payload into every position at once.
	BatteringRam AttackType = "battering_ram"
	// Pitchfork walks multiple payload sets in lockstep (one set per position).
	Pitchfork AttackType = "pitchfork"
	// ClusterBomb tries every combination across multiple payload sets.
	ClusterBomb AttackType = "cluster_bomb"
)

// Config describes an attack to run.
type Config struct {
	Type   AttackType
	Scheme string
	Host   string

	// Payloads holds one or more payload sets. Sniper and BatteringRam use
	// Payloads[0]; Pitchfork and ClusterBomb use one set per position.
	Payloads [][]string

	// Concurrency caps in-flight requests. Defaults to 10.
	Concurrency int

	// GrepMatch, when non-empty, is compiled as a regexp and each response is
	// flagged if the body matches — a quick way to spot interesting results.
	GrepMatch string

	// ExtractGrep, when non-empty, is compiled as a regexp and the first
	// match (or its first capture group) is copied into Result.Extracted, so
	// tokens echoed in responses can be harvested at a glance. Matches are
	// capped at maxExtractLen.
	ExtractGrep string

	// DelayMs waits this long before every dispatch, including the first,
	// so rate-limited targets and WAFs are not hammered. Zero means full speed.
	DelayMs int

	// InsecureUpstream disables upstream TLS verification.
	InsecureUpstream bool
}

// MaxPlannedRequests caps how many requests one attack may plan. Cluster-bomb
// combinations grow multiplicatively; without a cap a wide numeric range can
// exhaust memory before the first request is sent. PreviewIntruder reports the
// cap via IntruderPreview.Capped.
const MaxPlannedRequests = 20000

// Result is one dispatched request's outcome. Results are delivered in
// completion order, each tagged with the payload set index it came from.
type Result struct {
	Index      int         `json:"index"`
	Payloads   []string    `json:"payloads"`
	Flow       *proxy.Flow `json:"flow"`
	StatusCode int         `json:"statusCode"`
	Length     int         `json:"length"`
	DurationMs int64       `json:"durationMs"`
	Matched    bool        `json:"matched"`
	// Extracted holds the first ExtractGrep match (or its first capture
	// group), capped at maxExtractLen. Empty when nothing matched.
	Extracted string `json:"extracted,omitempty"`
	Error     string `json:"error,omitempty"`
}

// maxExtractLen caps Result.Extracted so a greedy regexp cannot balloon a result.
const maxExtractLen = 200

// Attack is a runnable intruder job.
type Attack struct {
	tmpl    *Template
	cfg     Config
	sender  *proxy.Sender
	grep    *regexp.Regexp
	extract *regexp.Regexp
	// mu guards truncated: plan() runs on the dispatch goroutine while
	// Count/Truncated may be read from the UI thread.
	mu sync.Mutex
	// truncated is true when plan() hit MaxPlannedRequests and dropped the
	// tail of the combination space. Read via Truncated().
	truncated bool
	// pauseMu guards paused/resumeCh. SetPaused flips the state; the Run
	// loop waits while paused (in-flight requests still finish).
	pauseMu  sync.Mutex
	paused   bool
	resumeCh chan struct{}
}

// NewAttack validates cfg against tmpl and prepares the job.
func NewAttack(tmpl *Template, cfg Config) (*Attack, error) {
	if tmpl.Positions() == 0 {
		return nil, errInvalid("template defines no payload positions")
	}
	if len(cfg.Payloads) == 0 {
		return nil, errInvalid("no payload sets provided")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	switch cfg.Type {
	case Sniper, BatteringRam:
		// single set used
	case Pitchfork, ClusterBomb:
		if len(cfg.Payloads) < tmpl.Positions() {
			return nil, errInvalid("need one payload set per position for this attack type")
		}
	default:
		return nil, errInvalid("unknown attack type: " + string(cfg.Type))
	}
	if cfg.DelayMs < 0 {
		return nil, errInvalid("delay must not be negative")
	}
	a := &Attack{
		tmpl:     tmpl,
		cfg:      cfg,
		sender:   proxy.NewSender(proxy.SenderConfig{InsecureUpstream: cfg.InsecureUpstream}),
		resumeCh: make(chan struct{}),
	}
	if cfg.GrepMatch != "" {
		re, err := regexp.Compile(cfg.GrepMatch)
		if err != nil {
			return nil, errInvalid("invalid grep regexp: " + err.Error())
		}
		a.grep = re
	}
	if cfg.ExtractGrep != "" {
		re, err := regexp.Compile(cfg.ExtractGrep)
		if err != nil {
			return nil, errInvalid("invalid extract regexp: " + err.Error())
		}
		a.extract = re
	}
	return a, nil
}

// job is a single planned request: the concrete values for each position.
type job struct {
	index  int
	values []string
}

// plan enumerates every request the attack will make, according to its type.
func (a *Attack) plan() []job {
	positions := a.tmpl.Positions()
	base := a.tmpl.BaseValues()
	var jobs []job
	idx := 0

	switch a.cfg.Type {
	case Sniper:
		set := a.cfg.Payloads[0]
		for pos := 0; pos < positions; pos++ {
			for _, pl := range set {
				vals := append([]string(nil), base...)
				vals[pos] = pl
				jobs = append(jobs, job{index: idx, values: vals})
				idx++
			}
		}
	case BatteringRam:
		set := a.cfg.Payloads[0]
		for _, pl := range set {
			vals := make([]string, positions)
			for i := range vals {
				vals[i] = pl
			}
			jobs = append(jobs, job{index: idx, values: vals})
			idx++
		}
	case Pitchfork:
		n := minLen(a.cfg.Payloads[:positions])
		for i := 0; i < n; i++ {
			vals := make([]string, positions)
			for pos := 0; pos < positions; pos++ {
				vals[pos] = a.cfg.Payloads[pos][i]
			}
			jobs = append(jobs, job{index: idx, values: vals})
			idx++
		}
	case ClusterBomb:
		combos, cut := cartesianCapped(a.cfg.Payloads[:positions], MaxPlannedRequests)
		if cut {
			a.mu.Lock()
			a.truncated = true
			a.mu.Unlock()
		}
		for _, vals := range combos {
			jobs = append(jobs, job{index: idx, values: vals})
			idx++
		}
	}
	if len(jobs) > MaxPlannedRequests {
		jobs = jobs[:MaxPlannedRequests]
		a.mu.Lock()
		a.truncated = true
		a.mu.Unlock()
	}
	return jobs
}

// Run executes the attack, streaming results on the returned channel until all
// requests finish or ctx is cancelled. The channel is closed when done.
func (a *Attack) Run(ctx context.Context) <-chan Result {
	jobs := a.plan()
	out := make(chan Result)
	tokens := make(chan struct{}, a.cfg.Concurrency)
	var wg sync.WaitGroup

	go func() {
		defer close(out)
	loop:
		for _, j := range jobs {
			// Fast path: an already-cancelled context must not dispatch even
			// one job. (The select below would also catch it, but when a
			// token slot is free both cases are ready and Go picks randomly.)
			if ctx.Err() != nil {
				break loop
			}
			// Pause gate + inter-request delay (both honour cancellation).
			if !a.sleepDelay(ctx) {
				break loop
			}
			select {
			case <-ctx.Done():
				break loop
			case tokens <- struct{}{}:
			}
			wg.Add(1)
			go func(j job) {
				defer wg.Done()
				defer func() { <-tokens }()
				res := a.dispatch(ctx, j)
				select {
				case out <- res:
				case <-ctx.Done():
				}
			}(j)
		}
		wg.Wait()
	}()
	return out
}

// SetPaused freezes (true) or resumes (false) dispatching. In-flight requests
// still finish; the results channel stays open until resume or cancel.
func (a *Attack) SetPaused(p bool) {
	a.pauseMu.Lock()
	defer a.pauseMu.Unlock()
	if a.paused == p {
		return
	}
	a.paused = p
	if !p {
		close(a.resumeCh)
		a.resumeCh = make(chan struct{})
	}
}

// Paused reports the current pause state.
func (a *Attack) Paused() bool {
	a.pauseMu.Lock()
	defer a.pauseMu.Unlock()
	return a.paused
}

// waitIfPaused blocks while the attack is paused. It returns false when ctx
// was cancelled while waiting.
func (a *Attack) waitIfPaused(ctx context.Context) bool {
	for {
		a.pauseMu.Lock()
		paused, ch := a.paused, a.resumeCh
		a.pauseMu.Unlock()
		if !paused {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ch:
		}
	}
}

// sleepDelay waits DelayMs before the next dispatch, honouring cancel and
// pause. It returns false when the wait was cut short by cancellation.
func (a *Attack) sleepDelay(ctx context.Context) bool {
	d := time.Duration(a.cfg.DelayMs) * time.Millisecond
	if d <= 0 {
		return a.waitIfPaused(ctx) && ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		if !a.waitIfPaused(ctx) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
		// The timer may have fired while paused; re-gate before dispatch.
		if a.waitIfPaused(ctx) {
			return true
		}
		return false
	}
}

// Count reports how many requests the attack will issue without running it.
func (a *Attack) Count() int { return len(a.plan()) }

// Truncated reports whether the plan was capped at MaxPlannedRequests.
// It is valid after the plan has been built (Count, Run, or PreviewIntruder
// all build it); a fresh Attack that never planned reports false.
func (a *Attack) Truncated() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.truncated
}

func (a *Attack) dispatch(ctx context.Context, j job) Result {
	raw := a.tmpl.Render(j.values)
	f := a.sender.Send(ctx, raw, a.cfg.Scheme, a.cfg.Host)
	res := Result{
		Index:      j.index,
		Payloads:   j.values,
		Flow:       f,
		StatusCode: f.StatusCode,
		Length:     len(f.Response.Body),
		DurationMs: f.Duration,
		Error:      f.Error,
	}
	if a.grep != nil && f.Error == "" {
		res.Matched = a.grep.Match(f.Response.DecodedBody())
	}
	if a.extract != nil && f.Error == "" {
		res.Extracted = extractFirst(a.extract, f.Response.DecodedBody())
	}
	return res
}

// extractFirst returns the first match of re in body — the first capture
// group when the pattern defines one — capped at maxExtractLen.
func extractFirst(re *regexp.Regexp, body []byte) string {
	m := re.FindSubmatch(body)
	if m == nil {
		return ""
	}
	out := m[0]
	if len(m) > 1 {
		out = m[1]
	}
	if len(out) > maxExtractLen {
		out = out[:maxExtractLen]
	}
	return string(out)
}

// cartesianCapped is cartesian with an early stop: when capN > 0, at most
// capN combinations are produced, so a huge product cannot exhaust memory.
// Every returned combination has full arity (one value per set); only the
// tail of the product is dropped. It reports whether the space was truncated.
func cartesianCapped(sets [][]string, capN int) (out [][]string, truncated bool) {
	for _, s := range sets {
		if len(s) == 0 {
			return nil, false
		}
	}
	// Bound the product without materialising it (early exit on overflow).
	total := 1
	for _, s := range sets {
		if capN > 0 && total > capN/len(s) {
			total = capN + 1
			break
		}
		total *= len(s)
	}
	n := total
	if capN > 0 && n > capN {
		n, truncated = capN, true
	}
	out = make([][]string, 0, n)
	idx := make([]int, len(sets))
	for i := 0; i < n; i++ {
		combo := make([]string, len(sets))
		for j, s := range sets {
			combo[j] = s[idx[j]]
		}
		out = append(out, combo)
		for j := len(sets) - 1; j >= 0; j-- {
			idx[j]++
			if idx[j] < len(sets[j]) {
				break
			}
			idx[j] = 0
		}
	}
	return out, truncated
}

func minLen(sets [][]string) int {
	if len(sets) == 0 {
		return 0
	}
	m := len(sets[0])
	for _, s := range sets[1:] {
		if len(s) < m {
			m = len(s)
		}
	}
	return m
}

type invalidConfig struct{ msg string }

func (e invalidConfig) Error() string { return "intruder: " + e.msg }

func errInvalid(msg string) error { return invalidConfig{msg: strings.TrimSpace(msg)} }
