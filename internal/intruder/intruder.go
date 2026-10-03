package intruder

import (
	"context"
	"regexp"
	"strings"
	"sync"

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

	// InsecureUpstream disables upstream TLS verification.
	InsecureUpstream bool
}

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
	Error      string      `json:"error,omitempty"`
}

// Attack is a runnable intruder job.
type Attack struct {
	tmpl   *Template
	cfg    Config
	sender *proxy.Sender
	grep   *regexp.Regexp
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
	a := &Attack{
		tmpl:   tmpl,
		cfg:    cfg,
		sender: proxy.NewSender(proxy.SenderConfig{InsecureUpstream: cfg.InsecureUpstream}),
	}
	if cfg.GrepMatch != "" {
		re, err := regexp.Compile(cfg.GrepMatch)
		if err != nil {
			return nil, errInvalid("invalid grep regexp: " + err.Error())
		}
		a.grep = re
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
		combos := cartesian(a.cfg.Payloads[:positions])
		for _, vals := range combos {
			jobs = append(jobs, job{index: idx, values: vals})
			idx++
		}
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
		for _, j := range jobs {
			select {
			case <-ctx.Done():
				break
			case tokens <- struct{}{}:
			}
			if ctx.Err() != nil {
				break
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

// Count reports how many requests the attack will issue without running it.
func (a *Attack) Count() int { return len(a.plan()) }

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
		res.Matched = a.grep.Match(f.Response.Body)
	}
	return res
}

func cartesian(sets [][]string) [][]string {
	result := [][]string{{}}
	for _, set := range sets {
		var next [][]string
		for _, prefix := range result {
			for _, v := range set {
				combo := append(append([]string(nil), prefix...), v)
				next = append(next, combo)
			}
		}
		result = next
	}
	return result
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
