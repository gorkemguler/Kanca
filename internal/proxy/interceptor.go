package proxy

import (
	"sync"
)

// Direction identifies which half of a transaction an intercepted item holds.
type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
)

// Decision is the resolution the user (or a rule) applies to a held item.
type Decision int

const (
	// DecisionForward sends the item on, using EditedRaw when non-nil.
	DecisionForward Decision = iota
	// DecisionDrop abandons the transaction; the client receives a reset.
	DecisionDrop
)

// Held is a transaction paused by the interceptor awaiting a Decision. The
// resolve channel is buffered with capacity 1 so Resolve never blocks.
type Held struct {
	ID        int64     `json:"id"`
	Direction Direction `json:"direction"`
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Raw       []byte    `json:"raw"`

	resolve chan resolution
}

type resolution struct {
	decision  Decision
	editedRaw []byte
}

// Resolution carries the user's choice back to the paused round trip.
type Resolution struct {
	Decision  Decision
	EditedRaw []byte // when non-nil, replaces the on-the-wire bytes
}

// Interceptor holds transactions when enabled and releases them once a
// Decision arrives. When disabled it passes everything through untouched.
//
// The zero value is not usable; construct with newInterceptor.
type Interceptor struct {
	mu                 sync.RWMutex
	enabled            bool
	interceptResponses bool

	pending map[int64]*Held
	// onHold is invoked (without locks held) whenever an item is queued, so
	// the UI layer can surface it. May be nil.
	onHold func(*Held)
}

func newInterceptor() *Interceptor {
	return &Interceptor{pending: make(map[int64]*Held)}
}

// SetEnabled toggles request interception. Disabling it does not auto-forward
// already-held items; call ForwardAll for that.
func (ic *Interceptor) SetEnabled(v bool) {
	ic.mu.Lock()
	ic.enabled = v
	ic.mu.Unlock()
}

// SetInterceptResponses toggles whether responses are also held.
func (ic *Interceptor) SetInterceptResponses(v bool) {
	ic.mu.Lock()
	ic.interceptResponses = v
	ic.mu.Unlock()
}

// Enabled reports whether request interception is active.
func (ic *Interceptor) Enabled() bool {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.enabled
}

func (ic *Interceptor) setOnHold(fn func(*Held)) {
	ic.mu.Lock()
	ic.onHold = fn
	ic.mu.Unlock()
}

// hold blocks the calling round trip until a Decision is supplied for the
// given direction. When interception for that direction is off it returns a
// forward-through resolution immediately.
func (ic *Interceptor) hold(id int64, dir Direction, host, method, url string, raw []byte) Resolution {
	ic.mu.Lock()
	active := ic.enabled && (dir == DirectionRequest || ic.interceptResponses)
	if !active {
		ic.mu.Unlock()
		return Resolution{Decision: DecisionForward}
	}
	h := &Held{
		ID:        id,
		Direction: dir,
		Host:      host,
		Method:    method,
		URL:       url,
		Raw:       raw,
		resolve:   make(chan resolution, 1),
	}
	ic.pending[id] = h
	onHold := ic.onHold
	ic.mu.Unlock()

	if onHold != nil {
		onHold(h)
	}

	r := <-h.resolve

	ic.mu.Lock()
	delete(ic.pending, id)
	ic.mu.Unlock()

	return Resolution{Decision: r.decision, EditedRaw: r.editedRaw}
}

// Resolve applies a Decision to a held item. editedRaw may be nil to forward
// the original bytes. It is a no-op if the id is unknown or already resolved.
func (ic *Interceptor) Resolve(id int64, decision Decision, editedRaw []byte) {
	ic.mu.RLock()
	h, ok := ic.pending[id]
	ic.mu.RUnlock()
	if !ok {
		return
	}
	select {
	case h.resolve <- resolution{decision: decision, editedRaw: editedRaw}:
	default:
		// Already resolved; ignore the duplicate.
	}
}

// ForwardAll releases every held item with a plain forward decision.
func (ic *Interceptor) ForwardAll() {
	ic.mu.RLock()
	ids := make([]int64, 0, len(ic.pending))
	for id := range ic.pending {
		ids = append(ids, id)
	}
	ic.mu.RUnlock()
	for _, id := range ids {
		ic.Resolve(id, DecisionForward, nil)
	}
}

// Pending returns a snapshot of currently held items.
func (ic *Interceptor) Pending() []*Held {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	out := make([]*Held, 0, len(ic.pending))
	for _, h := range ic.pending {
		out = append(out, h)
	}
	return out
}
