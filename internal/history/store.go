// Package history keeps a searchable, bounded log of captured proxy flows.
// It is safe for concurrent use by the proxy (writer) and the UI (reader).
package history

import (
	"sort"
	"strings"
	"sync"

	"github.com/gorkemguler/mimlec/internal/proxy"
)

// Entry is a lightweight projection of a Flow for list rendering. The full
// Flow (with bodies) is fetched separately by ID.
type Entry struct {
	ID         int64  `json:"id"`
	Method     string `json:"method"`
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	StatusCode int    `json:"statusCode"`
	Length     int    `json:"length"`
	MIME       string `json:"mime"`
	DurationMs int64  `json:"durationMs"`
	Comment    string `json:"comment,omitempty"`
	Highlight  string `json:"highlight,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Store is a ring buffer of flows keyed by ID with a fast index for retrieval.
type Store struct {
	mu    sync.RWMutex
	max   int
	order []int64
	byID  map[int64]*proxy.Flow

	// listeners are notified (id) whenever a flow is added.
	listeners []func(int64)
}

// New returns a store that retains at most max flows (0 or negative means an
// effectively unbounded 100k cap to avoid unbounded memory growth).
func New(max int) *Store {
	if max <= 0 {
		max = 100_000
	}
	return &Store{
		max:  max,
		byID: make(map[int64]*proxy.Flow, 1024),
	}
}

// Subscribe registers fn to be called with the ID of each newly added flow.
func (s *Store) Subscribe(fn func(int64)) {
	s.mu.Lock()
	s.listeners = append(s.listeners, fn)
	s.mu.Unlock()
}

// Add records a flow, evicting the oldest when at capacity.
func (s *Store) Add(f *proxy.Flow) {
	s.mu.Lock()
	if _, exists := s.byID[f.ID]; !exists {
		s.order = append(s.order, f.ID)
	}
	s.byID[f.ID] = f
	for len(s.order) > s.max {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.byID, oldest)
	}
	listeners := make([]func(int64), len(s.listeners))
	copy(listeners, s.listeners)
	s.mu.Unlock()

	for _, fn := range listeners {
		fn(f.ID)
	}
}

// Get returns the full flow for id.
func (s *Store) Get(id int64) (*proxy.Flow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.byID[id]
	return f, ok
}

// Len reports the number of retained flows.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.order)
}

// Clear discards all retained flows.
func (s *Store) Clear() {
	s.mu.Lock()
	s.order = nil
	s.byID = make(map[int64]*proxy.Flow, 1024)
	s.mu.Unlock()
}

// Filter narrows which entries List returns.
type Filter struct {
	// Text matches (case-insensitive) against host, path and method.
	Text string
	// Methods, when non-empty, restricts to these HTTP methods.
	Methods []string
	// OnlyInScope, when set with a Scope func, hides out-of-scope hosts.
	Scope func(host string) bool
	// HideStatus lists status codes to omit (e.g. 404s).
	HideStatus map[int]bool
}

func (f Filter) matches(e *proxy.Flow) bool {
	if len(f.Methods) > 0 {
		ok := false
		for _, m := range f.Methods {
			if strings.EqualFold(m, e.Method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.HideStatus != nil && f.HideStatus[e.StatusCode] {
		return false
	}
	if f.Scope != nil && !f.Scope(hostOnly(e.Host)) {
		return false
	}
	if f.Text != "" {
		needle := strings.ToLower(f.Text)
		hay := strings.ToLower(e.Method + " " + e.Host + " " + e.Path)
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}

// List returns matching entries newest-first. A zero Filter returns all.
func (s *Store) List(filter Filter) []Entry {
	s.mu.RLock()
	flows := make([]*proxy.Flow, 0, len(s.order))
	for _, id := range s.order {
		if f := s.byID[id]; f != nil && filter.matches(f) {
			flows = append(flows, f)
		}
	}
	s.mu.RUnlock()

	sort.Slice(flows, func(i, j int) bool { return flows[i].ID > flows[j].ID })

	out := make([]Entry, 0, len(flows))
	for _, f := range flows {
		out = append(out, toEntry(f))
	}
	return out
}

func toEntry(f *proxy.Flow) Entry {
	return Entry{
		ID:         f.ID,
		Method:     f.Method,
		Scheme:     f.Scheme,
		Host:       f.Host,
		Path:       f.Path,
		StatusCode: f.StatusCode,
		Length:     len(f.Response.Body),
		MIME:       mimeOf(f),
		DurationMs: f.Duration,
		Comment:    f.Comment,
		Highlight:  f.Highlight,
		Error:      f.Error,
	}
}

func mimeOf(f *proxy.Flow) string {
	ct := f.Response.Headers.Get("Content-Type")
	if ct == "" {
		return ""
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		return strings.TrimSpace(ct[:i])
	}
	return ct
}

func hostOnly(authority string) string {
	if i := strings.LastIndexByte(authority, ':'); i > 0 {
		// Avoid stripping the colon in an IPv6 literal without a port.
		if !strings.Contains(authority[i+1:], "]") {
			return authority[:i]
		}
	}
	return authority
}
