// Package repeater lets an operator take a captured request, edit it freely
// and resend it as many times as needed, keeping the response history per tab.
package repeater

import (
	"context"
	"sync"

	"github.com/gorkemguler/mimlec/internal/proxy"
)

// Tab is a single repeater workspace: an editable request bound to a target,
// plus the flows produced by sending it.
type Tab struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Raw    []byte `json:"raw"`

	// History holds past sends, newest last.
	History []*proxy.Flow `json:"history"`
}

// Repeater owns a set of tabs and a shared sender.
type Repeater struct {
	mu     sync.Mutex
	seq    int64
	tabs   map[int64]*Tab
	sender *proxy.Sender
}

// New builds a Repeater. insecure controls upstream TLS verification.
func New(insecure bool) *Repeater {
	return &Repeater{
		tabs:   make(map[int64]*Tab),
		sender: proxy.NewSender(proxy.SenderConfig{InsecureUpstream: insecure}),
	}
}

// NewTab creates a tab seeded with the given request. name may be empty.
func (r *Repeater) NewTab(name, scheme, host string, raw []byte) *Tab {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	if name == "" {
		name = defaultName(r.seq)
	}
	t := &Tab{ID: r.seq, Name: name, Scheme: scheme, Host: host, Raw: raw}
	r.tabs[t.ID] = t
	return t
}

// FromFlow seeds a new tab from a captured flow.
func (r *Repeater) FromFlow(f *proxy.Flow) *Tab {
	return r.NewTab("", f.Scheme, f.Host, f.Request.Raw)
}

// Update replaces a tab's editable request bytes and target.
func (r *Repeater) Update(id int64, scheme, host string, raw []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tabs[id]
	if !ok {
		return false
	}
	t.Scheme, t.Host, t.Raw = scheme, host, raw
	return true
}

// Send dispatches the tab's current request and appends the resulting flow to
// its history, returning that flow.
func (r *Repeater) Send(ctx context.Context, id int64) (*proxy.Flow, bool) {
	r.mu.Lock()
	t, ok := r.tabs[id]
	if !ok {
		r.mu.Unlock()
		return nil, false
	}
	scheme, host, raw := t.Scheme, t.Host, append([]byte(nil), t.Raw...)
	r.mu.Unlock()

	f := r.sender.Send(ctx, raw, scheme, host)

	r.mu.Lock()
	if t, ok := r.tabs[id]; ok {
		t.History = append(t.History, f)
	}
	r.mu.Unlock()
	return f, true
}

// Tabs returns a snapshot of all tabs.
func (r *Repeater) Tabs() []*Tab {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Tab, 0, len(r.tabs))
	for _, t := range r.tabs {
		out = append(out, t)
	}
	return out
}

// Close removes a tab.
func (r *Repeater) Close(id int64) {
	r.mu.Lock()
	delete(r.tabs, id)
	r.mu.Unlock()
}

func defaultName(n int64) string {
	return "Tab " + itoa(n)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
