// Package mcp lets AI assistants such as Claude work with Kanca through the
// Model Context Protocol: read captured traffic, the site map and findings,
// send requests to and scan the user's targets, and record findings.
//
// The endpoint speaks MCP's Streamable HTTP transport (JSON responses, no
// server-initiated stream), listens on loopback only and requires a bearer
// token. RunStdioBridge exposes the same endpoint to stdio-only clients such
// as Claude Desktop. Only the standard library is used.
package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
)

// Access levels.
const (
	// LevelRead lets the assistant read traffic and record findings only.
	LevelRead = "read"
	// LevelReadWrite also lets it send requests and run active scans against
	// in-scope hosts.
	LevelReadWrite = "readwrite"
)

// DefaultBudget caps how many requests an assistant may send per session.
const DefaultBudget = 500

// Deps connects the server to Kanca's live state.
type Deps struct {
	Store   *history.Store
	Scanner *scanner.Scanner
	// Scope returns the matcher for the user's targets, or nil when none are set;
	// actions are refused without one.
	Scope func() func(host string) bool
	// ScopeHosts lists the configured scope entries, for display.
	ScopeHosts func() []string
	// Send dispatches a raw request; nil uses a fresh proxy.Sender.
	Send func(raw []byte, scheme, host string) *proxy.Flow
	// Version is reported to clients.
	Version string
	// OnActivity, if set, is called after each tool call so the user can
	// follow what the assistant does.
	OnActivity func(Activity)
}

// Activity records one tool call.
type Activity struct {
	At     time.Time `json:"at"`
	Tool   string    `json:"tool"`
	Action string    `json:"action"`
	Result string    `json:"result"`
	Error  bool      `json:"error,omitempty"`
}

// maxActivity bounds the activity kept per session.
const maxActivity = 200

// Options are the user-controlled settings, read on every call so changes
// apply immediately.
type Options struct {
	Level  string
	Mask   bool
	Budget int
}

// Server handles MCP messages. Create it with NewServer.
type Server struct {
	deps    Deps
	opts    func() Options
	secrets *secretBox

	mu       sync.Mutex
	sent     int
	activity []Activity
}

// NewServer returns a server backed by deps; opts is consulted on each call.
func NewServer(deps Deps, opts func() Options) *Server {
	if deps.Send == nil {
		sender := proxy.NewSender(proxy.SenderConfig{InsecureUpstream: true})
		deps.Send = func(raw []byte, scheme, host string) *proxy.Flow {
			return sender.Send(context.Background(), raw, scheme, host)
		}
	}
	return &Server{deps: deps, opts: opts, secrets: newSecretBox()}
}

// Sent reports how many requests the assistant has sent this session.
func (s *Server) Sent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

// Activity returns this session's tool calls, oldest first.
func (s *Server) Activity() []Activity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Activity(nil), s.activity...)
}

func (s *Server) record(a Activity) {
	s.mu.Lock()
	s.activity = append(s.activity, a)
	if len(s.activity) > maxActivity {
		s.activity = append([]Activity(nil), s.activity[len(s.activity)-maxActivity:]...)
	}
	s.mu.Unlock()
	if s.deps.OnActivity != nil {
		s.deps.OnActivity(a)
	}
}

// Handler serves the MCP endpoint, requiring "Authorization: Bearer <token>".
func (s *Server) Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A browser page must not reach this endpoint (DNS rebinding).
		if origin := r.Header.Get("Origin"); origin != "" && !loopbackOrigin(origin) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if !validBearer(r.Header.Get("Authorization"), token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kanca"`)
			http.Error(w, "missing or invalid token", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			// No server-initiated SSE stream and no sessions to delete.
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		resp, isRequest := s.HandleMessage(body)
		if !isRequest {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	})
}

func validBearer(header, token string) bool {
	const prefix = "Bearer "
	if token == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, prefix)), []byte(token)) == 1
}

func loopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// ---- JSON-RPC ----------------------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// supportedVersions lists protocol revisions this server speaks, newest first.
var supportedVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// HandleMessage processes one JSON-RPC message. It returns the encoded
// response and true for requests, or nil and false for notifications.
func (s *Server) HandleMessage(msg []byte) ([]byte, bool) {
	var req rpcRequest
	if err := json.Unmarshal(msg, &req); err != nil || req.Method == "" {
		return encode(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}), true
	}
	if len(req.ID) == 0 || string(req.ID) == "null" {
		return nil, false // notifications (initialized, cancelled...) need no reply
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = s.initialize(req.Params)
	case "ping":
		resp.Result = struct{}{}
	case "tools/list":
		resp.Result = map[string]any{"tools": toolDefs}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			resp.Error = &rpcError{-32602, "invalid params"}
			break
		}
		result, ok := s.callTool(p.Name, p.Arguments)
		if !ok {
			resp.Error = &rpcError{-32602, "unknown tool: " + p.Name}
			break
		}
		resp.Result = result
	default:
		resp.Error = &rpcError{-32601, "method not found: " + req.Method}
	}
	return encode(resp), true
}

func encode(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (s *Server) initialize(params json.RawMessage) any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	version := supportedVersions[0]
	for _, v := range supportedVersions {
		if v == p.ProtocolVersion {
			version = v
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "kanca", "title": "Kanca intercepting proxy", "version": s.deps.Version},
		"instructions":    instructions,
	}
}

const instructions = `Kanca is an intercepting proxy. The user browses a target through it; you can review what was captured and help find security issues.

Work like a careful tester: start with list_flows and get_sitemap to understand the application, read interesting requests with get_flow, and form concrete hypotheses (IDOR, injection, auth/session flaws, missing access control, information leaks). Verify them with send_request or active_scan before reporting, then record each confirmed or strongly suspected issue with add_finding, including the evidence (flow IDs, what changed, what came back).

Only the user's targets may be tested; get_scope lists them. You can read all captured traffic, but leave other sites alone. Keep requests minimal and non-destructive: never delete or modify real data, never brute-force credentials, and stop if something looks unsafe. Values like [[KANCA_SECRET_3]] are masked secrets (cookies, tokens, passwords): copy them unchanged into send_request and Kanca substitutes the real value.`
