package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gorkemguler/kanca/internal/activescan"
	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
	"github.com/gorkemguler/kanca/internal/scope"
	"github.com/gorkemguler/kanca/internal/sitemap"
)

// Markers on flows the assistant sent, so the user can tell them apart.
const (
	aiHighlight = "ai"
	aiComment   = "Sent by AI assistant (MCP)"
)

const defaultMaxBody = 20000

type tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations"`
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

var (
	readOnly = map[string]any{"readOnlyHint": true, "openWorldHint": false}
	recorder = map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	prober   = map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true}
)

var maxBodyProp = map[string]any{"type": "integer", "minimum": 0, "description": "Truncate each body to this many bytes (default 20000)."}

var toolDefs = []tool{
	{
		Name: "list_flows", Title: "List captured requests",
		Description: "List HTTP(S) transactions captured by Kanca, newest first: ID, method, URL, status, size and type. Use filter to narrow by method, host or path (and bodies with search_bodies).",
		InputSchema: obj(map[string]any{
			"filter":        map[string]any{"type": "string", "description": "Case-insensitive text matched against method, host and path."},
			"search_bodies": map[string]any{"type": "boolean", "description": "Also match filter against request and response bodies."},
			"host":          map[string]any{"type": "string", "description": "Only flows to this host (or its subdomains)."},
			"limit":         map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "description": "Default 50."},
			"offset":        map[string]any{"type": "integer", "minimum": 0},
		}),
		Annotations: readOnly,
	},
	{
		Name: "get_flow", Title: "Read a captured request and response",
		Description: "Return the full raw request and response of one flow. Compressed response bodies are decoded; binary bodies are summarised.",
		InputSchema: obj(map[string]any{
			"id":             map[string]any{"type": "integer", "description": "Flow ID from list_flows."},
			"max_body_bytes": maxBodyProp,
		}, "id"),
		Annotations: readOnly,
	},
	{
		Name: "get_sitemap", Title: "Show the site map",
		Description: "The endpoints observed through the proxy, as a tree per host, with the last method and status seen and how many times each path was hit.",
		InputSchema: obj(map[string]any{
			"host": map[string]any{"type": "string", "description": "Only this host."},
		}),
		Annotations: readOnly,
	},
	{
		Name: "list_findings", Title: "List findings",
		Description: "Issues found so far by Kanca's passive and active scanners and by AI assistants, with severity, host and the related flow.",
		InputSchema: obj(map[string]any{}),
		Annotations: readOnly,
	},
	{
		Name: "get_scope", Title: "Show what may be tested",
		Description: "The user's targets (the only hosts you may send requests to or scan), your access level, and how many requests you have left.",
		InputSchema: obj(map[string]any{}),
		Annotations: readOnly,
	},
	{
		Name: "send_request", Title: "Send a request",
		Description: "Send a raw HTTP/1.1 request to one of the user's targets, like Burp Repeater, and return the response. It is recorded in Kanca's history marked as sent by AI. Start from a captured flow (get_flow) and change one thing at a time. Content-Length is recomputed. Keep [[KANCA_SECRET_n]] placeholders as they are.",
		InputSchema: obj(map[string]any{
			"raw":            map[string]any{"type": "string", "description": "The full request: request line, headers, blank line, optional body."},
			"from_flow_id":   map[string]any{"type": "integer", "description": "Use this flow's scheme and host as defaults."},
			"scheme":         map[string]any{"type": "string", "enum": []string{"http", "https"}},
			"host":           map[string]any{"type": "string", "description": "host:port to connect to; defaults to the Host header."},
			"max_body_bytes": maxBodyProp,
		}, "raw"),
		Annotations: prober,
	},
	{
		Name: "active_scan", Title: "Run Kanca's active scanner",
		Description: "Probe one captured request's parameters for reflected XSS, SQL injection, path traversal, open redirect, template injection and CRLF injection. aggressive adds boolean/time-based SQL injection and command injection checks, which make the target do work. Each probe counts against the session's request budget (a scan sends from a few to a few hundred requests, depending on the parameters). Findings are added to Kanca and returned.",
		InputSchema: obj(map[string]any{
			"flow_id":    map[string]any{"type": "integer"},
			"aggressive": map[string]any{"type": "boolean", "description": "Default false."},
		}, "flow_id"),
		Annotations: prober,
	},
	{
		Name: "add_finding", Title: "Record a finding",
		Description: "Add an issue you found to Kanca's Findings, marked as from AI, for the user to review. Include the evidence: which flows, what you changed and what the response showed.",
		InputSchema: obj(map[string]any{
			"severity": map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high"}},
			"title":    map[string]any{"type": "string", "description": "Short, e.g. \"IDOR in /api/users id\"."},
			"detail":   map[string]any{"type": "string", "description": "Evidence and how to reproduce."},
			"flow_id":  map[string]any{"type": "integer", "description": "The flow that demonstrates it."},
			"host":     map[string]any{"type": "string", "description": "Host, when there is no flow_id."},
		}, "severity", "title", "detail"),
		Annotations: recorder,
	},
}

type toolResult struct {
	Content []map[string]string `json:"content"`
	IsError bool                `json:"isError,omitempty"`
}

func textResult(format string, a ...any) toolResult {
	return toolResult{Content: []map[string]string{{"type": "text", "text": fmt.Sprintf(format, a...)}}}
}

func errorResult(format string, a ...any) toolResult {
	r := textResult(format, a...)
	r.IsError = true
	return r
}

// callTool runs a tool and records it in the activity log; ok is false when
// the name is unknown.
func (s *Server) callTool(name string, args json.RawMessage) (toolResult, bool) {
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	r, ok := s.runTool(name, args)
	if ok {
		s.record(Activity{
			At: time.Now(), Tool: name, Action: describeCall(name, args),
			Result: firstLine(r), Error: r.IsError,
		})
	}
	return r, ok
}

func (s *Server) runTool(name string, args json.RawMessage) (toolResult, bool) {
	switch name {
	case "list_flows":
		return s.listFlows(args), true
	case "get_flow":
		return s.getFlow(args), true
	case "get_sitemap":
		return s.getSitemap(args), true
	case "list_findings":
		return s.listFindings(), true
	case "get_scope":
		return s.getScope(), true
	case "send_request":
		return s.sendRequest(args), true
	case "active_scan":
		return s.activeScan(args), true
	case "add_finding":
		return s.addFinding(args), true
	}
	return toolResult{}, false
}

// describeCall summarises a tool call for the activity log.
func describeCall(name string, args json.RawMessage) string {
	var a struct {
		ID       int64  `json:"id"`
		FlowID   int64  `json:"flow_id"`
		FromFlow int64  `json:"from_flow_id"`
		Filter   string `json:"filter"`
		Host     string `json:"host"`
		Raw      string `json:"raw"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Aggr     bool   `json:"aggressive"`
	}
	_ = json.Unmarshal(args, &a)
	switch name {
	case "list_flows":
		if a.Filter != "" {
			return fmt.Sprintf("Listed flows matching %q", a.Filter)
		}
		if a.Host != "" {
			return "Listed flows for " + a.Host
		}
		return "Listed flows"
	case "get_flow":
		return fmt.Sprintf("Read flow #%d", a.ID)
	case "get_sitemap":
		if a.Host != "" {
			return "Read the site map of " + a.Host
		}
		return "Read the site map"
	case "list_findings":
		return "Read findings"
	case "get_scope":
		return "Read the targets"
	case "send_request":
		head, _, _ := strings.Cut(strings.ReplaceAll(strings.TrimLeft(a.Raw, "\r\n"), "\r\n", "\n"), "\n\n")
		line, _, _ := strings.Cut(head, "\n")
		method, target, _ := strings.Cut(strings.TrimSpace(line), " ")
		target, _, _ = strings.Cut(target, " ") // drop the HTTP version
		host := a.Host
		if host == "" {
			host = headerValue(strings.ReplaceAll(head, "\n", "\r\n"), "Host")
		}
		if host == "" && a.FromFlow != 0 {
			host = fmt.Sprintf("flow #%d's host", a.FromFlow)
		}
		return clip(fmt.Sprintf("Sent %s %s to %s", method, target, host), 200)
	case "active_scan":
		if a.Aggr {
			return fmt.Sprintf("Ran an aggressive active scan of flow #%d", a.FlowID)
		}
		return fmt.Sprintf("Ran an active scan of flow #%d", a.FlowID)
	case "add_finding":
		return fmt.Sprintf("Reported [%s] %s", strings.ToUpper(a.Severity), a.Title)
	}
	return name
}

func firstLine(r toolResult) string {
	if len(r.Content) == 0 {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(r.Content[0]["text"]), "\n")
	return clip(strings.TrimSuffix(line, ":"), 200)
}

// clip shortens s to at most n bytes without splitting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func (s *Server) listFlows(args json.RawMessage) toolResult {
	var a struct {
		Filter       string `json:"filter"`
		SearchBodies bool   `json:"search_bodies"`
		Host         string `json:"host"`
		Limit        int    `json:"limit"`
		Offset       int    `json:"offset"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return errorResult("invalid arguments: %v", err)
	}
	if a.Limit <= 0 || a.Limit > 500 {
		a.Limit = 50
	}
	entries := s.deps.Store.List(history.Filter{Text: a.Filter, SearchBodies: a.SearchBodies})
	if a.Host != "" {
		kept := entries[:0]
		for _, e := range entries {
			if hostMatches(hostOnly(e.Host), a.Host) {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	total := len(entries)
	if a.Offset > total {
		a.Offset = total
	}
	entries = entries[a.Offset:]
	if len(entries) > a.Limit {
		entries = entries[:a.Limit]
	}
	if total == 0 {
		return textResult("No captured flows match. The user may need to browse the target through Kanca first.")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d flow(s) match; showing %d from offset %d, newest first.\n", total, len(entries), a.Offset)
	for _, e := range entries {
		status := fmt.Sprint(e.StatusCode)
		if e.Error != "" {
			status = "ERROR"
		}
		mark := ""
		if e.Highlight == aiHighlight {
			mark = " [sent by AI]"
		}
		fmt.Fprintf(&b, "#%d %s %s://%s%s -> %s %dB %s%s\n", e.ID, e.Method, e.Scheme, e.Host,
			s.maskTarget(e.Path), status, e.Length, e.MIME, mark)
	}
	return textResult("%s", b.String())
}

func (s *Server) getFlow(args json.RawMessage) toolResult {
	var a struct {
		ID      int64 `json:"id"`
		MaxBody *int  `json:"max_body_bytes"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return errorResult("invalid arguments: %v", err)
	}
	f, ok := s.deps.Store.Get(a.ID)
	if !ok {
		return errorResult("flow #%d not found (list_flows shows the available IDs)", a.ID)
	}
	return textResult("%s", s.describeFlow(f, maxBody(a.MaxBody)))
}

func maxBody(p *int) int {
	if p == nil || *p < 0 {
		return defaultMaxBody
	}
	return *p
}

func (s *Server) describeFlow(f *proxy.Flow, limit int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Flow #%d: %s %s\n", f.ID, f.Method, s.maskTarget(f.URL))
	if f.Highlight == aiHighlight {
		b.WriteString("(sent by AI)\n")
	}
	fmt.Fprintf(&b, "Duration: %dms\n\n--- Request ---\n", f.Duration)
	b.WriteString(s.render(f.Request, limit))
	if f.Error != "" {
		fmt.Fprintf(&b, "\n\n--- Error ---\n%s\n", f.Error)
		return b.String()
	}
	b.WriteString("\n\n--- Response ---\n")
	b.WriteString(s.render(f.Response, limit))
	return b.String()
}

// render shows a message as raw HTTP with a decoded, truncated body, masking
// secrets when that option is on.
func (s *Server) render(m proxy.Message, limit int) string {
	head, _, _ := splitMessage(string(m.Raw))
	body, enc := proxy.DecodeBody(m.Headers, m.Body)
	var bodyText string
	switch {
	case len(body) == 0:
	case !utf8.Valid(body) || strings.ContainsRune(string(body), 0):
		bodyText = fmt.Sprintf("[binary body, %d bytes]", len(body))
	default:
		bodyText = string(body)
		if len(bodyText) > limit {
			bodyText = bodyText[:limit] + fmt.Sprintf("\n[... truncated, %d bytes total]", len(body))
		}
	}
	if enc != "" {
		head += fmt.Sprintf("\r\n[body shown decoded from %s]", enc)
	}
	out := head + "\r\n\r\n" + bodyText
	if s.opts().Mask {
		out = s.secrets.maskMessage(out)
	}
	return out
}

func (s *Server) maskTarget(target string) string {
	if !s.opts().Mask {
		return target
	}
	if path, q, ok := strings.Cut(target, "?"); ok {
		return path + "?" + s.secrets.maskQuery(q)
	}
	return target
}

func (s *Server) getSitemap(args json.RawMessage) toolResult {
	var a struct {
		Host string `json:"host"`
	}
	_ = json.Unmarshal(args, &a)
	var b strings.Builder
	for _, root := range sitemap.Build(s.deps.Store.Snapshot()) {
		if a.Host != "" && !hostMatches(hostOnly(strings.TrimPrefix(strings.TrimPrefix(root.Name, "https://"), "http://")), a.Host) {
			continue
		}
		writeNode(&b, root, 0)
	}
	if b.Len() == 0 {
		return textResult("The site map is empty: nothing matching has been captured yet.")
	}
	return textResult("%s", b.String())
}

func writeNode(b *strings.Builder, n *sitemap.Node, depth int) {
	b.WriteString(strings.Repeat("  ", depth))
	b.WriteString(n.Name)
	if n.Method != "" {
		fmt.Fprintf(b, "  [%s -> %d, flow #%d]", n.Method, n.StatusCode, n.FlowID)
	}
	fmt.Fprintf(b, "  (%d hit%s)\n", n.Count, plural(n.Count))
	for _, c := range n.Children {
		writeNode(b, c, depth+1)
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (s *Server) listFindings() toolResult {
	fs := s.deps.Scanner.Findings()
	if len(fs) == 0 {
		return textResult("No findings yet.")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d finding%s:\n", len(fs), plural(len(fs)))
	for _, f := range fs {
		src := ""
		if f.Source == "ai" {
			src = " [AI]"
		}
		flow := ""
		if f.FlowID != 0 {
			flow = fmt.Sprintf(" (flow #%d)", f.FlowID)
		}
		fmt.Fprintf(&b, "[%s] %s on %s%s%s: %s\n", strings.ToUpper(string(f.Severity)), f.Title, f.Host, flow, src, f.Detail)
	}
	return textResult("%s", b.String())
}

func (s *Server) getScope() toolResult {
	o := s.opts()
	var b strings.Builder
	hosts := s.deps.ScopeHosts()
	if s.deps.Scope() == nil || len(hosts) == 0 {
		b.WriteString("No targets are set, so no requests may be sent. Ask the user to add the site under CA / Settings → Targets in Kanca.\n")
	} else {
		fmt.Fprintf(&b, "Targets (a bare domain also covers its subdomains): %s\n", strings.Join(hosts, ", "))
	}
	if o.Level == LevelReadWrite {
		fmt.Fprintf(&b, "Access: read all captured traffic; send requests and scan targets only. Requests left this session: %d.\n", s.budget(o)-s.Sent())
	} else {
		b.WriteString("Access: read-only. You can analyse traffic and record findings but not send requests.\n")
	}
	if o.Mask {
		b.WriteString("Secrets are masked as [[KANCA_SECRET_n]]; send them back unchanged and Kanca substitutes the real values.\n")
	}
	return textResult("%s", b.String())
}

func (s *Server) budget(o Options) int {
	if o.Budget > 0 {
		return o.Budget
	}
	return DefaultBudget
}

// allowed checks that the assistant may send traffic to host.
func (s *Server) allowed(host string) (string, bool) {
	if s.opts().Level != LevelReadWrite {
		return "Kanca gives you read-only access, so requests can't be sent. The user can allow it in CA / Settings → AI assistant.", false
	}
	inScope := s.deps.Scope()
	if inScope == nil {
		return "No targets are set. Ask the user to add the site under CA / Settings → Targets in Kanca before testing.", false
	}
	if !inScope(hostOnly(host)) {
		return fmt.Sprintf("%s is not one of the user's targets (%s); only targets may be tested.", hostOnly(host), strings.Join(s.deps.ScopeHosts(), ", ")), false
	}
	return "", true
}

func (s *Server) sendRequest(args json.RawMessage) toolResult {
	var a struct {
		Raw      string `json:"raw"`
		FromFlow int64  `json:"from_flow_id"`
		Scheme   string `json:"scheme"`
		Host     string `json:"host"`
		MaxBody  *int   `json:"max_body_bytes"`
	}
	if err := json.Unmarshal(args, &a); err != nil || strings.TrimSpace(a.Raw) == "" {
		return errorResult("raw (the full HTTP request) is required")
	}
	raw := normalizeRaw(s.secrets.unmask(a.Raw))
	scheme, host := a.Scheme, a.Host
	if a.FromFlow != 0 {
		base, ok := s.deps.Store.Get(a.FromFlow)
		if !ok {
			return errorResult("flow #%d not found", a.FromFlow)
		}
		if scheme == "" {
			scheme = base.Scheme
		}
		if host == "" {
			host = base.Host
		}
	}
	if host == "" {
		host, _, _ = strings.Cut(headerValue(strings.SplitN(string(raw), "\r\n\r\n", 2)[0], "Host"), " ")
	}
	if scheme == "" {
		scheme = "https"
	}
	if host == "" {
		return errorResult("can't tell which host to send to: add a Host header or the host argument")
	}
	if !strings.Contains(host, ":") || strings.HasSuffix(host, "]") {
		port := "443"
		if scheme == "http" {
			port = "80"
		}
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	if msg, ok := s.allowed(host); !ok {
		return errorResult("%s", msg)
	}
	o := s.opts()
	s.mu.Lock()
	if s.sent >= s.budget(o) {
		s.mu.Unlock()
		return errorResult("request budget for this session (%d) is used up; the user can reset it by turning AI access off and on", s.budget(o))
	}
	s.sent++
	s.mu.Unlock()

	f := s.deps.Send(raw, scheme, host)
	f.Highlight = aiHighlight
	f.Comment = aiComment
	s.deps.Store.Add(f)
	if f.Error != "" {
		return errorResult("request failed (recorded as flow #%d): %s", f.ID, f.Error)
	}
	return textResult("Recorded as flow #%d.\n\n--- Response ---\n%s", f.ID, s.render(f.Response, maxBody(a.MaxBody)))
}

// normalizeRaw makes a hand-written request parseable: CRLF line endings in
// the head and a Content-Length that matches the body.
func normalizeRaw(raw string) []byte {
	var head, body string
	if h, bd, ok := strings.Cut(raw, "\r\n\r\n"); ok {
		head, body = h, bd
	} else if h, bd, ok := strings.Cut(raw, "\n\n"); ok {
		head, body = h, bd
	} else {
		head = strings.TrimRight(raw, "\r\n")
	}
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	out := []string{strings.TrimSpace(lines[0])}
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if k, _, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			continue
		}
		out = append(out, l)
	}
	method, _, _ := strings.Cut(out[0], " ")
	if body != "" || method == "POST" || method == "PUT" || method == "PATCH" {
		out = append(out, fmt.Sprintf("Content-Length: %d", len(body)))
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n\r\n" + body)
}

func (s *Server) activeScan(args json.RawMessage) toolResult {
	var a struct {
		FlowID     int64 `json:"flow_id"`
		Aggressive bool  `json:"aggressive"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return errorResult("invalid arguments: %v", err)
	}
	f, ok := s.deps.Store.Get(a.FlowID)
	if !ok {
		return errorResult("flow #%d not found", a.FlowID)
	}
	if msg, ok := s.allowed(f.Host); !ok {
		return errorResult("%s", msg)
	}
	// Every probe counts against the session's request budget.
	limit := s.budget(s.opts())
	used, stopped := 0, false
	beforeSend := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.sent >= limit {
			stopped = true
			return false
		}
		s.sent++
		used++
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	found, err := activescan.Run(ctx, activescan.Config{
		Scheme: f.Scheme, Host: f.Host, Raw: f.Request.Raw,
		InsecureUpstream: true, Aggressive: a.Aggressive, BeforeSend: beforeSend,
	})
	if err != nil {
		if stopped {
			return errorResult("request budget for this session (%d) is used up; the user can reset it by turning AI access off and on", limit)
		}
		return errorResult("active scan failed: %v", err)
	}
	s.mu.Lock()
	cost := fmt.Sprintf("%d requests; %d left this session", used, limit-s.sent)
	if stopped {
		cost += "; stopped early because the request budget ran out"
	}
	s.mu.Unlock()
	if len(found) == 0 {
		return textResult("Active scan of flow #%d found nothing (%s).", a.FlowID, cost)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Active scan of flow #%d found %d lead(s) (%s), added to Kanca's Findings:\n", a.FlowID, len(found), cost)
	for _, fnd := range found {
		fnd.FlowID = a.FlowID
		s.deps.Scanner.Add(fnd)
		fmt.Fprintf(&b, "[%s] %s: %s\n", strings.ToUpper(string(fnd.Severity)), fnd.Title, fnd.Detail)
	}
	return textResult("%s", b.String())
}

func (s *Server) addFinding(args json.RawMessage) toolResult {
	var a struct {
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Detail   string `json:"detail"`
		FlowID   int64  `json:"flow_id"`
		Host     string `json:"host"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return errorResult("invalid arguments: %v", err)
	}
	sev := scanner.Severity(strings.ToLower(a.Severity))
	switch sev {
	case scanner.Info, scanner.Low, scanner.Medium, scanner.High:
	default:
		return errorResult("severity must be info, low, medium or high")
	}
	if strings.TrimSpace(a.Title) == "" || strings.TrimSpace(a.Detail) == "" {
		return errorResult("title and detail are required")
	}
	fnd := scanner.Finding{Severity: sev, Title: a.Title, Detail: a.Detail, Host: a.Host, Source: "ai"}
	if a.FlowID != 0 {
		f, ok := s.deps.Store.Get(a.FlowID)
		if !ok {
			return errorResult("flow #%d not found", a.FlowID)
		}
		fnd.FlowID, fnd.Host, fnd.URL = f.ID, f.Host, f.URL
	}
	if fnd.Host == "" {
		return errorResult("give flow_id (preferred) or host")
	}
	if !s.deps.Scanner.Add(fnd) {
		return textResult("A finding with this severity and title already exists for %s.", fnd.Host)
	}
	return textResult("Recorded \"%s\" (%s) in Kanca's Findings for the user to review.", a.Title, sev)
}

func hostOnly(authority string) string {
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return h
	}
	return strings.Trim(authority, "[]")
}

func hostMatches(host, want string) bool {
	return scope.Matches(strings.ToLower(host), strings.ToLower(hostOnly(want)))
}
