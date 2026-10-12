package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
	"github.com/gorkemguler/kanca/internal/scope"
)

// fixture is a Server over a real history store and scanner, with a backend
// that echoes what it receives and reflects ?q= (an XSS-style sink).
type fixture struct {
	srv     *Server
	store   *history.Store
	scanner *scanner.Scanner
	backend *httptest.Server
	host    string // backend host:port
	opts    Options
	scope   []string
	got     chan *http.Request
	gotBody chan string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fx := &fixture{
		store:   history.New(0),
		scanner: scanner.New(),
		opts:    Options{Level: LevelReadWrite, Mask: true},
		got:     make(chan *http.Request, 16),
		gotBody: make(chan string, 16),
	}
	fx.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fx.got <- r
		fx.gotBody <- string(b)
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "s3cr3t-session", HttpOnly: true})
		fmt.Fprintf(w, "<p>hello %s</p>", r.URL.Query().Get("q"))
	}))
	t.Cleanup(fx.backend.Close)
	fx.host = strings.TrimPrefix(fx.backend.URL, "http://")
	fx.scope = []string{"127.0.0.1"}
	fx.srv = NewServer(Deps{
		Store:      fx.store,
		Scanner:    fx.scanner,
		Scope:      func() func(string) bool { return scope.Matcher(fx.scope) },
		ScopeHosts: func() []string { return fx.scope },
		Version:    "test",
	}, func() Options { return fx.opts })
	return fx
}

// capture sends a request to the backend and records it like the proxy would.
func (fx *fixture) capture(t *testing.T, raw string) *proxy.Flow {
	t.Helper()
	f := proxy.NewSender(proxy.SenderConfig{}).Send(context.Background(), []byte(raw), "http", fx.host)
	if f.Error != "" {
		t.Fatalf("capture: %s", f.Error)
	}
	fx.store.Add(f)
	<-fx.got
	<-fx.gotBody
	return f
}

func (fx *fixture) call(t *testing.T, tool string, args any) (string, bool) {
	t.Helper()
	a, _ := json.Marshal(args)
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": json.RawMessage(a)}})
	out, ok := fx.srv.HandleMessage(msg)
	if !ok {
		t.Fatal("tools/call treated as a notification")
	}
	var resp struct {
		Result toolResult `json:"result"`
		Error  *rpcError  `json:"error"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if resp.Error != nil {
		t.Fatalf("%s: rpc error %d %s", tool, resp.Error.Code, resp.Error.Message)
	}
	return resp.Result.Content[0]["text"], resp.Result.IsError
}

func rpc(t *testing.T, s *Server, method string, params any) map[string]any {
	t.Helper()
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
	out, ok := s.HandleMessage(msg)
	if !ok {
		t.Fatalf("%s treated as a notification", method)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	return m
}

func TestInitializeNegotiatesVersionAndListsTools(t *testing.T) {
	fx := newFixture(t)
	res := rpc(t, fx.srv, "initialize", map[string]any{"protocolVersion": "2025-06-18"})["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocolVersion = %v", res["protocolVersion"])
	}
	if !strings.Contains(res["instructions"].(string), "Target scope") {
		t.Fatal("instructions should explain scope")
	}
	res = rpc(t, fx.srv, "initialize", map[string]any{"protocolVersion": "1999-01-01"})["result"].(map[string]any)
	if res["protocolVersion"] != supportedVersions[0] {
		t.Fatalf("unknown version should fall back to latest, got %v", res["protocolVersion"])
	}
	tools := rpc(t, fx.srv, "tools/list", nil)["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 8 {
		t.Fatalf("tools = %d, want 8", len(tools))
	}
	if errObj := rpc(t, fx.srv, "nope", nil)["error"].(map[string]any); errObj["code"].(float64) != -32601 {
		t.Fatalf("unknown method error = %v", errObj)
	}
	if _, isRequest := fx.srv.HandleMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); isRequest {
		t.Fatal("a notification must not get a reply")
	}
}

func TestHandlerRequiresTokenAndLoopbackOrigin(t *testing.T) {
	fx := newFixture(t)
	ts := httptest.NewServer(fx.srv.Handler("tok"))
	defer ts.Close()
	post := func(auth, origin, body string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	for name, tc := range map[string]struct {
		auth, origin, body string
		want               int
	}{
		"no token":        {"", "", ping, 401},
		"wrong token":     {"Bearer nope", "", ping, 401},
		"foreign origin":  {"Bearer tok", "https://evil.example", ping, 403},
		"ok":              {"Bearer tok", "", ping, 200},
		"local origin ok": {"Bearer tok", "http://localhost:6274", ping, 200},
		"notification":    {"Bearer tok", "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202},
	} {
		if got := post(tc.auth, tc.origin, tc.body); got != tc.want {
			t.Errorf("%s: status %d, want %d", name, got, tc.want)
		}
	}
	resp, _ := http.Get(ts.URL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status %d", resp.StatusCode)
	}
}

func TestReadToolsMaskSecrets(t *testing.T) {
	fx := newFixture(t)
	f := fx.capture(t, "POST /login?q=x HTTP/1.1\r\nHost: "+fx.host+"\r\nCookie: PHPSESSID=abc123\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 30\r\n\r\nusername=ayse&password=hunter2")

	list, isErr := fx.call(t, "list_flows", map[string]any{})
	if isErr || !strings.Contains(list, fmt.Sprintf("#%d POST", f.ID)) {
		t.Fatalf("list_flows:\n%s", list)
	}

	text, _ := fx.call(t, "get_flow", map[string]any{"id": f.ID})
	for _, secret := range []string{"abc123", "hunter2", "s3cr3t-session"} {
		if strings.Contains(text, secret) {
			t.Errorf("get_flow leaked %q:\n%s", secret, text)
		}
	}
	for _, kept := range []string{"username=ayse", "HttpOnly", "PHPSESSID=[[KANCA_SECRET_"} {
		if !strings.Contains(text, kept) {
			t.Errorf("get_flow lost %q:\n%s", kept, text)
		}
	}

	fx.opts.Mask = false
	if text, _ := fx.call(t, "get_flow", map[string]any{"id": f.ID}); !strings.Contains(text, "hunter2") {
		t.Errorf("with masking off the raw value should show:\n%s", text)
	}
}

func TestSendRequestRestoresSecretsAndRecordsFlow(t *testing.T) {
	fx := newFixture(t)
	f := fx.capture(t, "GET /?q=hi HTTP/1.1\r\nHost: "+fx.host+"\r\nCookie: PHPSESSID=abc123\r\n\r\n")
	shown, _ := fx.call(t, "get_flow", map[string]any{"id": f.ID})
	placeholder := shown[strings.Index(shown, "[[KANCA_SECRET_"):]
	placeholder = placeholder[:strings.Index(placeholder, "]]")+2]

	// Bare-LF lines and a body without Content-Length, as a model might write.
	raw := "POST /?q=again HTTP/1.1\nHost: " + fx.host + "\nCookie: PHPSESSID=" + placeholder + "\n\nhello=world"
	text, isErr := fx.call(t, "send_request", map[string]any{"raw": raw, "from_flow_id": f.ID})
	if isErr {
		t.Fatalf("send_request failed: %s", text)
	}
	got := <-fx.got
	if c, _ := got.Cookie("PHPSESSID"); c == nil || c.Value != "abc123" {
		t.Fatalf("backend got cookie %v, want the real value", got.Header.Get("Cookie"))
	}
	if body := <-fx.gotBody; body != "hello=world" {
		t.Fatalf("backend got body %q", body)
	}
	if !strings.Contains(text, "hello again") {
		t.Fatalf("response not returned:\n%s", text)
	}
	var sent *proxy.Flow
	for _, fl := range fx.store.Snapshot() {
		if fl.Highlight == aiHighlight {
			sent = fl
		}
	}
	if sent == nil || sent.Comment != aiComment {
		t.Fatal("the request should be recorded in history and marked as sent by AI")
	}
}

func TestActivityRecordsEachToolCall(t *testing.T) {
	fx := newFixture(t)
	var seen []Activity
	fx.srv.deps.OnActivity = func(a Activity) { seen = append(seen, a) }
	f := fx.capture(t, "GET /?q=hi HTTP/1.1\r\nHost: "+fx.host+"\r\n\r\n")

	fx.call(t, "get_flow", map[string]any{"id": f.ID})
	fx.call(t, "send_request", map[string]any{"raw": "GET /?q=two HTTP/1.1\r\nHost: " + fx.host + "\r\n\r\n", "scheme": "http"})
	<-fx.got
	<-fx.gotBody
	fx.opts.Level = LevelRead
	fx.call(t, "send_request", map[string]any{"raw": "GET / HTTP/1.1\r\nHost: " + fx.host + "\r\n\r\n", "scheme": "http"})

	log := fx.srv.Activity()
	if len(log) != 3 || len(seen) != 3 {
		t.Fatalf("want 3 activities (log %d, callbacks %d)", len(log), len(seen))
	}
	if log[0].Action != fmt.Sprintf("Read flow #%d", f.ID) || log[0].Error {
		t.Errorf("get_flow activity: %+v", log[0])
	}
	if log[1].Action != "Sent GET /?q=two to "+fx.host || !strings.HasPrefix(log[1].Result, "Recorded as flow #") {
		t.Errorf("send_request activity: %+v", log[1])
	}
	if !log[2].Error || !strings.Contains(log[2].Result, "read-only") {
		t.Errorf("refused call should be logged as an error: %+v", log[2])
	}
	if got := clip("ağaç", 2); got != "a…" {
		t.Errorf("clip split a rune: %q", got)
	}
}

func TestSendRequestGuards(t *testing.T) {
	fx := newFixture(t)
	raw := "GET / HTTP/1.1\r\nHost: " + fx.host + "\r\n\r\n"

	fx.opts.Level = LevelRead
	if text, isErr := fx.call(t, "send_request", map[string]any{"raw": raw, "scheme": "http"}); !isErr || !strings.Contains(text, "read-only") {
		t.Fatalf("read-only should refuse: %s", text)
	}
	fx.opts.Level = LevelReadWrite

	fx.scope = nil
	if text, isErr := fx.call(t, "send_request", map[string]any{"raw": raw, "scheme": "http"}); !isErr || !strings.Contains(text, "No Target scope") {
		t.Fatalf("no scope should refuse: %s", text)
	}
	fx.scope = []string{"example.com"}
	if text, isErr := fx.call(t, "send_request", map[string]any{"raw": raw, "scheme": "http"}); !isErr || !strings.Contains(text, "outside the Target scope") {
		t.Fatalf("out-of-scope should refuse: %s", text)
	}
	select {
	case r := <-fx.got:
		t.Fatalf("a refused request reached the backend: %s", r.URL)
	default:
	}

	fx.scope = []string{"127.0.0.1"}
	fx.opts.Budget = 1
	if _, isErr := fx.call(t, "send_request", map[string]any{"raw": raw, "scheme": "http"}); isErr {
		t.Fatal("first request within budget should succeed")
	}
	<-fx.got
	<-fx.gotBody
	if text, isErr := fx.call(t, "send_request", map[string]any{"raw": raw, "scheme": "http"}); !isErr || !strings.Contains(text, "budget") {
		t.Fatalf("over budget should refuse: %s", text)
	}
}

func TestActiveScanAndFindings(t *testing.T) {
	fx := newFixture(t)
	f := fx.capture(t, "GET /?q=hi HTTP/1.1\r\nHost: "+fx.host+"\r\n\r\n")
	go func() { // drain probes
		for range fx.got {
			<-fx.gotBody
		}
	}()

	text, isErr := fx.call(t, "active_scan", map[string]any{"flow_id": f.ID})
	if isErr || !strings.Contains(text, "Reflected input in q") {
		t.Fatalf("active_scan:\n%s", text)
	}
	// Probes are charged to the request budget.
	if fx.srv.Sent() < 2 || !strings.Contains(text, fmt.Sprintf("%d requests; %d left", fx.srv.Sent(), DefaultBudget-fx.srv.Sent())) {
		t.Fatalf("scan used %d requests but reported:\n%s", fx.srv.Sent(), text)
	}
	fx.opts.Budget = fx.srv.Sent() + 1
	if text, _ := fx.call(t, "active_scan", map[string]any{"flow_id": f.ID}); !strings.Contains(text, "stopped early") {
		t.Fatalf("a scan that runs out of budget should say so:\n%s", text)
	}
	if text, isErr := fx.call(t, "active_scan", map[string]any{"flow_id": f.ID}); !isErr || !strings.Contains(text, "used up") {
		t.Fatalf("a scan with no budget left should be refused:\n%s", text)
	}

	text, isErr = fx.call(t, "add_finding", map[string]any{"severity": "high", "title": "IDOR in id", "detail": "flow 1 vs 2", "flow_id": f.ID})
	if isErr {
		t.Fatalf("add_finding: %s", text)
	}
	if text, _ := fx.call(t, "add_finding", map[string]any{"severity": "high", "title": "IDOR in id", "detail": "again", "flow_id": f.ID}); !strings.Contains(text, "already exists") {
		t.Fatalf("duplicate finding: %s", text)
	}
	if _, isErr := fx.call(t, "add_finding", map[string]any{"severity": "critical", "title": "x", "detail": "y", "flow_id": f.ID}); !isErr {
		t.Fatal("unknown severity should be rejected")
	}
	var ai bool
	for _, fnd := range fx.scanner.Findings() {
		if fnd.Source == "ai" && fnd.FlowID == f.ID {
			ai = true
		}
	}
	if !ai {
		t.Fatal("AI finding not recorded with source ai")
	}
	if list, _ := fx.call(t, "list_findings", map[string]any{}); !strings.Contains(list, "IDOR in id") || !strings.Contains(list, "[AI]") {
		t.Fatalf("list_findings:\n%s", list)
	}
}

func TestSecretBoxMasksAndRestores(t *testing.T) {
	b := newSecretBox()
	raw := "POST /api?token=abc&page=2 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\r\nX-Api-Key: k-1\r\nContent-Type: application/json\r\n\r\n{\"user\":{\"name\":\"a\",\"password\":\"p@ss\"}}"
	masked := b.maskMessage(raw)
	for _, secret := range []string{"token=abc", "eyJhbGci", "k-1", "p@ss"} {
		if strings.Contains(masked, secret) {
			t.Errorf("leaked %q in:\n%s", secret, masked)
		}
	}
	for _, kept := range []string{"page=2", "Authorization: Bearer [[KANCA_SECRET_", `"name":"a"`} {
		if !strings.Contains(masked, kept) {
			t.Errorf("lost %q in:\n%s", kept, masked)
		}
	}
	if again := b.maskMessage(raw); again != masked {
		t.Error("the same secret must always get the same placeholder")
	}
	if !strings.Contains(b.unmask(masked), "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig") {
		t.Error("unmask should restore the original token")
	}
	if got := b.unmask("[[KANCA_SECRET_999]]"); got != "[[KANCA_SECRET_999]]" {
		t.Errorf("unknown placeholder changed to %q", got)
	}
}

func TestNormalizeRaw(t *testing.T) {
	got := string(normalizeRaw("POST /x HTTP/1.1\nHost: a\nContent-Length: 99\n\nab"))
	if got != "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nab" {
		t.Fatalf("normalizeRaw = %q", got)
	}
	if got := string(normalizeRaw("GET / HTTP/1.1\r\nHost: a")); got != "GET / HTTP/1.1\r\nHost: a\r\n\r\n" {
		t.Fatalf("GET without blank line = %q", got)
	}
}

func TestConfigDefaultsAndPersistence(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled || c.Level != LevelReadWrite || !c.Mask || c.Addr != DefaultAddr || len(c.Token) != 64 {
		t.Fatalf("defaults = %+v", c)
	}
	c.Enabled = true
	if err := SaveConfig(dir, c); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "mcp.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, want 0600 (it holds the token)", st.Mode().Perm())
	}
	again, _ := LoadConfig(dir)
	if again != c {
		t.Fatalf("reloaded %+v, want %+v", again, c)
	}
}

func TestServiceOnlyListensOnLoopback(t *testing.T) {
	svc := &Service{Server: newFixture(t).srv}
	if err := svc.Start("0.0.0.0:0", "t"); err == nil {
		t.Fatal("must refuse a non-loopback address")
	}
	if err := svc.Start("127.0.0.1:0", "t"); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()
	if svc.Addr() == "" {
		t.Fatal("no address after Start")
	}
}

func TestStdioBridgeForwardsToEndpoint(t *testing.T) {
	fx := newFixture(t)
	svc := &Service{Server: fx.srv}
	if err := svc.Start("127.0.0.1:0", "tok"); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()
	dir := t.TempDir()
	cfg := Config{Enabled: true, Level: LevelReadWrite, Mask: true, Addr: svc.Addr(), Token: "tok"}
	if err := SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
`)
	var out bytes.Buffer
	if err := RunStdioBridge(dir, in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"protocolVersion":"2025-06-18"`) || !strings.Contains(lines[1], "send_request") {
		t.Fatalf("bridge output:\n%s", out.String())
	}

	_ = svc.Stop()
	out.Reset()
	_ = RunStdioBridge(dir, strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"ping"}`+"\n"), &out)
	if !strings.Contains(out.String(), "isn't reachable") || !strings.Contains(out.String(), `"id":3`) {
		t.Fatalf("with Kanca down the bridge should answer the request with an explanation, got %s", out.String())
	}
}
