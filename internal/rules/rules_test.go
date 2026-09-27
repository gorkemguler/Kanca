package rules

import (
	"strings"
	"testing"
)

func TestReplaceHeader(t *testing.T) {
	s := NewSet()
	if _, err := s.Add(Rule{Name: "ua", Enabled: true, Phase: PhaseRequest, Part: PartHeaders,
		Match: `User-Agent: .*`, Replace: "User-Agent: mimlec"}); err != nil {
		t.Fatal(err)
	}
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n")
	out := string(s.Apply(PhaseRequest, "x", raw))
	if !strings.Contains(out, "User-Agent: mimlec") || strings.Contains(out, "curl/8") {
		t.Fatalf("header not replaced: %q", out)
	}
}

func TestReplaceBodyFixesContentLength(t *testing.T) {
	s := NewSet()
	s.Add(Rule{Name: "b", Enabled: true, Phase: PhaseResponse, Part: PartBody,
		Match: `admin`, Replace: "user"})
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nadmin")
	out := string(s.Apply(PhaseResponse, "x", raw))
	if !strings.Contains(out, "\r\n\r\nuser") {
		t.Fatalf("body not replaced: %q", out)
	}
	if !strings.Contains(out, "Content-Length: 4") {
		t.Fatalf("content-length not fixed: %q", out)
	}
}

func TestFirstLineAndPhaseIsolation(t *testing.T) {
	s := NewSet()
	s.Add(Rule{Name: "path", Enabled: true, Phase: PhaseRequest, Part: PartFirstLine,
		Match: `/old`, Replace: "/new"})
	raw := []byte("GET /old HTTP/1.1\r\nHost: x\r\n\r\n/old-in-body-should-stay")
	// Response phase must not touch a request-phase rule.
	if got := string(s.Apply(PhaseResponse, "x", raw)); got != string(raw) {
		t.Fatal("response phase applied a request rule")
	}
	out := string(s.Apply(PhaseRequest, "x", raw))
	if !strings.HasPrefix(out, "GET /new HTTP/1.1") {
		t.Fatalf("first line not replaced: %q", out)
	}
	if !strings.Contains(out, "/old-in-body-should-stay") {
		t.Fatalf("first-line rule leaked into body: %q", out)
	}
}

func TestHostScopingAndDisabled(t *testing.T) {
	s := NewSet()
	s.Add(Rule{Name: "h", Enabled: true, Phase: PhaseRequest, Part: PartHeaders,
		Match: `X: 1`, Replace: "X: 2", Host: "example.com"})
	s.Add(Rule{Name: "off", Enabled: false, Phase: PhaseRequest, Part: PartHeaders,
		Match: `Y: 1`, Replace: "Y: 2"})
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\nX: 1\r\nY: 1\r\n\r\n")
	// Out-of-scope host: host rule must not fire; disabled rule never fires.
	if got := string(s.Apply(PhaseRequest, "other.com", raw)); got != string(raw) {
		t.Fatalf("rule fired out of scope/disabled: %q", got)
	}
	// In-scope host: only the enabled host rule fires.
	out := string(s.Apply(PhaseRequest, "api.example.com", raw))
	if !strings.Contains(out, "X: 2") || !strings.Contains(out, "Y: 1") {
		t.Fatalf("scoped apply wrong: %q", out)
	}
}

func TestBadRegexpRejected(t *testing.T) {
	s := NewSet()
	if _, err := s.Add(Rule{Name: "bad", Enabled: true, Phase: PhaseRequest, Part: PartHeaders,
		Match: `(`, Replace: ""}); err == nil {
		t.Fatal("expected compile error for invalid regexp")
	}
}
