package jwt

import (
	"strings"
	"testing"
)

const testSecret = "kanca-test-secret"

// hsSample is built at test time (never hardcode a "known-good" token whose
// bytes could drift with JSON key order; round-trip instead).
func mustSign(t *testing.T, alg string, payload map[string]any) string {
	t.Helper()
	tok, err := Sign(map[string]any{"alg": alg, "typ": "JWT"}, payload, []byte(testSecret))
	if err != nil {
		t.Fatalf("sign %s: %v", alg, err)
	}
	return tok
}

func TestDecodeRoundTrip(t *testing.T) {
	tok := mustSign(t, "HS256", map[string]any{"sub": "123", "role": "user"})
	got, err := Decode(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Algorithm != "HS256" || got.Payload["role"] != "user" {
		t.Fatalf("decoded wrong: %+v", got)
	}
	if got.Unsigned {
		t.Fatal("signed token reported unsigned")
	}
}

func TestVerifyAcceptsAndRejects(t *testing.T) {
	tok := mustSign(t, "HS384", map[string]any{"sub": "1"})
	ok, err := Verify(tok, []byte(testSecret))
	if err != nil || !ok {
		t.Fatalf("verify good = %v, %v", ok, err)
	}
	ok, err = Verify(tok, []byte("wrong"))
	if err != nil {
		t.Fatalf("verify wrong secret errored: %v", err)
	}
	if ok {
		t.Fatal("verify accepted a wrong secret")
	}
	// Tampered payload must fail.
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + parts[1] + "x." + parts[2]
	if ok, _ := Verify(tampered, []byte(testSecret)); ok {
		t.Fatal("verify accepted a tampered payload")
	}
}

func TestNoneHandling(t *testing.T) {
	tok, err := Sign(map[string]any{"alg": "none"}, map[string]any{"admin": true}, nil)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if !strings.HasSuffix(tok, ".") {
		t.Fatalf("none token should end with a dot: %q", tok)
	}
	got, err := Decode(tok)
	if err != nil || !got.Unsigned {
		t.Fatalf("decode none = %+v, %v", got, err)
	}
	if ok, _ := Verify(tok, []byte(testSecret)); ok {
		t.Fatal("unsigned token verified")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!!!.e30.e30", strings.Repeat("x", maxTokenBytes+1)} {
		if _, err := Decode(bad); err == nil {
			t.Fatalf("Decode(%q) accepted garbage", bad[:min(8, len(bad))])
		}
	}
}

func TestSignRejectsAsymmetric(t *testing.T) {
	if _, err := Sign(map[string]any{"alg": "RS256"}, map[string]any{}, []byte("s")); err == nil {
		t.Fatal("Sign(RS256) should refuse (no key handling here)")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
