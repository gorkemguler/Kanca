package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const testSecret = "kanca-test-secret"

// hsSample is built at test time (never hardcode a "known-good" token whose
// bytes could drift with JSON key order; round-trip instead).
func mustSign(t *testing.T, alg string, payload map[string]any) string {
	t.Helper()
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	tok, err := Sign([]byte(`{"alg":"`+alg+`","typ":"JWT"}`), pb, alg, []byte(testSecret))
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
	tok, err := Sign([]byte(`{"typ":"JWT"}`), []byte(`{"admin":true}`), "none", nil)
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
	if _, err := Sign([]byte(`{}`), []byte(`{}`), "RS256", []byte("s")); err == nil {
		t.Fatal("Sign(RS256) should refuse (no key handling here)")
	}
}

func TestSignRejectsEmptyAlg(t *testing.T) {
	if _, err := Sign([]byte(`{"alg":"HS256"}`), []byte(`{}`), " ", []byte("s")); err == nil {
		t.Fatal("Sign accepted an empty alg")
	}
}

func TestLargeIntegerClaimsSurviveRoundTrip(t *testing.T) {
	// 9007199254740993 is 2^53+1: a float64 cannot represent it, so this claim
	// is the canary for precision loss on decode/re-sign.
	payloadJSON := `{"sub":9007199254740993,"nested":{"id":18446744073709551615}}`
	tok, err := Sign([]byte(`{"typ":"JWT"}`), []byte(payloadJSON), "HS256", []byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	dec, err := Decode(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(dec.PayloadJSON, `"sub":9007199254740993`) ||
		!strings.Contains(dec.PayloadJSON, `"id":18446744073709551615`) {
		t.Fatalf("payload JSON lost digits: %q", dec.PayloadJSON)
	}
	sub, ok := dec.Payload["sub"].(json.Number)
	if !ok || sub.String() != "9007199254740993" {
		t.Fatalf("sub lost precision: %#v", dec.Payload["sub"])
	}
	nested, ok := dec.Payload["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested not an object: %#v", dec.Payload["nested"])
	}
	id, ok := nested["id"].(json.Number)
	if !ok || id.String() != "18446744073709551615" {
		t.Fatalf("nested id lost precision: %#v", nested["id"])
	}
	// Re-sign the decoded raw payload: the bytes must stay identical.
	signedPayload := dec.PayloadJSON
	re, err := Sign([]byte(dec.HeaderJSON), []byte(signedPayload), "HS256", []byte(testSecret))
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	parts := strings.Split(re, ".")
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	if string(got) != signedPayload {
		t.Fatalf("re-signed payload drifted: %s", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
