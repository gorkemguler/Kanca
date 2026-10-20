// Package jwt decodes, verifies and forges JSON Web Tokens for authorised
// testing — inspecting what a token carries, re-signing it with a known
// secret, or stripping the signature to probe "none"-algorithm acceptance.
// Standard library only.
package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

// maxTokenBytes caps the token size Decode will parse.
const maxTokenBytes = 64 << 10

// Token is a decoded JWT.
type Token struct {
	Header  map[string]any `json:"header"`
	Payload map[string]any `json:"payload"`
	// HeaderJSON/PayloadJSON hold the decoded JSON exactly as it appeared in
	// the token. The maps above decode numbers as json.Number, but a webview
	// re-decodes them as IEEE-754 doubles; round-tripping these strings keeps
	// 64-bit claims (subject IDs, timestamps, nonces) exact in the editor.
	HeaderJSON  string `json:"headerJson"`
	PayloadJSON string `json:"payloadJson"`
	Algorithm   string `json:"alg"`
	// SignedParts holds the two ASCII segments the signature covers.
	SignedParts [2]string `json:"-"`
	Signature   []byte    `json:"-"`
	Unsigned    bool      `json:"unsigned"`
}

// Decode parses token without verifying the signature. Three dot-separated
// parts are required; "none"-algorithm tokens may carry an empty signature.
func Decode(token string) (*Token, error) {
	if len(token) > maxTokenBytes {
		return nil, errors.New("jwt: token exceeds 64 KiB")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: want 3 parts, got %d", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad header encoding: %w", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad payload encoding: %w", err)
	}
	var header, payload map[string]any
	if err := unmarshalObject(hb, &header); err != nil {
		return nil, fmt.Errorf("jwt: bad header JSON: %w", err)
	}
	if err := unmarshalObject(pb, &payload); err != nil {
		return nil, fmt.Errorf("jwt: bad payload JSON: %w", err)
	}
	alg, _ := header["alg"].(string)
	if alg == "" {
		return nil, errors.New("jwt: header has no alg")
	}
	t := &Token{
		Header: header, Payload: payload,
		HeaderJSON: string(hb), PayloadJSON: string(pb), Algorithm: alg,
	}
	t.SignedParts = [2]string{parts[0], parts[1]}
	if parts[2] == "" {
		t.Unsigned = true
		if !strings.EqualFold(alg, "none") {
			return nil, errors.New("jwt: empty signature with non-none alg")
		}
		return t, nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad signature encoding: %w", err)
	}
	t.Signature = sig
	return t, nil
}

// hashFor maps HMAC algs to constructors. Asymmetric algs (RS/ES/PS) need key
// handling the UI does not offer; they decode fine but cannot be forged here.
func hashFor(alg string) (func() hash.Hash, error) {
	switch strings.ToUpper(alg) {
	case "HS256":
		return sha256.New, nil
	case "HS384":
		return sha512.New384, nil
	case "HS512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("jwt: cannot forge alg %q (HMAC only)", alg)
	}
}

// unmarshalObject decodes exactly one JSON object, rejecting trailing data.
// Numbers stay as json.Number so a 64-bit claim is not silently rounded.
func unmarshalObject(data []byte, dst *map[string]any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("unexpected data after JSON object")
		}
		return err
	}
	if *dst == nil {
		return errors.New("want a JSON object")
	}
	return nil
}

// Sign builds a token from raw header/payload JSON objects and an explicit
// algorithm with an HMAC secret. alg is written into the header, so the
// signed header and the signature can never disagree. alg "none" produces an
// unsigned token (for probing accept-none flaws). Raw JSON is decoded with
// json.Number, preserving 64-bit numeric claims exactly.
func Sign(headerJSON, payloadJSON []byte, alg string, secret []byte) (string, error) {
	alg = strings.TrimSpace(alg)
	if alg == "" {
		return "", errors.New("jwt: no alg selected")
	}
	var header, payload map[string]any
	if err := unmarshalObject(headerJSON, &header); err != nil {
		return "", fmt.Errorf("jwt: bad header JSON: %w", err)
	}
	if err := unmarshalObject(payloadJSON, &payload); err != nil {
		return "", fmt.Errorf("jwt: bad payload JSON: %w", err)
	}
	header["alg"] = alg
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jwt: marshal header: %w", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("jwt: marshal payload: %w", err)
	}
	head, body := base64.RawURLEncoding.EncodeToString(hb), base64.RawURLEncoding.EncodeToString(pb)
	if strings.EqualFold(alg, "none") {
		return head + "." + body + ".", nil
	}
	hf, err := hashFor(alg)
	if err != nil {
		return "", err
	}
	mac := hmac.New(hf, secret)
	mac.Write([]byte(head + "." + body))
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Verify checks an HMAC token's signature against secret. Unsigned tokens
// never verify (use Decode to inspect them).
func Verify(token string, secret []byte) (bool, error) {
	t, err := Decode(token)
	if err != nil {
		return false, err
	}
	if t.Unsigned {
		return false, nil
	}
	hf, err := hashFor(t.Algorithm)
	if err != nil {
		return false, err
	}
	mac := hmac.New(hf, secret)
	mac.Write([]byte(t.SignedParts[0] + "." + t.SignedParts[1]))
	return hmac.Equal(mac.Sum(nil), t.Signature), nil
}
