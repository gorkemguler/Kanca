package main

import (
	"encoding/json"
	"fmt"

	kjwt "github.com/gorkemguler/kanca/internal/jwt"
)

// DecodeJWT parses a token for inspection. It never verifies.
func (a *App) DecodeJWT(token string) (kjwt.Token, error) {
	t, err := kjwt.Decode(token)
	if err != nil {
		return kjwt.Token{}, err
	}
	return *t, nil
}

// SignJWT rebuilds a token from JSON-encoded header/payload with an HMAC
// secret. Header alg "none" produces an unsigned token for accept-none
// probing against systems the operator may test.
func (a *App) SignJWT(headerJSON, payloadJSON, secret string) (string, error) {
	var header, payload map[string]any
	if err := json.Unmarshal([]byte(headerJSON), &header); err != nil {
		return "", fmt.Errorf("bad header JSON: %w", err)
	}
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return "", fmt.Errorf("bad payload JSON: %w", err)
	}
	return kjwt.Sign(header, payload, []byte(secret))
}

// VerifyJWT checks an HMAC token against a secret.
func (a *App) VerifyJWT(token, secret string) (bool, error) {
	return kjwt.Verify(token, []byte(secret))
}
