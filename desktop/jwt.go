package main

import (
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

// SignJWT rebuilds a token from JSON-encoded header/payload with an explicit
// algorithm and an HMAC secret. alg is authoritative and is written into the
// header, so the UI selector cannot drift from the signed bytes. alg "none"
// produces an unsigned token for accept-none probing against systems the
// operator may test.
func (a *App) SignJWT(headerJSON, payloadJSON, alg, secret string) (string, error) {
	return kjwt.Sign([]byte(headerJSON), []byte(payloadJSON), alg, []byte(secret))
}

// VerifyJWT checks an HMAC token against a secret.
func (a *App) VerifyJWT(token, secret string) (bool, error) {
	return kjwt.Verify(token, []byte(secret))
}
