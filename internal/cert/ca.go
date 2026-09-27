// Package cert provides an on-the-fly certificate authority used by the
// intercepting proxy to present per-host leaf certificates that the user's
// browser trusts once the Mimlec root CA is installed.
//
// The root CA private key never leaves the user's machine. Leaf certificates
// are generated lazily per SNI host and cached in memory for the lifetime of
// the process.
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// rootValidity is how long a freshly minted root CA remains valid.
	rootValidity = 10 * 365 * 24 * time.Hour
	// leafValidity is how long each generated leaf certificate remains valid.
	// Kept short because leaves are cheap to regenerate and short lifetimes
	// limit the blast radius if one is ever exported.
	leafValidity = 90 * 24 * time.Hour
	// organization is embedded in generated certificates.
	organization   = "Mimlec Proxy"
	rootCommonName = "Mimlec Root CA"
)

// Authority is an in-memory certificate authority backed by a persisted root
// key pair. It is safe for concurrent use.
type Authority struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	rootPEM  []byte

	mu    sync.RWMutex
	cache map[string]*tls.Certificate

	// leafKey is a single reusable key shared by every leaf certificate.
	// Reusing one key avoids paying the key-generation cost on every new
	// host while keeping each leaf's identity (its SANs) distinct.
	leafKey *ecdsa.PrivateKey

	serial uint64
}

// NewAuthority loads a root CA from dir, generating and persisting a new one
// when none exists yet. The files created are ca-cert.pem and ca-key.pem.
func NewAuthority(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cert: create dir: %w", err)
	}
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		a, err := authorityFromPEM(certPEM, keyPEM)
		if err == nil {
			return a, nil
		}
		// Fall through and regenerate if the stored pair is unusable.
	}

	a, err := generateAuthority()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, a.rootPEM, 0o644); err != nil {
		return nil, fmt.Errorf("cert: write ca cert: %w", err)
	}
	keyOut, err := marshalECKey(a.rootKey)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return nil, fmt.Errorf("cert: write ca key: %w", err)
	}
	return a, nil
}

// NewEphemeralAuthority builds an in-memory authority that is never persisted.
// Useful for tests and for one-off sessions.
func NewEphemeralAuthority() (*Authority, error) {
	return generateAuthority()
}

func generateAuthority() (*Authority, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cert: generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   rootCommonName,
			Organization: []string{organization},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("cert: create root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cert: parse root cert: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cert: generate leaf key: %w", err)
	}
	return &Authority{
		rootCert: rootCert,
		rootKey:  rootKey,
		rootPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cache:    make(map[string]*tls.Certificate),
		leafKey:  leafKey,
	}, nil
}

func authorityFromPEM(certPEM, keyPEM []byte) (*Authority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("cert: invalid ca cert pem")
	}
	rootCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cert: parse ca cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("cert: invalid ca key pem")
	}
	rootKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cert: parse ca key: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cert: generate leaf key: %w", err)
	}
	return &Authority{
		rootCert: rootCert,
		rootKey:  rootKey,
		rootPEM:  pem.EncodeToMemory(certBlock),
		cache:    make(map[string]*tls.Certificate),
		leafKey:  leafKey,
	}, nil
}

// RootCertPEM returns the PEM-encoded root certificate, suitable for the user
// to import into their browser or OS trust store.
func (a *Authority) RootCertPEM() []byte {
	out := make([]byte, len(a.rootPEM))
	copy(out, a.rootPEM)
	return out
}

// CertForName returns a leaf certificate valid for the given host, generating
// and caching it on first use. host may be a DNS name or an IP literal.
func (a *Authority) CertForName(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)

	a.mu.RLock()
	if c, ok := a.cache[host]; ok {
		a.mu.RUnlock()
		return c, nil
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	// Re-check: another goroutine may have generated it while we waited.
	if c, ok := a.cache[host]; ok {
		return c, nil
	}

	leaf, err := a.newLeaf(host)
	if err != nil {
		return nil, err
	}
	a.cache[host] = leaf
	return leaf, nil
}

func (a *Authority) newLeaf(host string) (*tls.Certificate, error) {
	serial := a.nextSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{organization},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.rootCert, &a.leafKey.PublicKey, a.rootKey)
	if err != nil {
		return nil, fmt.Errorf("cert: create leaf for %q: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, a.rootCert.Raw},
		PrivateKey:  a.leafKey,
		Leaf:        mustParse(der),
	}, nil
}

// nextSerial derives a deterministic-yet-unique serial number. Callers hold
// a.mu. It combines a monotonic counter with time to avoid collisions across
// restarts that reuse the same root.
func (a *Authority) nextSerial() *big.Int {
	a.serial++
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint64(buf[8:16], a.serial)
	sum := sha256.Sum256(buf)
	n := new(big.Int).SetBytes(sum[:16])
	// Ensure positive.
	return n.Abs(n)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("cert: serial: %w", err)
	}
	return n, nil
}

func marshalECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("cert: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func mustParse(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		// A certificate we just created must parse; a failure here is a bug.
		panic("cert: parse just-created leaf: " + err.Error())
	}
	return c
}

// normalizeHost strips a trailing port and lowercases the host so cache keys
// and generated SANs are consistent.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Lowercase ASCII in place; hostnames are case-insensitive.
	b := []byte(host)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
