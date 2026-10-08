// Package trust adds the Kanca root CA to the current user's trust store, removes
// it again, and reports whether the operating system trusts the certificates
// Kanca issues. Installing is supported on macOS, where it goes through the
// system's own authorisation prompt; other platforms keep the manual steps.
package trust

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gorkemguler/kanca/internal/cert"
)

// ErrUnsupported is returned by Install and Remove where one-click install isn't
// available.
var ErrUnsupported = errors.New("installing the certificate automatically is only supported on macOS")

// ErrCancelled is returned when the user dismisses the system's authorisation
// prompt.
var ErrCancelled = errors.New("cancelled in the macOS authorisation prompt")

// Supported reports whether Install and Remove work on this platform.
func Supported() bool { return runtime.GOOS == "darwin" }

// checkHost is a name that never resolves; it only labels the probe certificate.
const checkHost = "trust-check.kanca.invalid"

// Trusted reports whether the operating system trusts a certificate issued by
// ca for a TLS server, using the platform verifier (on macOS the Security
// framework), i.e. the same answer Safari, Chrome and Edge get.
func Trusted(ca *cert.Authority) bool {
	return trustedWith(ca, nil)
}

// trustedWith verifies against roots, or the system verifier when roots is nil.
func trustedWith(ca *cert.Authority, roots *x509.CertPool) bool {
	root, err := rootCert(ca)
	if err != nil {
		return false
	}
	leaf, err := ca.CertForName(checkHost)
	if err != nil {
		return false
	}
	inter := x509.NewCertPool()
	inter.AddCert(root)
	_, err = leaf.Leaf.Verify(x509.VerifyOptions{DNSName: checkHost, Intermediates: inter, Roots: roots})
	return err == nil
}

// run executes a command and returns its combined output; tests replace it.
var run = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Install adds the root CA to the login keychain and marks it trusted for SSL.
// macOS asks the user to authorise the trust change.
func Install(ca *cert.Authority) error {
	if !Supported() {
		return ErrUnsupported
	}
	return withCertFile(ca, func(path string) error {
		out, err := run("security", installArgs(loginKeychain(), path)...)
		if err != nil {
			return securityError(out, err)
		}
		return nil
	})
}

// installArgs adds the certificate to keychain as a trusted root for SSL and
// basic X.509 use, in the user's trust domain (no admin rights needed).
func installArgs(keychain, certPath string) []string {
	return []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-p", "basic", "-k", keychain, certPath}
}

// Remove clears the trust setting and deletes the root CA from the login keychain.
func Remove(ca *cert.Authority) error {
	if !Supported() {
		return ErrUnsupported
	}
	root, err := rootCert(ca)
	if err != nil {
		return err
	}
	return withCertFile(ca, func(path string) error {
		if out, err := run("security", "remove-trusted-cert", path); err != nil && !notFound(out) {
			return securityError(out, err)
		}
		sum := sha1.Sum(root.Raw)
		if out, err := run("security", "delete-certificate", "-Z", strings.ToUpper(hex.EncodeToString(sum[:])), loginKeychain()); err != nil && !notFound(out) {
			return securityError(out, err)
		}
		return nil
	})
}

func rootCert(ca *cert.Authority) (*x509.Certificate, error) {
	block, _ := pem.Decode(ca.RootCertPEM())
	if block == nil {
		return nil, errors.New("trust: invalid root certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func withCertFile(ca *cert.Authority, fn func(path string) error) error {
	f, err := os.CreateTemp("", "kanca-ca-*.pem")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(ca.RootCertPEM()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fn(f.Name())
}

func loginKeychain() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db")
}

func notFound(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "could not be found") || strings.Contains(s, "unable to delete certificate matching") ||
		strings.Contains(s, "no trust settings")
}

func securityError(out []byte, err error) error {
	msg := strings.TrimSpace(string(out))
	if strings.Contains(strings.ToLower(msg), "canceled") || strings.Contains(strings.ToLower(msg), "cancelled") {
		return ErrCancelled
	}
	if msg == "" {
		return fmt.Errorf("security: %w", err)
	}
	return fmt.Errorf("security: %s", msg)
}
