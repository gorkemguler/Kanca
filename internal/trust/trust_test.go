package trust

import (
	"crypto/x509"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gorkemguler/kanca/internal/cert"
)

func newCA(t *testing.T) *cert.Authority {
	t.Helper()
	ca, err := cert.NewEphemeralAuthority()
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestFreshCAIsNotTrustedBySystem(t *testing.T) {
	// A CA minted for this test was never installed anywhere.
	if Trusted(newCA(t)) {
		t.Fatal("system reports a brand-new CA as trusted")
	}
}

func TestIssuedCertsVerifyOnceRootIsTrusted(t *testing.T) {
	ca := newCA(t)
	root, err := rootCert(ca)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if !trustedWith(ca, roots) {
		t.Fatal("a leaf from Kanca's CA should verify for TLS once the root is trusted")
	}
}

func TestInstallArgsTrustRootInUserDomain(t *testing.T) {
	args := installArgs("/k/login.keychain-db", "/tmp/ca.pem")
	for _, want := range []string{"add-trusted-cert", "trustRoot", "ssl", "/k/login.keychain-db", "/tmp/ca.pem"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %v missing %q", args, want)
		}
	}
	if slices.Contains(args, "-d") {
		t.Error("must use the user trust domain, not the admin domain (-d needs sudo)")
	}
}

func TestSecurityErrorMapsCancellation(t *testing.T) {
	err := securityError([]byte("SecTrustSettingsSetTrustSettings: The authorization was canceled by the user."), errors.New("exit status 1"))
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
	err = securityError([]byte("some other failure"), errors.New("exit status 1"))
	if err == nil || !strings.Contains(err.Error(), "some other failure") {
		t.Fatalf("err = %v, want the tool's message", err)
	}
}

func TestInstallAndRemoveRunSecurity(t *testing.T) {
	if !Supported() {
		if err := Install(newCA(t)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Install on %s: err = %v, want ErrUnsupported", "this platform", err)
		}
		return
	}
	var calls [][]string
	orig := run
	t.Cleanup(func() { run = orig })
	run = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		// The cert file must exist while the tool runs.
		if _, err := os.Stat(args[len(args)-1]); err != nil && args[0] != "delete-certificate" {
			t.Errorf("cert file missing during %v", args)
		}
		if args[0] == "delete-certificate" {
			return []byte("Unable to delete certificate matching \"X\""), errors.New("exit status 44")
		}
		return nil, nil
	}

	ca := newCA(t)
	if err := Install(ca); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := Remove(ca); err != nil {
		t.Fatalf("Remove should ignore a certificate that is already gone: %v", err)
	}
	if len(calls) != 3 || calls[0][1] != "add-trusted-cert" || calls[1][1] != "remove-trusted-cert" || calls[2][1] != "delete-certificate" {
		t.Fatalf("unexpected security calls: %v", calls)
	}
}
