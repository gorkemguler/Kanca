package cert

import (
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
)

func TestLeafForDNSName(t *testing.T) {
	a, err := NewEphemeralAuthority()
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	leaf, err := a.CertForName("example.com:443")
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	if leaf.Leaf.Subject.CommonName != "example.com" {
		t.Fatalf("cn = %q", leaf.Leaf.Subject.CommonName)
	}
	if err := leaf.Leaf.VerifyHostname("example.com"); err != nil {
		t.Fatalf("verify hostname: %v", err)
	}

	// Leaf must chain to the root.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(a.RootCertPEM()) {
		t.Fatal("append root")
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "example.com"}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
}

func TestLeafForIP(t *testing.T) {
	a, _ := NewEphemeralAuthority()
	leaf, err := a.CertForName("10.0.0.5")
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("ip SAN = %v", leaf.Leaf.IPAddresses)
	}
}

func TestLeafCaching(t *testing.T) {
	a, _ := NewEphemeralAuthority()
	c1, _ := a.CertForName("cache.test")
	c2, _ := a.CertForName("cache.test")
	if c1 != c2 {
		t.Fatal("expected cached leaf to be reused")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a1, err := NewAuthority(dir)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	a2, err := NewAuthority(dir)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(a1.RootCertPEM()) != string(a2.RootCertPEM()) {
		t.Fatal("root cert not persisted across loads")
	}
	if _, err := filepath.Glob(filepath.Join(dir, "ca-*.pem")); err != nil {
		t.Fatalf("glob: %v", err)
	}
}
