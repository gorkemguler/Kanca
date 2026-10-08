package launcher

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gorkemguler/kanca/internal/cert"
)

func TestFindPrefersFirstInstalled(t *testing.T) {
	cands := []Browser{{"Google Chrome", "/x/chrome"}, {"Microsoft Edge", "/x/edge"}, {"Brave", "/x/brave"}}
	installed := map[string]bool{"/x/edge": true, "/x/brave": true}
	b, err := find(cands, func(p string) bool { return installed[p] })
	if err != nil || b.Name != "Microsoft Edge" {
		t.Fatalf("find = %+v, %v; want Microsoft Edge", b, err)
	}
	if _, err := find(cands, func(string) bool { return false }); !errors.Is(err, ErrNoBrowser) {
		t.Fatalf("no browser installed: err = %v, want ErrNoBrowser", err)
	}
}

func TestArgsRouteThroughProxyInDedicatedProfile(t *testing.T) {
	args := Args(Options{
		ProxyAddr:   "0.0.0.0:8080",
		ProfileDir:  "/tmp/kanca-profile",
		TrustedSPKI: "AAA=,BBB=",
		StartURL:    "http://kanca/",
	})
	for _, want := range []string{
		"--user-data-dir=/tmp/kanca-profile",
		"--proxy-server=http://127.0.0.1:8080",
		"--proxy-bypass-list=<-loopback>",
		"--ignore-certificate-errors-spki-list=AAA=,BBB=",
		"--disable-background-networking",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("args missing %q:\n%s", want, strings.Join(args, "\n"))
		}
	}
	if args[len(args)-1] != "http://kanca/" {
		t.Errorf("start URL should be last, got %q", args[len(args)-1])
	}
	for _, a := range args {
		if a == "--ignore-certificate-errors" {
			t.Error("must not disable certificate checks for every site")
		}
	}
}

func TestArgsOmitTrustWhenNoKeys(t *testing.T) {
	for _, a := range Args(Options{ProxyAddr: "127.0.0.1:8080", ProfileDir: "/p"}) {
		if strings.HasPrefix(a, "--ignore-certificate-errors") {
			t.Fatalf("unexpected %q with no trusted keys", a)
		}
	}
}

func TestLocalAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:8080":   "127.0.0.1:8080",
		"[::]:8080":      "127.0.0.1:8080",
		":8080":          "127.0.0.1:8080",
		"127.0.0.1:9000": "127.0.0.1:9000",
		"10.1.2.3:8080":  "10.1.2.3:8080",
	} {
		if got := LocalAddr(in); got != want {
			t.Errorf("LocalAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSPKIHashesMatchKancaCertificates(t *testing.T) {
	ca, err := cert.NewEphemeralAuthority()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(ca.RootCertPEM())
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leafA, _ := ca.CertForName("a.example")
	leafB, _ := ca.CertForName("b.example")

	got := strings.Split(SPKIHashes(root, leafA.Leaf, leafB.Leaf, nil), ",")
	sum := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	if got[0] != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("root hash = %q", got[0])
	}
	// Every leaf shares one key, so the list stays at root + one leaf key.
	if len(got) != 2 {
		t.Fatalf("hashes = %v, want root and shared leaf key", got)
	}

	keys, err := TrustedKeys(ca)
	if err != nil {
		t.Fatalf("TrustedKeys: %v", err)
	}
	if keys != strings.Join(got, ",") {
		t.Fatalf("TrustedKeys = %q, want %q", keys, strings.Join(got, ","))
	}
}
