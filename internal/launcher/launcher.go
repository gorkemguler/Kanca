// Package launcher opens a Chromium-based browser in a dedicated profile that
// is already routed through the Kanca proxy and trusts only Kanca's own
// certificates, so a tester can start intercepting with one click without
// touching their everyday browser profile or the OS trust store.
package launcher

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gorkemguler/kanca/internal/cert"
)

// StartURL is Kanca's own status page, served by the proxy; it confirms the
// browser is routed through Kanca and offers the CA for other browsers.
const StartURL = "http://kanca/"

// Open finds a browser and launches it in profileDir, routed through the proxy
// at proxyAddr and trusting certificates issued by ca.
func Open(ca *cert.Authority, proxyAddr, profileDir string) (Browser, error) {
	b, err := Find()
	if err != nil {
		return Browser{}, err
	}
	keys, err := TrustedKeys(ca)
	if err != nil {
		return Browser{}, err
	}
	return b, Launch(b, Options{
		ProxyAddr:   proxyAddr,
		ProfileDir:  profileDir,
		TrustedSPKI: keys,
		StartURL:    StartURL,
	})
}

// TrustedKeys returns the SPKI allow-list for certificates issued by ca: the
// root key, and the single key every leaf certificate is issued with.
func TrustedKeys(ca *cert.Authority) (string, error) {
	block, _ := pem.Decode(ca.RootCertPEM())
	if block == nil {
		return "", errors.New("launcher: invalid root certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	leaf, err := ca.CertForName("kanca")
	if err != nil {
		return "", err
	}
	return SPKIHashes(root, leaf.Leaf), nil
}

// Browser is an installed Chromium-based browser.
type Browser struct {
	Name string
	Path string
}

// ErrNoBrowser is returned when no supported browser is installed.
var ErrNoBrowser = errors.New("no Chrome, Edge, Brave or Chromium installation found")

// Find returns the first supported browser installed on this machine,
// preferring Chrome, then Edge, Brave and Chromium.
func Find() (Browser, error) {
	return find(candidates(), fileExists)
}

func find(cands []Browser, exists func(string) bool) (Browser, error) {
	for _, b := range cands {
		if b.Path != "" && exists(b.Path) {
			return b, nil
		}
	}
	return Browser{}, ErrNoBrowser
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func candidates() []Browser {
	switch runtime.GOOS {
	case "darwin":
		var out []Browser
		home, _ := os.UserHomeDir()
		for _, root := range []string{"/Applications", filepath.Join(home, "Applications")} {
			out = append(out,
				Browser{"Google Chrome", filepath.Join(root, "Google Chrome.app/Contents/MacOS/Google Chrome")},
				Browser{"Microsoft Edge", filepath.Join(root, "Microsoft Edge.app/Contents/MacOS/Microsoft Edge")},
				Browser{"Brave", filepath.Join(root, "Brave Browser.app/Contents/MacOS/Brave Browser")},
				Browser{"Chromium", filepath.Join(root, "Chromium.app/Contents/MacOS/Chromium")},
			)
		}
		return out
	case "windows":
		var out []Browser
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			root := os.Getenv(env)
			if root == "" {
				continue
			}
			out = append(out,
				Browser{"Google Chrome", filepath.Join(root, `Google\Chrome\Application\chrome.exe`)},
				Browser{"Microsoft Edge", filepath.Join(root, `Microsoft\Edge\Application\msedge.exe`)},
				Browser{"Brave", filepath.Join(root, `BraveSoftware\Brave-Browser\Application\brave.exe`)},
				Browser{"Chromium", filepath.Join(root, `Chromium\Application\chrome.exe`)},
			)
		}
		return out
	default:
		var out []Browser
		for _, c := range []struct{ name, bin string }{
			{"Google Chrome", "google-chrome"},
			{"Google Chrome", "google-chrome-stable"},
			{"Microsoft Edge", "microsoft-edge"},
			{"Microsoft Edge", "microsoft-edge-stable"},
			{"Brave", "brave-browser"},
			{"Chromium", "chromium"},
			{"Chromium", "chromium-browser"},
		} {
			if p, err := exec.LookPath(c.bin); err == nil {
				out = append(out, Browser{c.name, p})
			}
		}
		return out
	}
}

// Options configures a launch.
type Options struct {
	// ProxyAddr is the proxy listen address (host:port).
	ProxyAddr string
	// ProfileDir holds the dedicated browser profile, kept apart from the
	// user's everyday profile.
	ProfileDir string
	// TrustedSPKI lists base64 SHA-256 hashes of public keys whose certificate
	// errors the browser should ignore (Kanca's root and leaf keys); see
	// SPKIHashes.
	TrustedSPKI string
	// StartURL is opened in the first tab.
	StartURL string
}

// Args builds the browser command line for o.
func Args(o Options) []string {
	args := []string{
		"--user-data-dir=" + o.ProfileDir,
		"--proxy-server=http://" + LocalAddr(o.ProxyAddr),
		// Browsers never proxy loopback by default; testers want local targets.
		"--proxy-bypass-list=<-loopback>",
		"--no-first-run",
		"--no-default-browser-check",
		// Keep the browser's own update, sync and telemetry traffic out of the
		// history so it only shows what the tester does.
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-sync",
		"--disable-default-apps",
	}
	if o.TrustedSPKI != "" {
		// Honoured only together with --user-data-dir, and only for these keys,
		// so other sites keep normal certificate checks.
		args = append(args, "--ignore-certificate-errors-spki-list="+o.TrustedSPKI)
	}
	if o.StartURL != "" {
		args = append(args, o.StartURL)
	}
	return args
}

// Launch starts b with the options and returns once the process has started.
func Launch(b Browser, o Options) error {
	if err := os.MkdirAll(o.ProfileDir, 0o700); err != nil {
		return err
	}
	cmd := exec.Command(b.Path, Args(o)...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap the process when the user closes it
	return nil
}

// LocalAddr rewrites a wildcard listen address (0.0.0.0, ::, or an empty host)
// to loopback, the address a browser on this machine should dial.
func LocalAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// SPKIHashes returns the comma-separated base64 SHA-256 hashes of the certs'
// SubjectPublicKeyInfo, de-duplicated, in the format Chromium expects.
func SPKIHashes(certs ...*x509.Certificate) string {
	seen := map[string]bool{}
	var out []string
	for _, c := range certs {
		if c == nil {
			continue
		}
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		h := base64.StdEncoding.EncodeToString(sum[:])
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return strings.Join(out, ",")
}

// Reveal opens dir in the platform file manager.
func Reveal(dir string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", dir)
	case "windows":
		cmd = exec.Command("explorer", dir)
	default:
		cmd = exec.Command("xdg-open", dir)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
