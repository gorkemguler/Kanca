// Command kanca runs the Kanca intercepting proxy headlessly, printing a
// live log of captured transactions. It is handy for servers, CI and for
// verifying the engine without the desktop UI.
//
// Configure your browser or system HTTP/HTTPS proxy to point at the listen
// address, then install the printed root CA to intercept TLS. Use only against
// systems you are authorised to test.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gorkemguler/kanca/internal/cert"
	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/launcher"
	"github.com/gorkemguler/kanca/internal/proxy"
)

func main() {
	var (
		addr     = flag.String("addr", "127.0.0.1:8080", "proxy listen address")
		caDir    = flag.String("cadir", defaultCADir(), "directory holding the root CA")
		exportCA = flag.String("export-ca", "", "write the root CA certificate to this path and exit")
		insecure = flag.Bool("insecure-upstream", true, "skip verification of upstream TLS certificates")
		maxFlows = flag.Int("max-flows", 100000, "maximum retained transactions")
		browser  = flag.Bool("browser", false, "open Chrome/Edge/Brave in a dedicated profile already routed through the proxy")
	)
	flag.Parse()

	ca, err := cert.NewAuthority(*caDir)
	if err != nil {
		fatal("initialising CA: %v", err)
	}

	if *exportCA != "" {
		if err := os.WriteFile(*exportCA, ca.RootCertPEM(), 0o644); err != nil {
			fatal("exporting CA: %v", err)
		}
		fmt.Printf("root CA written to %s\n", *exportCA)
		return
	}

	store := history.New(*maxFlows)

	p, err := proxy.New(proxy.Config{Addr: *addr, CA: ca, InsecureUpstream: *insecure})
	if err != nil {
		fatal("creating proxy: %v", err)
	}
	p.OnFlow(func(f *proxy.Flow) {
		store.Add(f)
		printFlow(f)
	})

	if err := p.Start(); err != nil {
		fatal("starting proxy: %v", err)
	}

	fmt.Printf("Kanca proxy listening on http://%s\n", p.Addr())
	fmt.Printf("Root CA: %s (import into your browser/OS to intercept HTTPS)\n", filepath.Join(*caDir, "ca-cert.pem"))
	fmt.Println("Set this as your HTTP/HTTPS proxy. Ctrl-C to stop.")
	if *browser {
		b, err := launcher.Open(ca, p.Addr(), filepath.Join(*caDir, "browser-profile"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "kanca: opening browser: %v\n", err)
		} else {
			fmt.Printf("Opened %s, routed through Kanca (HTTPS works without installing the CA).\n", b.Name)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = p.Stop(ctx)
	fmt.Printf("\nstopped; %d transactions captured\n", store.Len())
}

func printFlow(f *proxy.Flow) {
	status := f.StatusCode
	marker := "→"
	detail := fmt.Sprintf("%d", status)
	if f.Error != "" {
		marker = "✗"
		detail = f.Error
	}
	fmt.Printf("%s %-6s %s %s  (%dms, %s)\n",
		marker, f.Method, f.URL, detail, f.Duration, humanBytes(len(f.Response.Body)))
}

func humanBytes(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1fMB", float64(n)/(1024*1024))
	}
}

func defaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".kanca"
	}
	return filepath.Join(home, ".kanca")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "kanca: "+format+"\n", args...)
	os.Exit(1)
}
