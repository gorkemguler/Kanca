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
	"strings"
	"syscall"
	"time"

	"github.com/gorkemguler/kanca/internal/cert"
	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/launcher"
	"github.com/gorkemguler/kanca/internal/mcp"
	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
	"github.com/gorkemguler/kanca/internal/scope"
)

func main() {
	// AI assistants (Claude Code/Desktop, Opencode) reach a running Kanca via
	// "kanca mcp-stdio", which bridges stdio JSON-RPC to the local HTTP
	// endpoint (desktop app or "kanca -mcp").
	if len(os.Args) > 1 && os.Args[1] == "mcp-stdio" {
		if err := mcp.RunStdioBridge(defaultCADir(), os.Stdin, os.Stdout); err != nil {
			fatal("mcp-stdio: %v", err)
		}
		return
	}

	var (
		addr     = flag.String("addr", "127.0.0.1:8080", "proxy listen address")
		caDir    = flag.String("cadir", defaultCADir(), "directory holding the root CA")
		exportCA = flag.String("export-ca", "", "write the root CA certificate to this path and exit")
		insecure = flag.Bool("insecure-upstream", true, "skip verification of upstream TLS certificates")
		maxFlows = flag.Int("max-flows", 100000, "maximum retained transactions")
		browser  = flag.Bool("browser", false, "open Chrome/Edge/Brave in a dedicated profile already routed through the proxy")
		scopeArg = flag.String("scope", "", "comma-separated target hosts; only these are recorded, and the only ones an AI assistant may test")
		aiFlag   = flag.Bool("mcp", false, "let AI assistants (Claude Code/Desktop, Opencode) use Kanca over MCP on 127.0.0.1:8765")
		aiRead   = flag.Bool("mcp-readonly", false, "with -mcp: the assistant may read traffic but not send requests")
		aiRaw    = flag.Bool("mcp-no-mask", false, "with -mcp: show cookies, tokens and passwords to the assistant unmasked")
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
	findings := scanner.New()
	store.Subscribe(func(id int64) {
		if f, ok := store.Get(id); ok {
			findings.Inspect(f)
		}
	})
	scopeHosts := scope.Normalize(strings.Split(*scopeArg, ","))

	p, err := proxy.New(proxy.Config{Addr: *addr, CA: ca, InsecureUpstream: *insecure})
	if err != nil {
		fatal("creating proxy: %v", err)
	}
	p.SetScope(scope.Matcher(scopeHosts))
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

	if *aiFlag {
		startMCP(*caDir, store, findings, scopeHosts, *aiRead, !*aiRaw)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = p.Stop(ctx)
	fmt.Printf("\nstopped; %d transactions captured\n", store.Len())
}

// startMCP serves the AI assistant endpoint for this session and prints how
// to connect Claude Code/Desktop and Opencode (remote HTTP + local stdio).
func startMCP(dir string, store *history.Store, findings *scanner.Scanner, hosts []string, readOnly, mask bool) {
	cfg, err := mcp.LoadConfig(dir)
	if err != nil {
		fatal("loading AI settings: %v", err)
	}
	// Persist only the token (so the stdio bridge can find it); this session's
	// level and masking come from the flags and don't change the desktop app's.
	if err := mcp.SaveConfig(dir, cfg); err != nil {
		fatal("saving AI settings: %v", err)
	}
	cfg.Mask, cfg.Level = mask, mcp.LevelReadWrite
	if readOnly {
		cfg.Level = mcp.LevelRead
	}
	srv := mcp.NewServer(mcp.Deps{
		Store:      store,
		Scanner:    findings,
		Scope:      func() func(string) bool { return scope.Matcher(hosts) },
		ScopeHosts: func() []string { return hosts },
		Version:    "cli",
	}, func() mcp.Options {
		// AllowDelete is a persisted user setting, not a session flag: the
		// desktop app (or a hand-edited mcp.json) decides whether assistants
		// may send DELETE.
		return mcp.Options{Level: cfg.Level, Mask: cfg.Mask, AllowDelete: cfg.AllowDelete}
	})
	if err := (&mcp.Service{Server: srv}).Start(cfg.Addr, cfg.Token); err != nil {
		fatal("starting AI endpoint: %v", err)
	}
	fmt.Printf("\nAI assistant endpoint: %s (%s", cfg.URL(), cfg.Level)
	if cfg.Mask {
		fmt.Print(", secrets masked")
	}
	fmt.Println(")")
	if len(hosts) == 0 {
		fmt.Println("  No -scope given: the assistant can read traffic but not send requests.")
	}
	fmt.Printf("  Claude Code:    claude mcp add --transport http kanca %s --header \"Authorization: Bearer %s\"\n", cfg.URL(), cfg.Token)
	exe, _ := os.Executable()
	fmt.Printf("  Claude Desktop: add {\"command\": %q, \"args\": [\"mcp-stdio\"]} under mcpServers.kanca\n", exe)
	fmt.Printf("  Opencode (remote): add to opencode.json under mcp.kanca: {\"type\":\"remote\",\"url\":%q,\"headers\":{\"Authorization\":\"Bearer {env:KANCA_MCP_TOKEN}\"},\"oauth\":false}\n", cfg.URL())
	fmt.Println(`    then: export KANCA_MCP_TOKEN="$(jq -r .token ~/.kanca/mcp.json)"  # no secret in the file`)
	fmt.Printf("  Opencode (local):  add to opencode.json under mcp.kanca: {\"type\":\"local\",\"command\":[%q, \"mcp-stdio\"]}\n", exe)
	fmt.Println(`  Verify: opencode mcp list  # kanca should appear as connected; opencode mcp debug kanca on 401/OAuth issues`)
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
