// Command kanca-desktop is the Wails-based desktop UI for the Kanca
// intercepting proxy. Build it with the Wails CLI:
//
//	cd desktop && wails dev      # live-reload development
//	cd desktop && wails build    # produce a native binary
//
// The core engine lives in the parent module's internal packages; this module
// only provides the desktop shell and frontend.
package main

import (
	"embed"
	"log"
	"os"

	"github.com/gorkemguler/kanca/internal/mcp"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Claude Desktop launches this binary with "mcp-stdio" to reach the running
	// app's AI endpoint; that mode has no window.
	if len(os.Args) > 1 && os.Args[1] == "mcp-stdio" {
		if err := mcp.RunStdioBridge(configDir(), os.Stdin, os.Stdout); err != nil {
			log.Fatalf("kanca mcp-stdio: %v", err)
		}
		return
	}

	app, err := NewApp()
	if err != nil {
		log.Fatalf("kanca: %v", err)
	}

	err = wails.Run(&options.App{
		Title:     "Kanca",
		Width:     1280,
		Height:    820,
		MinWidth:  960,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup: app.startup,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		log.Fatalf("kanca: %v", err)
	}
}
