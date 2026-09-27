// Command mimlec-desktop is the Wails-based desktop UI for the Mimlec
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

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app, err := NewApp()
	if err != nil {
		log.Fatalf("mimlec: %v", err)
	}

	err = wails.Run(&options.App{
		Title:     "Mimlec",
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
		log.Fatalf("mimlec: %v", err)
	}
}
