// Package extension embeds the Kanca browser extension so the desktop app can
// hand it to users without a separate download. The extension itself is plain
// JavaScript; this file only exposes it to Go.
package extension

import "embed"

// Files holds the extension as it is loaded into the browser (no tests or
// tooling files).
//
//go:embed manifest.json background.js popup.html popup.css popup.js lib icons
var Files embed.FS
