package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gorkemguler/kanca/extension"
	"github.com/gorkemguler/kanca/internal/launcher"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// OpenBrowser launches Chrome, Edge or Brave in a dedicated Kanca profile that
// is routed through the proxy and trusts Kanca's certificates, starting the
// proxy first if needed. It returns the browser's name.
func (a *App) OpenBrowser() (string, error) {
	st, err := a.StartProxy("")
	if err != nil {
		return "", err
	}
	if a.ctx != nil {
		// The proxy may have just been started here rather than from the top bar.
		wruntime.EventsEmit(a.ctx, "proxy:status", st)
	}
	b, err := launcher.Open(a.ca, st.Addr, filepath.Join(configDir(), "browser-profile"))
	if errors.Is(err, launcher.ErrNoBrowser) {
		return "", fmt.Errorf("no Chrome, Edge, Brave or Chromium found; install one, or use the Kanca extension in your own browser")
	}
	if err != nil {
		return "", err
	}
	return b.Name, nil
}

// ExportExtension writes the bundled browser extension to
// ~/.kanca/browser-extension, replacing any older copy so it matches this app
// version, and opens the folder ready for "Load unpacked". It returns the path.
func (a *App) ExportExtension() (string, error) {
	dir := filepath.Join(configDir(), "browser-extension")
	if err := writeExtension(dir); err != nil {
		return "", err
	}
	_ = launcher.Reveal(dir)
	return dir, nil
}

func writeExtension(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return fs.WalkDir(extension.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := fs.ReadFile(extension.Files, p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
