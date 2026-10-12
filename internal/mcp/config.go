package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultAddr is where the endpoint listens; loopback only.
const DefaultAddr = "127.0.0.1:8765"

// Config is persisted in <dir>/mcp.json (mode 0600) so clients keep working
// across restarts and the stdio bridge can find the endpoint.
type Config struct {
	Enabled bool   `json:"enabled"`
	Level   string `json:"level"`
	Mask    bool   `json:"mask"`
	Addr    string `json:"addr"`
	Token   string `json:"token"`
}

func configPath(dir string) string { return filepath.Join(dir, "mcp.json") }

// LoadConfig reads the config, filling defaults (off, read-write, masking on,
// a fresh token) for anything missing.
func LoadConfig(dir string) (Config, error) {
	c := Config{Level: LevelReadWrite, Mask: true, Addr: DefaultAddr}
	data, err := os.ReadFile(configPath(dir))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return c, err
	default:
		if err := json.Unmarshal(data, &c); err != nil {
			return c, err
		}
	}
	if c.Level != LevelRead && c.Level != LevelReadWrite {
		c.Level = LevelReadWrite
	}
	if c.Addr == "" {
		c.Addr = DefaultAddr
	}
	if c.Token == "" {
		c.Token = NewToken()
	}
	return c, nil
}

// SaveConfig writes the config readable by the current user only.
func SaveConfig(dir string, c Config) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(dir), data, 0o600)
}

// NewToken returns a random 256-bit bearer token.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b)
}

// URL is the endpoint clients connect to.
func (c Config) URL() string { return "http://" + c.Addr + "/mcp" }
