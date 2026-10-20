// Package project persists and restores a working session — captured flows,
// match-and-replace rules, scanner findings and scope — as a single JSON file
// so an assessment can be saved and reopened later.
package project

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/rules"
	"github.com/gorkemguler/kanca/internal/scanner"
)

// ProjectVersion is stamped into every new file by Save.
const ProjectVersion = "1"

// maxProjectBytes caps both how much of a project file is read before
// parsing and how much Save will write, so a runaway session cannot create a
// file that this application can no longer open.
const maxProjectBytes int64 = 256 << 20

// versionRe accepts the 0.x/1.x lineage Kanca writes (empty for very old
// files, "1.0", app versions like "0.3.1", "1" for new files). A newer major
// ("2", "10.0") fails loudly so a foreign or future format never loads
// half-wrong.
var versionRe = regexp.MustCompile(`^(0|[01])(\.[0-9]+)*$`)

// File is the on-disk project structure. Byte fields (raw messages, bodies)
// marshal as base64 strings via encoding/json, so the file is plain JSON.
type File struct {
	Version    string            `json:"version"`
	SavedAt    time.Time         `json:"savedAt"`
	Flows      []FlowDTO         `json:"flows"`
	Rules      []rules.Rule      `json:"rules"`
	Findings   []scanner.Finding `json:"findings"`
	ScopeOn    bool              `json:"scopeEnabled"`
	ScopeHosts []string          `json:"scopeHosts"`
}

// FlowDTO is a fully serialisable projection of a proxy.Flow (whose raw/body
// fields are excluded from its own JSON encoding).
type FlowDTO struct {
	ID          int64       `json:"id"`
	Scheme      string      `json:"scheme"`
	Method      string      `json:"method"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	URL         string      `json:"url"`
	StatusCode  int         `json:"statusCode"`
	DurationMs  int64       `json:"durationMs"`
	Error       string      `json:"error,omitempty"`
	Started     time.Time   `json:"started"`
	Comment     string      `json:"comment,omitempty"`
	Highlight   string      `json:"highlight,omitempty"`
	ReqHeaders  http.Header `json:"reqHeaders"`
	RespHeaders http.Header `json:"respHeaders"`
	ReqRaw      []byte      `json:"reqRaw"`
	ReqBody     []byte      `json:"reqBody,omitempty"`
	RespRaw     []byte      `json:"respRaw"`
	RespBody    []byte      `json:"respBody,omitempty"`
	// ReqTruncated/RespTruncated mirror proxy.Message.Truncated: the stored
	// snapshot was capped, not the forwarded message.
	ReqTruncated  bool `json:"reqTruncated,omitempty"`
	RespTruncated bool `json:"respTruncated,omitempty"`
}

// FromFlow projects a live flow into a serialisable DTO. A body that is
// already a suffix of Raw is stored once, as raw, and rebuilt by ToFlow; this
// roughly halves the size of a saved session without changing what loads.
func FromFlow(f *proxy.Flow) FlowDTO {
	reqRaw, reqBody := dedupeBody(f.Request.Raw, f.Request.Body)
	respRaw, respBody := dedupeBody(f.Response.Raw, f.Response.Body)
	return FlowDTO{
		ID: f.ID, Scheme: f.Scheme, Method: f.Method, Host: f.Host,
		Path: f.Path, URL: f.URL, StatusCode: f.StatusCode,
		DurationMs: f.Duration, Error: f.Error, Started: f.Started,
		Comment: f.Comment, Highlight: f.Highlight,
		ReqHeaders: f.Request.Headers, RespHeaders: f.Response.Headers,
		ReqRaw: reqRaw, ReqBody: reqBody,
		RespRaw: respRaw, RespBody: respBody,
		ReqTruncated: f.Request.Truncated, RespTruncated: f.Response.Truncated,
	}
}

// dedupeBody returns body as nil when raw already ends with exactly that
// body, so the file stores the payload once.
func dedupeBody(raw, body []byte) ([]byte, []byte) {
	if len(raw) == 0 || len(body) == 0 {
		return raw, body
	}
	if got, ok := splitBody(raw); ok && bytes.Equal(got, body) {
		return raw, nil
	}
	return raw, body
}

// splitBody returns the payload after the first blank line of a raw HTTP
// message. ok is false when raw has no header terminator.
func splitBody(raw []byte) ([]byte, bool) {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, false
	}
	return raw[i+4:], true
}

// joinBody restores a body omitted by dedupeBody.
func joinBody(raw, body []byte) []byte {
	if body != nil || len(raw) == 0 {
		return body
	}
	if got, ok := splitBody(raw); ok {
		return got
	}
	return body
}

// ToFlow rebuilds a flow suitable for display from a DTO.
func (d FlowDTO) ToFlow() *proxy.Flow {
	reqH := d.ReqHeaders
	if reqH == nil {
		reqH = http.Header{}
	}
	respH := d.RespHeaders
	if respH == nil {
		respH = http.Header{}
	}
	reqBody := joinBody(d.ReqRaw, d.ReqBody)
	respBody := joinBody(d.RespRaw, d.RespBody)
	return &proxy.Flow{
		ID: d.ID, Scheme: d.Scheme, Method: d.Method, Host: d.Host,
		Path: d.Path, URL: d.URL, StatusCode: d.StatusCode,
		Duration: d.DurationMs, Error: d.Error, Started: d.Started,
		Comment: d.Comment, Highlight: d.Highlight,
		Request: proxy.Message{
			Raw: d.ReqRaw, Headers: reqH, Body: reqBody,
			ContentLength: int64(len(reqBody)),
			Truncated:     d.ReqTruncated,
		},
		Response: proxy.Message{
			Raw: d.RespRaw, Headers: respH, Body: respBody,
			ContentLength: int64(len(respBody)),
			Truncated:     d.RespTruncated,
		},
	}
}

// Flows rebuilds every stored flow.
func (f File) FlowList() []*proxy.Flow {
	out := make([]*proxy.Flow, 0, len(f.Flows))
	for _, d := range f.Flows {
		out = append(out, d.ToFlow())
	}
	return out
}

// Save writes f to path as indented JSON. The file is capped at
// maxProjectBytes and replaced atomically, so a crash mid-write cannot leave
// a half-written session behind.
func Save(path string, f File) error {
	return saveTo(path, f, maxProjectBytes)
}

// saveTo is Save with an explicit cap, so tests can exercise the rejection
// path without allocating a project larger than maxProjectBytes.
func saveTo(path string, f File, limit int64) error {
	f.SavedAt = time.Now()
	if f.Version == "" {
		f.Version = ProjectVersion
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("project: marshal: %w", err)
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("project: session is %d bytes, exceeds %d; remove some flows and retry", len(data), limit)
	}
	return writeAtomic(path, data)
}

// writeAtomic writes data to a temp file beside path and renames it into
// place, so readers never observe a partial file.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kanca-save-*.tmp")
	if err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}
	name := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(name) // no-op after a successful rename
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}
	return nil
}

// Load reads and parses a project file from path. Files larger than
// maxProjectBytes are rejected instead of partially parsed.
func Load(path string) (File, error) {
	var f File
	info, err := os.Stat(path)
	if err != nil {
		return f, fmt.Errorf("project: read %s: %w", path, err)
	}
	if info.Size() > maxProjectBytes {
		return f, fmt.Errorf("project: %s is %d bytes, exceeds %d", path, info.Size(), maxProjectBytes)
	}
	fh, err := os.Open(path)
	if err != nil {
		return f, fmt.Errorf("project: read %s: %w", path, err)
	}
	defer fh.Close()
	counting := &countReader{r: io.LimitReader(fh, maxProjectBytes+1)}
	if err := json.NewDecoder(counting).Decode(&f); err != nil {
		return f, fmt.Errorf("project: parse %s: %w", path, err)
	}
	if counting.n > maxProjectBytes {
		return f, fmt.Errorf("project: %s exceeds %d bytes", path, maxProjectBytes)
	}
	if f.Version != "" && !versionRe.MatchString(f.Version) {
		return f, fmt.Errorf("project: unsupported version %q", f.Version)
	}
	return f, nil
}

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
