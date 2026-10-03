// Package project persists and restores a working session — captured flows,
// match-and-replace rules, scanner findings and scope — as a single JSON file
// so an assessment can be saved and reopened later.
package project

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/rules"
	"github.com/gorkemguler/kanca/internal/scanner"
)

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
	ReqHeaders  http.Header `json:"reqHeaders"`
	RespHeaders http.Header `json:"respHeaders"`
	ReqRaw      []byte      `json:"reqRaw"`
	ReqBody     []byte      `json:"reqBody"`
	RespRaw     []byte      `json:"respRaw"`
	RespBody    []byte      `json:"respBody"`
}

// FromFlow projects a live flow into a serialisable DTO.
func FromFlow(f *proxy.Flow) FlowDTO {
	return FlowDTO{
		ID: f.ID, Scheme: f.Scheme, Method: f.Method, Host: f.Host,
		Path: f.Path, URL: f.URL, StatusCode: f.StatusCode,
		DurationMs: f.Duration, Error: f.Error, Started: f.Started,
		ReqHeaders: f.Request.Headers, RespHeaders: f.Response.Headers,
		ReqRaw: f.Request.Raw, ReqBody: f.Request.Body,
		RespRaw: f.Response.Raw, RespBody: f.Response.Body,
	}
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
	return &proxy.Flow{
		ID: d.ID, Scheme: d.Scheme, Method: d.Method, Host: d.Host,
		Path: d.Path, URL: d.URL, StatusCode: d.StatusCode,
		Duration: d.DurationMs, Error: d.Error, Started: d.Started,
		Request: proxy.Message{
			Raw: d.ReqRaw, Headers: reqH, Body: d.ReqBody,
			ContentLength: int64(len(d.ReqBody)),
		},
		Response: proxy.Message{
			Raw: d.RespRaw, Headers: respH, Body: d.RespBody,
			ContentLength: int64(len(d.RespBody)),
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

// Save writes f to path as indented JSON.
func Save(path string, f File) error {
	f.SavedAt = time.Now()
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("project: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}
	return nil
}

// Load reads and parses a project file from path.
func Load(path string) (File, error) {
	var f File
	data, err := os.ReadFile(path)
	if err != nil {
		return f, fmt.Errorf("project: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("project: parse %s: %w", path, err)
	}
	return f, nil
}
