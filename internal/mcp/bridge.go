package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RunStdioBridge connects a stdio-only MCP client (such as Claude Desktop) to
// the running Kanca endpoint: each newline-delimited JSON-RPC message on in is
// POSTed to the endpoint and any reply is written to out. The endpoint address
// and token come from the config in dir, so the client config holds no secret.
func RunStdioBridge(dir string, in io.Reader, out io.Writer) error {
	client := &http.Client{Timeout: 5 * time.Minute} // active scans can take a while
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		reply := forward(client, dir, line)
		if reply == nil {
			continue
		}
		if _, err := out.Write(append(bytes.TrimSpace(reply), '\n')); err != nil {
			return err
		}
	}
	return sc.Err()
}

// forward sends one message and returns the reply, or nil for notifications.
// Failures to reach Kanca become JSON-RPC errors so the client can show them.
func forward(client *http.Client, dir string, msg []byte) []byte {
	var head struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(msg, &head)
	isRequest := len(head.ID) > 0 && string(head.ID) != "null"

	fail := func(format string, a ...any) []byte {
		if !isRequest {
			return nil
		}
		return encode(rpcResponse{JSONRPC: "2.0", ID: head.ID, Error: &rpcError{-32000, fmt.Sprintf(format, a...)}})
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		return fail("can't read Kanca's AI settings: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, cfg.URL(), bytes.NewReader(msg))
	if err != nil {
		return fail("%v", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return fail("Kanca isn't reachable at %s. Open Kanca and turn on AI access in the AI Assistant tab (or run kanca -mcp). (%v)", cfg.URL(), err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == http.StatusAccepted:
		return nil
	case resp.StatusCode != http.StatusOK:
		return fail("Kanca refused the request: %s %s", resp.Status, bytes.TrimSpace(body))
	}
	return body
}
