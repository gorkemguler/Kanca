package proxy_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// A response over the snapshot cap must not keep the upstream connection open
// once Send has returned: Repeater, Intruder and scans only use the snapshot.
func TestSenderClosesTruncatedResponses(t *testing.T) {
	gone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("k"), 1<<20)
		for {
			if _, err := w.Write(chunk); err != nil {
				close(gone) // the client hung up
				return
			}
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	f := proxy.NewSender(proxy.SenderConfig{}).Send(context.Background(), []byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), "http", host)
	if !f.Response.Truncated {
		t.Fatalf("an endless response should be stored truncated (error %q)", f.Error)
	}
	select {
	case <-gone:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream connection was left open after Send returned")
	}
}
