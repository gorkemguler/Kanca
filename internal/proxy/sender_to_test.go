package proxy_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorkemguler/kanca/internal/proxy"
)

func TestSendToKeepsTheHostHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Host)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	raw := []byte("GET /x HTTP/1.1\r\nHost: forged.invalid\r\n\r\n")
	f := proxy.NewSender(proxy.SenderConfig{}).SendTo(context.Background(), raw, "http", addr)
	if f.Error != "" {
		t.Fatalf("SendTo should reach %s whatever the Host header says: %s", addr, f.Error)
	}
	if got := f.Response.BodyString(); got != "forged.invalid" {
		t.Fatalf("server saw Host %q, want the forged one", got)
	}
	if f.URL != "http://"+addr+"/x" {
		t.Fatalf("URL = %q, want the server actually reached", f.URL)
	}
}
