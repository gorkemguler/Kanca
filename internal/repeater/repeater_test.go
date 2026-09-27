package repeater

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRepeaterSend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "method=%s ua=%s", r.Method, r.Header.Get("User-Agent"))
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)

	r := New(true)
	raw := []byte("GET / HTTP/1.1\r\nHost: " + u.Host + "\r\nUser-Agent: mimlec-repeater\r\n\r\n")
	tab := r.NewTab("probe", "http", u.Host, raw)

	f, ok := r.Send(context.Background(), tab.ID)
	if !ok {
		t.Fatal("send returned not-ok")
	}
	if f.Error != "" {
		t.Fatalf("send error: %s", f.Error)
	}
	if f.StatusCode != 200 {
		t.Fatalf("status = %d", f.StatusCode)
	}
	if got := f.Response.BodyString(); got != "method=GET ua=mimlec-repeater" {
		t.Fatalf("body = %q", got)
	}

	// History should now hold one flow for this tab.
	tabs := r.Tabs()
	if len(tabs) != 1 || len(tabs[0].History) != 1 {
		t.Fatalf("history not recorded: %+v", tabs)
	}
}

func TestRepeaterUpdateAndResend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path)
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)

	r := New(true)
	tab := r.NewTab("", "http", u.Host, []byte("GET /one HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n"))
	f1, _ := r.Send(context.Background(), tab.ID)
	if f1.Response.BodyString() != "/one" {
		t.Fatalf("f1 body = %q", f1.Response.BodyString())
	}

	r.Update(tab.ID, "http", u.Host, []byte("GET /two HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n"))
	f2, _ := r.Send(context.Background(), tab.ID)
	if f2.Response.BodyString() != "/two" {
		t.Fatalf("f2 body = %q", f2.Response.BodyString())
	}
}
