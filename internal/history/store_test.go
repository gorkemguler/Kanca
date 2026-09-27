package history

import (
	"net/http"
	"testing"

	"github.com/gorkemguler/mimlec/internal/proxy"
)

func mkFlow(id int64, method, host, path string, status int) *proxy.Flow {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	return &proxy.Flow{
		ID: id, Method: method, Host: host, Path: path, StatusCode: status,
		Scheme:   "https",
		Response: proxy.Message{Headers: h, Body: []byte("body")},
	}
}

func TestAddAndGet(t *testing.T) {
	s := New(0)
	s.Add(mkFlow(1, "GET", "a.com", "/", 200))
	if s.Len() != 1 {
		t.Fatalf("len = %d", s.Len())
	}
	f, ok := s.Get(1)
	if !ok || f.Host != "a.com" {
		t.Fatalf("get = %+v ok=%v", f, ok)
	}
}

func TestEviction(t *testing.T) {
	s := New(2)
	s.Add(mkFlow(1, "GET", "a", "/", 200))
	s.Add(mkFlow(2, "GET", "b", "/", 200))
	s.Add(mkFlow(3, "GET", "c", "/", 200))
	if s.Len() != 2 {
		t.Fatalf("len = %d, want 2", s.Len())
	}
	if _, ok := s.Get(1); ok {
		t.Fatal("oldest flow should have been evicted")
	}
}

func TestListNewestFirstAndFilter(t *testing.T) {
	s := New(0)
	s.Add(mkFlow(1, "GET", "api.example.com", "/users", 200))
	s.Add(mkFlow(2, "POST", "api.example.com", "/login", 401))
	s.Add(mkFlow(3, "GET", "cdn.other.com", "/img.png", 200))

	all := s.List(Filter{})
	if len(all) != 3 || all[0].ID != 3 {
		t.Fatalf("expected newest-first, got %+v", all)
	}

	byMethod := s.List(Filter{Methods: []string{"POST"}})
	if len(byMethod) != 1 || byMethod[0].ID != 2 {
		t.Fatalf("method filter = %+v", byMethod)
	}

	byText := s.List(Filter{Text: "login"})
	if len(byText) != 1 || byText[0].ID != 2 {
		t.Fatalf("text filter = %+v", byText)
	}

	byScope := s.List(Filter{Scope: func(h string) bool { return h == "api.example.com" }})
	if len(byScope) != 2 {
		t.Fatalf("scope filter = %d", len(byScope))
	}

	hide := s.List(Filter{HideStatus: map[int]bool{401: true}})
	if len(hide) != 2 {
		t.Fatalf("hide-status filter = %d", len(hide))
	}
}

func TestSubscribeNotifies(t *testing.T) {
	s := New(0)
	got := make(chan int64, 1)
	s.Subscribe(func(id int64) { got <- id })
	s.Add(mkFlow(42, "GET", "x", "/", 200))
	if id := <-got; id != 42 {
		t.Fatalf("notified id = %d", id)
	}
}
