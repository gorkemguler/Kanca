package proxy

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestRawHeadersAreInStableSortedOrder(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	for _, k := range []string{"X-Zeta", "Accept", "User-Agent", "Cookie", "X-Alpha", "Accept-Language"} {
		req.Header.Set(k, "v")
	}

	first := string(requestToRaw(req, nil))
	// Map iteration is randomised, so an unsorted writer would differ here.
	for i := 0; i < 50; i++ {
		if got := string(requestToRaw(req, nil)); got != first {
			t.Fatalf("raw request changed between renders:\n%s\n---\n%s", first, got)
		}
	}

	want := []string{
		"GET / HTTP/1.1",
		"Host: example.com",
		"Accept: v",
		"Accept-Language: v",
		"Cookie: v",
		"User-Agent: v",
		"X-Alpha: v",
		"X-Zeta: v",
		"Content-Length: 0",
	}
	got := strings.Split(strings.TrimSuffix(first, "\r\n\r\n"), "\r\n")
	if !slices.Equal(got, want) {
		t.Fatalf("header order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
