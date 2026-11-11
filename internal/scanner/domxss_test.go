package scanner

import (
	"net/http"
	"testing"

	"github.com/gorkemguler/kanca/internal/proxy"
)

func htmlFlow(body string) *proxy.Flow {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	return &proxy.Flow{
		ID: 1, Scheme: "https", Host: "example.com", URL: "https://example.com/",
		StatusCode: 200,
		Response:   proxy.Message{Headers: h, Body: []byte(body)},
	}
}

func TestDOMXSSDetectsSourceToSink(t *testing.T) {
	s := New()
	s.Inspect(htmlFlow(`<script>
	var q = location.hash.slice(1);
	document.getElementById("out").innerHTML = q;
	</script>`))
	got := titles(s.Findings())
	if !got["Potential DOM-based XSS (innerHTML)"] {
		t.Fatalf("expected a DOM-XSS innerHTML finding, got %v", got)
	}
}

func TestDOMXSSDetectsDocumentWrite(t *testing.T) {
	s := New()
	s.Inspect(htmlFlow(`<script>document.write(decodeURIComponent(location.search));</script>`))
	if !titles(s.Findings())["Potential DOM-based XSS (document.write)"] {
		t.Fatalf("expected a document.write finding, got %v", titles(s.Findings()))
	}
}

func TestDOMXSSIgnoresSinkWithoutSource(t *testing.T) {
	s := New()
	// innerHTML fed from a server-rendered constant, no browser source nearby.
	s.Inspect(htmlFlow(`<script>el.innerHTML = "<b>Welcome back</b>";</script>`))
	for title := range titles(s.Findings()) {
		if len(title) >= 8 && title[:8] == "Potential" {
			t.Fatalf("a sink with no source should not be reported: %v", title)
		}
	}
}

func hasDOMFinding(fs []Finding) bool {
	for _, f := range fs {
		if len(f.Title) >= 9 && f.Title[:9] == "Potential" {
			return true
		}
	}
	return false
}

func TestDOMXSSIgnoresSourceWithoutSink(t *testing.T) {
	s := New()
	s.Inspect(htmlFlow(`<script>var page = location.pathname; analytics.track(page);</script>`))
	if hasDOMFinding(s.Findings()) {
		t.Fatalf("a source with no sink should not be reported: %v", titles(s.Findings()))
	}
}

func TestDOMXSSSkipsNonScriptContent(t *testing.T) {
	s := New()
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	s.Inspect(&proxy.Flow{
		ID: 1, Scheme: "https", Host: "example.com", URL: "https://example.com/api",
		StatusCode: 200,
		Response:   proxy.Message{Headers: h, Body: []byte(`{"innerHTML":"location.hash"}`)},
	})
	if hasDOMFinding(s.Findings()) {
		t.Fatalf("JSON must not be scanned for DOM XSS: %v", titles(s.Findings()))
	}
}

func TestDOMXSSOnePerSinkKind(t *testing.T) {
	s := New()
	s.Inspect(htmlFlow(`<script>
	a.innerHTML = location.hash;
	b.innerHTML = location.search;
	c.innerHTML = document.referrer;
	</script>`))
	n := 0
	for title := range titles(s.Findings()) {
		if title == "Potential DOM-based XSS (innerHTML)" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected one innerHTML finding across repeats, got %d", n)
	}
}
