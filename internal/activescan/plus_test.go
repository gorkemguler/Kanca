package activescan

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorkemguler/kanca/internal/proxy"
)

func runPlus(t *testing.T, srv *httptest.Server, raw string) []string {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	raw = strings.ReplaceAll(raw, "HOST", u.Host)
	fs, err := Run(context.Background(), Config{Scheme: "http", Host: u.Host, Raw: []byte(raw), Plus: true})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var out []string
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}

func TestPlusIsOffByDefault(t *testing.T) {
	var probed atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			probed.Add(1)
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	raw := []byte("GET /?q=1 HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
	if _, err := Run(context.Background(), Config{Scheme: "http", Host: u.Host, Raw: raw}); err != nil {
		t.Fatal(err)
	}
	if probed.Load() != 0 {
		t.Fatalf("a scan without Plus fetched %d other paths", probed.Load())
	}
}

func TestPlusCleanTargetNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><p>static page</p></html>")
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET /?q=hello&id=1 HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if len(got) != 0 {
		t.Fatalf("expected no findings on a clean target, got %v", got)
	}
}

func TestPlusEchoIsNotATransformation(t *testing.T) {
	// Reflecting input as it is must not look like rewriting it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><p>%s</p></html>", r.URL.Query().Get("q"))
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET /?q=hello HTTP/1.1\r\nHost: HOST\r\n\r\n")
	for _, title := range got {
		if !strings.Contains(title, "Reflected input") && !strings.Contains(title, "reflected XSS") {
			t.Errorf("unexpected finding on an echo: %s", title)
		}
	}
}

func TestPlusInterestingFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "Interesting file: /.git/config") {
		t.Fatalf("expected the exposed .git/config, got %v", got)
	}

	// A page served for every path contains the marker everywhere.
	all := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<pre>[core] Server uptime applinks</pre>")
	}))
	defer all.Close()
	if got := runPlus(t, all, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n"); has(got, "Interesting file") {
		t.Fatalf("a catch-all page is not an interesting file: %v", got)
	}
}

func TestPlusHostChecksRunOncePerHost(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			hits.Add(1)
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hosts := &HostSet{}
	for _, target := range []string{"/a", "/b"} {
		raw := []byte("GET " + target + " HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")
		if _, err := Run(context.Background(), Config{Scheme: "http", Host: u.Host, Raw: raw, Plus: true, PlusHosts: hosts}); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("host checks ran %d times for one host, want 1", hits.Load())
	}
}

func TestPlusHostHeaderPoisoning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<a href="http://%s/reset?token=1">Reset your password</a>`, r.Host)
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET /forgot HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "Host header poisoning") {
		t.Fatalf("expected Host header poisoning, got %v", got)
	}
	if !has(got, "Arbitrary Host header accepted") {
		t.Fatalf("over HTTP, answering any Host should be reported, got %v", got)
	}
}

func TestPlusXForwardedHostPoisoning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "127.0.0.1:") {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		host := r.Host
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			host = xfh
		}
		fmt.Fprintf(w, `<a href="http://%s/reset">Reset</a>`, host)
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET /forgot HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "Host header poisoning via X-Forwarded-Host") {
		t.Fatalf("expected poisoning via X-Forwarded-Host, got %v", got)
	}
	if has(got, "Arbitrary Host header accepted") {
		t.Fatalf("the server refuses other hosts: %v", got)
	}
}

func TestPlusEdgeSideInclude(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<p>%s</p>", strings.ReplaceAll(r.URL.Query().Get("q"), "<!--esi-->", ""))
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET /?q=hi HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "Edge Side Include injection in q") {
		t.Fatalf("expected ESI finding, got %v", got)
	}
}

func TestPlusInputTransformations(t *testing.T) {
	razor := regexp.MustCompile(`@\((\d+)\*(\d+)\)`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		quote := strings.ReplaceAll(q.Get("quote"), "''", "'")
		kelvin := strings.ReplaceAll(q.Get("name"), "K", "K")
		tpl := razor.ReplaceAllStringFunc(q.Get("tpl"), func(m string) string {
			p := razor.FindStringSubmatch(m)
			x, _ := strconv.Atoi(p[1])
			y, _ := strconv.Atoi(p[2])
			return strconv.Itoa(x * y)
		})
		fmt.Fprintf(w, "<p>%s</p><p>%s</p><p>%s</p>", quote, kelvin, tpl)
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET /?name=a&quote=b&tpl=c HTTP/1.1\r\nHost: HOST\r\n\r\n")
	for _, want := range []string{
		"(quote consumption) in quote",
		"(unicode normalisation) in name",
		"(template evaluation) in tpl",
	} {
		if !has(got, want) {
			t.Errorf("expected %q, got %v", want, got)
		}
	}
}

func TestPlusTemplateError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "${{") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "jinja2.exceptions.TemplateSyntaxError: unexpected '{'")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET /?q=hi HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "Template error triggered in q") {
		t.Fatalf("expected template error finding, got %v", got)
	}
}

func TestPlusXMLInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == "application/xml" {
			fmt.Fprint(w, "<error><message>malformed XML</message></error>")
			return
		}
		fmt.Fprint(w, "<html><p>saved</p></html>")
	}))
	defer srv.Close()
	got := runPlus(t, srv, "POST /api/save HTTP/1.1\r\nHost: HOST\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	if !has(got, "XML input supported") {
		t.Fatalf("expected XML input finding, got %v", got)
	}
}

func TestPlusRailsAccept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "e*c/h*s*s") {
			fmt.Fprint(w, "127.0.0.1\tlocalhost\n")
			return
		}
		fmt.Fprint(w, "<html>page</html>")
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET /docs HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "CVE-2019-5418") {
		t.Fatalf("expected Rails file disclosure, got %v", got)
	}
}

func TestPlusServerAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method == http.MethodPost && r.Header.Get("Next-Action") != "" && bytes.Contains(body, []byte(`["$1:a:a"]`)) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `0:{"a":"$@1"}`+"\n"+`1:E{"digest":"2971658870"}`)
			return
		}
		fmt.Fprint(w, "<html>home</html>")
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "CVE-2025-55182") {
		t.Fatalf("expected the React Server Components finding, got %v", got)
	}
}

func TestPlusPHP2Shell(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		body, _ := io.ReadAll(r.Body)
		if c, err := r.Cookie("PHPSESSID"); err == nil && c.Value == "_" && bytes.Contains(body, []byte("PHP_SESSION_UPLOAD_PROGRESS")) {
			fmt.Fprint(w, "<b>Warning</b>: session_start(): "+phpSessionInvalid+"\n"+
				"<b>Warning</b>: session_start(): "+phpSessionRead+"\n"+
				"<b>Warning</b>: Unknown: "+phpSessionWrite+"files)")
			return
		}
		fmt.Fprint(w, "<html>home</html>")
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "PHP2Shell (CVE-2026-109618") {
		t.Fatalf("expected the PHP2Shell probe finding, got %v", got)
	}
	if !has(got, "PHP version affected by PHP2Shell") {
		t.Fatalf("expected the PHP version finding, got %v", got)
	}
}

func TestPHP2ShellAffectedVersions(t *testing.T) {
	for v, want := range map[string]bool{
		"PHP/7.4.33":           true,
		"PHP/8.1.2":            true,
		"PHP/8.2.34":           true,
		"PHP/8.2.35":           false,
		"PHP/8.3.36RC1":        true,
		"PHP/8.4.27":           false,
		"PHP/8.5":              false, // no patch level: can't tell
		"Apache/2.4 PHP/8.3.1": true,
		"PHP/9.0.0":            false,
	} {
		m := phpVersionRe.FindStringSubmatch(v)
		if m == nil {
			t.Fatalf("%s: version not found", v)
		}
		if got := php2ShellAffected(m); got != want {
			t.Errorf("%s: affected = %v, want %v", v, got, want)
		}
	}
	if phpVersionRe.MatchString("MyPHP/8.1.0") {
		t.Error("a product merely ending in PHP is not PHP")
	}
}

func TestPlusGoogleAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<script>initMap({key: "AIzaSyD-1234567890abcdefghijklmnopqrstu"})</script>`)
	}))
	defer srv.Close()
	got := runPlus(t, srv, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n")
	if !has(got, "Google API key in response") {
		t.Fatalf("expected the API key finding, got %v", got)
	}
}

func TestPlusProbesBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		fmt.Fprintf(w, "<p>Welcome %s</p>", user)
	}))
	defer srv.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	got := runPlus(t, srv, "GET /account HTTP/1.1\r\nHost: HOST\r\nAuthorization: Basic "+auth+"\r\n\r\n")
	if !has(got, "Reflected input in basic-auth user") {
		t.Fatalf("expected the Basic auth user to be probed, got %v", got)
	}
}

const samlDoc = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_8e8dc5f69a98cc4c" Version="2.0"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_d71a3a8e9fcc45c9"/></samlp:Response>`

// samlSP is a service provider that logs in on any well-formed response and,
// unless strict, doesn't mind a DTD in it.
func samlSP(strict bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, _, ok := decodeSAML(r.URL.Query().Get("SAMLResponse"))
		if !ok || !strings.Contains(doc, "<samlp:Response") || strict && strings.Contains(doc, "<!DOCTYPE") {
			fmt.Fprint(w, "<html><form><p>Login failed</p></form></html>")
			return
		}
		http.Redirect(w, r, "/home", http.StatusFound)
	}))
}

func TestPlusSAMLAcceptsDTD(t *testing.T) {
	for _, deflated := range []bool{false, true} {
		value := encodeSAML(samlDoc, deflated)
		raw := "GET /acs?SAMLResponse=" + url.QueryEscape(value) + " HTTP/1.1\r\nHost: HOST\r\n\r\n"

		lax := samlSP(false)
		got := runPlus(t, lax, raw)
		lax.Close()
		for _, want := range []string{"SAML message with DOCTYPE accepted", "SAML message with external entity accepted"} {
			if !has(got, want) {
				t.Errorf("deflated=%v: expected %q, got %v", deflated, want, got)
			}
		}

		strict := samlSP(true)
		got = runPlus(t, strict, raw)
		strict.Close()
		if has(got, "SAML message") {
			t.Errorf("deflated=%v: a parser refusing DTDs was reported: %v", deflated, got)
		}
	}
}

func TestSAMLRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write([]byte(samlDoc))
	w.Close()
	for name, value := range map[string]string{
		"post":     base64.StdEncoding.EncodeToString([]byte(samlDoc)),
		"redirect": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"spaces":   strings.ReplaceAll(base64.StdEncoding.EncodeToString(buf.Bytes()), "+", " "),
	} {
		doc, _, ok := decodeSAML(value)
		if !ok || doc != samlDoc {
			t.Errorf("%s: decoded %q, %v", name, html.EscapeString(doc), ok)
		}
	}
	if _, _, ok := decodeSAML("not base64 at all"); ok {
		t.Error("garbage decoded as a SAML message")
	}
}

func TestPlanSitePlusIncludesRequestsWithoutParameters(t *testing.T) {
	const host = "shop.example"
	flows := []*proxy.Flow{
		flowOf("GET", host, "/about", ""),
		flowOf("GET", host, "/about", ""),
		flowOf("GET", host, "/logo.png", ""),
	}
	if p := PlanSite(flows, func(string) bool { return true }, SiteOptions{}); len(p.Safe) != 0 {
		t.Fatalf("without Plus, /about has nothing to probe: %d planned", len(p.Safe))
	}
	p := PlanSite(flows, func(string) bool { return true }, SiteOptions{Plus: true})
	if len(p.Safe) != 1 || p.Safe[0] != flows[0] {
		t.Fatalf("with Plus, want /about once and no static file, got %d", len(p.Safe))
	}
}
