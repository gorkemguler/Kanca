package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
)

// builtinHost is the hostname the proxy answers itself, like Burp's http://burp:
// browsing to http://kanca/ through the proxy shows a status page and offers the
// root CA for download. Such requests are neither forwarded nor recorded.
const builtinHost = "kanca"

// serveBuiltinIfTargeted answers requests addressed to the proxy itself and
// reports whether it did. That covers absolute-form requests for http://kanca/
// (a browser routed through the proxy) and origin-form requests, which only
// arrive when something talks to the listener directly rather than through it.
func (p *Proxy) serveBuiltinIfTargeted(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Host == "" {
		// Origin-form is never a proxy request. Answer only when the Host header
		// names this machine; anything else (e.g. a DNS-rebound page) must not be
		// relayed onward.
		if !p.isOwnHost(r.Host) {
			http.Error(w, "Kanca is an HTTP proxy: configure your browser to use it instead of requesting it directly.", http.StatusBadRequest)
			return true
		}
		p.serveBuiltin(w, r, false)
		return true
	}
	if isBuiltinAuthority(r.URL.Host) {
		p.serveBuiltin(w, r, true)
		return true
	}
	return false
}

// isBuiltinAuthority reports whether a request targets the proxy's own name.
func isBuiltinAuthority(authority string) bool {
	return strings.EqualFold(hostOnly(authority), builtinHost)
}

// serveBuiltinTunnel answers a request that came through a CONNECT tunnel to
// the proxy's own name. Over TLS (https://kanca/) the browser only gets an
// answer if it trusts Kanca's certificate, which is how the extension and the
// status page tell whether HTTPS interception will work.
func (p *Proxy) serveBuiltinTunnel(conn net.Conn, req *http.Request) error {
	rec := &bufferedResponse{header: http.Header{}, code: http.StatusOK}
	p.serveBuiltin(rec, req, true)
	resp := &http.Response{
		StatusCode: rec.code, ProtoMajor: 1, ProtoMinor: 1,
		Header: rec.header, Body: io.NopCloser(&rec.body),
		ContentLength: int64(rec.body.Len()), Request: req,
	}
	return resp.Write(conn)
}

// bufferedResponse collects a handler's response so it can be written onto a
// raw tunnel connection.
type bufferedResponse struct {
	header http.Header
	code   int
	wrote  bool
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) {
	if !b.wrote {
		b.code, b.wrote = code, true
	}
}

func (b *bufferedResponse) Write(data []byte) (int, error) {
	b.wrote = true
	return b.body.Write(data)
}

func (p *Proxy) isOwnHost(hostport string) bool {
	h := strings.ToLower(hostOnly(hostport))
	switch h {
	case builtinHost, "localhost", "127.0.0.1", "::1":
		return true
	}
	listen := hostOnly(p.Addr())
	return listen != "" && listen != "0.0.0.0" && listen != "::" && h == strings.ToLower(listen)
}

// serveBuiltin renders the proxy's own pages. proxied is true when the request
// came through the proxy (the browser is routed via Kanca).
func (p *Proxy) serveBuiltin(w http.ResponseWriter, r *http.Request, proxied bool) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/status":
		// Kanca's own page checks https://kanca/status to see whether this
		// browser trusts the certificate.
		if origin := r.Header.Get("Origin"); origin == "http://"+builtinHost || origin == "https://"+builtinHost {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kanca":   true,
			"proxied": proxied,
			"listen":  p.Addr(),
		})
	case "/cert", "/kanca-ca.crt":
		if p.ca == nil {
			http.Error(w, "no certificate authority configured", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="kanca-ca.crt"`)
		_, _ = w.Write(p.ca.RootCertPEM())
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, builtinPage(proxied, p.Addr()))
	default:
		http.NotFound(w, r)
	}
}

func builtinPage(proxied bool, addr string) string {
	status := `<p class="ok">&#10003; This browser is routed through Kanca.</p>`
	if !proxied {
		status = `<p class="warn">Kanca is running, but this page was opened directly. Point your browser's HTTP and HTTPS proxy at <code>` +
			html.EscapeString(addr) + `</code>, or switch it on with the Kanca browser extension.</p>`
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Kanca</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{margin:0;background:#16181d;color:#d7dae0;font:15px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:640px;margin:48px auto;padding:0 20px}
h1{display:flex;align-items:center;gap:10px;color:#e8792b;letter-spacing:.5px;font-size:24px;margin:0 0 4px}
.sub{color:#8b929e;margin:0 0 24px}
.ok{color:#4caf72}.warn{color:#e3b341}
code{background:#23262f;padding:1px 6px;border-radius:4px}
a.btn{display:inline-block;background:#e8792b;color:#16181d;font-weight:600;text-decoration:none;padding:9px 16px;border-radius:6px;margin:8px 0 20px}
h2{font-size:15px;margin:22px 0 6px}
ul{padding-left:20px;margin:0}li{margin:4px 0}
.dim{color:#8b929e;font-size:13px;margin-top:28px}
.dim-inline{color:#8b929e}
</style></head><body><main>
<h1><svg viewBox="0 0 256 256" width="28" height="28" aria-hidden="true"><g fill="none" stroke="#e8792b" stroke-width="22" stroke-linecap="round" stroke-linejoin="round"><circle cx="150" cy="58" r="18"/><path d="M150 76 L150 150 C150 182 150 198 126 198 C100 198 86 178 86 154 C86 138 95 128 108 124"/><path d="M108 124 L96 140"/></g><rect x="120" y="150" width="22" height="22" rx="5" transform="rotate(45 131 161)" fill="#4a9eff"/></svg>KANCA</h1>
<p class="sub">intercepting proxy</p>
` + status + `
<p id="https-check" class="dim-inline">Checking whether this browser trusts Kanca&rsquo;s certificate&hellip;</p>
<h2>Intercept HTTPS: trust the Kanca root certificate</h2>
<a class="btn" href="/cert">Download CA certificate</a>
<ul>
<li><b>macOS</b> &mdash; easiest: in the Kanca app, click <i>Trust certificate</i> (or <i>CA / Settings &rarr; Install on this Mac</i>) and approve with Touch ID or your password. Double-clicking <code>kanca-ca.crt</code> only adds it to the keychain: you then still have to open &ldquo;Kanca Root CA&rdquo; in Keychain Access and set <i>Trust &rarr; When using this certificate</i> to <i>Always Trust</i>.</li>
<li><b>Windows</b> &mdash; open <code>kanca-ca.crt</code> &rarr; <i>Install Certificate</i> &rarr; <i>Current User</i> &rarr; place it in <i>Trusted Root Certification Authorities</i>.</li>
<li><b>Firefox</b> &mdash; <i>Settings &rarr; Privacy &amp; Security &rarr; Certificates &rarr; View Certificates &rarr; Authorities &rarr; Import</i>, and tick &ldquo;Trust this CA to identify websites&rdquo;.</li>
<li><b>Chrome / Edge on Linux</b> &mdash; <i>Settings &rarr; Privacy and security &rarr; Security &rarr; Manage certificates &rarr; Authorities &rarr; Import</i>.</li>
</ul>
<p class="dim">Remove the certificate from your trust store when you are done testing. Use Kanca only against systems you are authorised to test.</p>
</main>
<script>
(function () {
  var el = document.getElementById("https-check");
  var ctrl = new AbortController();
  setTimeout(function () { ctrl.abort(); }, 4000);
  // https://kanca/ is answered by Kanca itself, so the request succeeds only if
  // this browser trusts Kanca's certificate.
  fetch("https://kanca/status", { cache: "no-store", signal: ctrl.signal })
    .then(function (r) { if (!r.ok) throw new Error(r.status); })
    .then(function () {
      el.className = "ok";
      el.textContent = "\u2713 HTTPS works: this browser trusts Kanca\u2019s certificate.";
    })
    .catch(function () {
      el.className = "warn";
      el.textContent = "\u2717 This browser doesn\u2019t trust Kanca\u2019s certificate yet, so HTTPS sites show warnings. Follow the steps below.";
    });
})();
</script>
</body></html>`
}
