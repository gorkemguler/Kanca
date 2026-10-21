package activescan

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
)

// ---- host level ------------------------------------------------------------

// interestingFiles are paths worth a look when their response contains marker.
var interestingFiles = []struct {
	path, marker, why string
	sev               scanner.Severity
}{
	{"/.git/config", "[core]", "the Git repository, and with it the source code and its history, may be downloadable", scanner.Medium},
	{"/server-status", "Server uptime", "Apache's status page lists the clients and the URLs they are requesting", scanner.Low},
	{"/.well-known/apple-app-site-association", "applinks", "it lists the paths iOS hands to the site's app as universal links", scanner.Info},
	{"/.well-known/openid-configuration", `"authorization_endpoint"`, "the OpenID metadata lists the OAuth endpoints and options, see https://portswigger.net/research/hidden-oauth-attack-vectors", scanner.Info},
	{"/.well-known/oauth-authorization-server", `"authorization_endpoint"`, "the OAuth metadata lists the endpoints and options, see https://portswigger.net/research/hidden-oauth-attack-vectors", scanner.Info},
	{"/users/confirmation", "onfirmation token", "sites built on Devise often have a race in email confirmation that confirms an address the user doesn't own, see https://portswigger.net/research/smashing-the-state-machine", scanner.Info},
}

func (r *runner) checkInterestingFiles() {
	for _, file := range interestingFiles {
		if r.ctx.Err() != nil {
			return
		}
		f := r.get(file.path)
		if f == nil || !strings.Contains(f.Response.DecodedBodyString(), file.marker) {
			continue
		}
		// A page served for every path would match too: the same path minus
		// its last character must not.
		g := r.get(file.path[:len(file.path)-1])
		if g == nil || strings.Contains(g.Response.DecodedBodyString(), file.marker) {
			continue
		}
		r.addAt(file.sev, "Interesting file: "+file.path,
			fmt.Sprintf("%s returned %q and a near-miss path didn't: %s.", file.path, file.marker, file.why),
			r.cfg.Scheme+"://"+r.cfg.Host+file.path)
	}
}

// checkServerAction looks for CVE-2025-55182 / CVE-2025-66478 in React Server
// Components (Next.js): a server action call whose argument references a
// property that doesn't exist. Patched servers reject it; vulnerable ones fail
// while resolving it and answer 500 with an error digest.
func (r *runner) checkServerAction() {
	boundary := "----WebKitFormBoundary" + randomString(16)
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"1\"\r\n\r\n{}\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"0\"\r\n\r\n[\"$1:a:a\"]\r\n" +
		"--" + boundary + "--\r\n"
	req := r.post("/", "multipart/form-data; boundary="+boundary)
	req.Header.Set("Next-Action", randomString(32))
	req.Header.Set("X-Nextjs-Request-Id", randomUUID())
	req.Header.Set("Next-Router-State-Tree", `[[["",{\"children\":[\"__PAGE__\",{}]},null,null,true]]`)
	f := r.sendReq(req, []byte(body))
	if f == nil || f.StatusCode != http.StatusInternalServerError {
		return
	}
	b := f.Response.DecodedBodyString()
	if strings.Contains(b, `E{"digest"`) || strings.Contains(b, "digest") && strings.Contains(b, "Error") {
		r.addAt(scanner.High, "React Server Components RCE (CVE-2025-55182 / CVE-2025-66478)",
			"A server action call referencing a missing property ([\"$1:a:a\"]) made the server fail with an error digest (HTTP 500) instead of rejecting it, as React and Next.js builds without the fix do. Upgrade React to 19.0.1, 19.1.2 or 19.2.1 and Next.js to a patched release (15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7 or later). See https://nextjs.org/blog/CVE-2025-66478.",
			r.rootURL())
	}
}

const (
	phpSessionInvalid = "Session ID is too long or contains illegal characters"
	phpSessionRead    = "Failed to read session data"
	phpSessionWrite   = "Failed to write session data ("
	php2ShellFix      = "8.2.35, 8.3.36, 8.4.27 or 8.5.12; 8.1 and older need a vendor backport"
)

// checkPHPSession looks for PHP2Shell (CVE-2026-109618 / CVE-2026-109619): an
// upload with an invalid session ID makes PHP fail to start the session, and
// only builds without the fix then try to write it anyway. It shows only where
// PHP displays its warnings.
func (r *runner) checkPHPSession() {
	boundary := randomString(24)
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n" + randomString(16) + "\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"f\"; filename=\"" + randomString(8) + ".txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n1\r\n" +
		"--" + boundary + "--\r\n"
	req := r.post("/", "multipart/form-data; boundary="+boundary)
	req.Header.Set("Cookie", "PHPSESSID=_")
	f := r.sendReq(req, []byte(body))
	if f == nil {
		return
	}
	b := f.Response.DecodedBodyString()
	if strings.Contains(b, phpSessionInvalid) && strings.Contains(b, phpSessionRead) && strings.Contains(b, phpSessionWrite) {
		r.addAt(scanner.High, "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
			"An upload with an invalid session cookie (PHPSESSID=_) made PHP report \""+phpSessionInvalid+"\" and \""+phpSessionRead+"\", and then also \"Failed to write session data\", which only builds without the fix do. Upgrade PHP ("+php2ShellFix+") and restart every PHP worker. See https://www.php.net/archive/2026.php.",
			r.rootURL())
	}
}

// ---- request level ---------------------------------------------------------

var (
	phpVersionRe = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])PHP/(\d+)\.(\d+)(?:\.(\d+))?([^\s;,()]*)`)
	preReleaseRe = regexp.MustCompile(`(?i)^-?(alpha|beta|rc|dev)`)
	// php2ShellFixed is the first fixed patch release of each supported branch.
	php2ShellFixed = map[string]int{"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
)

// php2ShellAffected reports whether a phpVersionRe match predates the
// PHP2Shell fix.
func php2ShellAffected(m []string) bool {
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major < 8 || major == 8 && minor < 2 {
		return true
	}
	fixed, ok := php2ShellFixed[m[1]+"."+m[2]]
	if !ok || m[3] == "" {
		return false
	}
	patch, _ := strconv.Atoi(m[3])
	return patch < fixed || patch == fixed && preReleaseRe.MatchString(m[4])
}

// checkPHPVersion reads the PHP version a response discloses.
func (r *runner) checkPHPVersion() {
	for _, name := range []string{"X-Powered-By", "Server"} {
		for _, v := range r.base.Response.Headers.Values(name) {
			m := phpVersionRe.FindStringSubmatch(v)
			if m == nil {
				continue
			}
			if php2ShellAffected(m) {
				version := "PHP/" + m[1] + "." + m[2]
				if m[3] != "" {
					version += "." + m[3] + m[4]
				}
				r.addAt(scanner.Medium, "PHP version affected by PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
					name+" discloses "+version+", which predates the fix ("+php2ShellFix+"). Distributions often backport fixes without changing the version, so check the package changelog before upgrading. Set expose_php = Off to stop disclosing it.",
					r.rootURL())
			}
			return
		}
	}
}

var googleKeyRe = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}\b`)

// checkGoogleAPIKey looks for Google API keys in the base response.
func (r *runner) checkGoogleAPIKey() {
	var keys []string
	seen := map[string]bool{}
	for _, k := range googleKeyRe.FindAllString(r.baseBody, -1) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	r.add(scanner.Info, "Google API key in response",
		"The response contains "+strings.Join(keys, ", ")+". If a key is unrestricted and the Generative Language API is enabled on its project, it also opens Gemini to anyone: uploaded files, cached content and the bill. Check its restrictions under APIs & Services → Credentials.")
}

// checkHostHeader looks for applications that build content from the Host
// header, which can poison password reset links and caches, and over plain
// HTTP for servers that answer any Host, which opens the door to DNS
// rebinding.
func (r *runner) checkHostHeader() {
	real := r.req.Host
	if real == "" || r.base.StatusCode == 0 || !strings.Contains(r.baseBody, real) {
		return
	}
	hostCanary, refCanary := randomString(6), randomString(6)
	forged := hostCanary + real
	attack := r.clone()
	// The Referer carries the forged host too: a page that echoes the Referer
	// shows refCanary as well and isn't counted.
	attack.Header.Set("Referer", "https://"+forged+"/"+refCanary)
	attack.Header.Set("Cache-Control", "no-cache")
	// A fresh cache key, so no one else is ever served a poisoned page.
	attack.URL.RawQuery = strings.TrimPrefix(attack.URL.RawQuery+"&cachebust="+randomString(6), "&")
	poisoned := func(f *proxy.Flow) bool {
		b := f.Response.DecodedBodyString()
		return strings.Contains(b, hostCanary) && !strings.Contains(b, refCanary)
	}

	viaHost := attack.Clone(context.Background())
	viaHost.Host = forged
	if f := r.dispatch(proxy.SerializeRequest(viaHost, r.reqBody), true); f != nil && f.StatusCode == r.base.StatusCode {
		if r.cfg.Scheme == "http" {
			r.addAt(scanner.Low, "Arbitrary Host header accepted",
				"The server answered Host: "+forged+" like its own name. If the site is meant to be reachable only internally, or restricts access by IP address, DNS rebinding can get around that through a visitor's browser; Host: localhost may also slip past weak access checks. See https://portswigger.net/web-security/host-header.",
				r.rootURL())
		}
		if poisoned(f) {
			r.add(scanner.Medium, "Host header poisoning",
				"The response to Host: "+forged+" contains "+hostCanary+": the application builds content from the Host header. A forged Host may poison password reset links or cached pages; also try server-side injection through it. See https://portswigger.net/web-security/host-header.")
			return
		}
	}

	viaXFH := attack.Clone(context.Background())
	viaXFH.Header.Set("X-Forwarded-Host", forged)
	if f := r.sendReq(viaXFH, r.reqBody); f != nil && f.StatusCode == r.base.StatusCode && poisoned(f) {
		r.add(scanner.Medium, "Host header poisoning via X-Forwarded-Host",
			"The response to X-Forwarded-Host: "+forged+" contains "+hostCanary+": the application builds content from that header. A forged value may poison password reset links or cached pages. See https://portswigger.net/web-security/host-header.")
	}
}

// checkXMLInput resends the body as application/xml. A page that changes
// structure, when a made-up type doesn't give the same page, suggests code
// that parses XML here.
func (r *runner) checkXMLInput() {
	if len(r.reqBody) == 0 {
		return
	}
	asXML := r.withHeader("Content-Type", "application/xml")
	if asXML == nil {
		return
	}
	xmlMap := tagmap(asXML.Response.DecodedBodyString())
	if xmlMap == tagmap(r.baseBody) {
		return
	}
	other := r.withHeader("Content-Type", "application/zml")
	if other == nil || tagmap(other.Response.DecodedBodyString()) == xmlMap {
		return
	}
	r.add(scanner.Info, "XML input supported",
		"Sent as application/xml, the request got a differently built page than as its own type or a made-up one (application/zml): the application seems to parse XML here. Test it for XXE and other XML parser issues.")
}

// checkRailsAccept looks for CVE-2019-5418: Rails renders a file named by a
// crafted Accept header. The glob matches /etc/hosts; a near-miss that matches
// nothing must not return it.
func (r *runner) checkRailsAccept() {
	const marker = "127.0.0.1"
	if strings.Contains(r.baseBody, marker) {
		return
	}
	f := r.withHeader("Accept", "../../../../../../../../../../../e*c/h*s*s{{")
	if f == nil || !strings.Contains(f.Response.DecodedBodyString(), marker) {
		return
	}
	g := r.withHeader("Accept", "../../../../../../../../../../../e*c/h*z*z{{")
	if g == nil || strings.Contains(g.Response.DecodedBodyString(), marker) {
		return
	}
	r.add(scanner.High, "Rails file disclosure (CVE-2019-5418)",
		"With Accept: ../../e*c/h*s*s{{ the response contained /etc/hosts (127.0.0.1), and with a glob that matches nothing it didn't: Rails renders files named in the Accept header. Upgrade Rails; verify manually.")
}

// withHeader sends the base request with one header set to value.
func (r *runner) withHeader(name, value string) *proxy.Flow {
	req := r.clone()
	req.Header.Set(name, value)
	return r.sendReq(req, r.reqBody)
}
