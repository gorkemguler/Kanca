package activescan

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/gorkemguler/kanca/internal/scanner"
)

// checkESI sends an ESI comment next to a look-alike one. If only the real one
// disappears, an ESI processor (often a cache or CDN) handles the response.
func (r *runner) checkESI(ip insertionPoint) {
	a, b, c := randomString(4), randomString(4), randomString(4)
	f := r.send(ip, a+"<!--esi-->"+b+"<!--esx-->"+c)
	if f == nil {
		return
	}
	if strings.Contains(f.Response.DecodedBodyString(), a+b+"<!--esx-->"+c) {
		r.add(scanner.High, "Possible Edge Side Include injection in "+ip.label,
			"An <!--esi--> comment sent in "+ip.where+" parameter '"+ip.label+"' was removed from the response while a look-alike <!--esx--> was kept: ESI is processed here. Injected ESI tags may include other URLs or get past XSS filters; verify manually. See https://gosecure.net/2018/04/03/beyond-xss-edge-side-include-injection/.")
	}
}

// transform probes for one way an application may rewrite input: the payload
// goes in, and any of the expected strings coming back gives it away.
type transform struct {
	name  string
	sev   scanner.Severity
	means string
	ref   string
	probe func() (payload string, expect []string)
	// notJSON marks payloads that aren't valid UTF-8, which JSON can't carry.
	notJSON bool
}

const (
	meansEval    = "the input is evaluated as code, a lead for code or template injection"
	meansRewrite = "input changing this way can carry a payload past filters that run earlier"
	sstiRef      = "https://portswigger.net/research/server-side-template-injection"
	overflowRef  = "https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows"
)

// transforms are ActiveScan++'s input transformation probes. ${…} is covered
// by checkSSTI.
var transforms = []transform{
	{name: "quote consumption", sev: scanner.Medium, means: "a doubled quote comes back single, so the input probably ends up in a quoted string, e.g. SQL",
		probe: func() (string, []string) { return around("''", "'") }},
	{name: "arithmetic evaluation", sev: scanner.High, means: meansEval, probe: product("", "")},
	{name: "EL evaluation", sev: scanner.High, means: meansEval, ref: sstiRef, probe: product("%{", "}")},
	{name: "template evaluation", sev: scanner.High, means: meansEval, ref: sstiRef, probe: product("@(", ")")},
	{name: "unicode normalisation", sev: scanner.Medium, means: meansRewrite, ref: "https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/",
		probe: func() (string, []string) { return around("K", "K") }},
	{name: "URL decoding error", sev: scanner.Medium, means: meansRewrite, ref: "https://cwe.mitre.org/data/definitions/172.html",
		probe: func() (string, []string) { return around("Α", "N\u0011") }},
	{name: "unicode byte truncation", sev: scanner.Medium, means: meansRewrite, ref: overflowRef,
		probe: func() (string, []string) { return around("콻", "{") }},
	{name: "unicode case conversion", sev: scanner.Medium, means: meansRewrite, ref: "https://www.unicode.org/charts/case/index.html",
		probe: func() (string, []string) { return around("ı", "I") }},
	{name: "unicode combining diacritic", sev: scanner.Medium, means: meansRewrite, ref: "https://codepoints.net/combining_diacritical_marks",
		// U+0338 right after a '>' in the page normalises to U+226F.
		probe: func() (string, []string) { s := randomString(6); return "̸" + s, []string{"≯" + s} }},
	{name: "legacy URL decoding", sev: scanner.Medium, means: meansRewrite, ref: "https://datatracker.ietf.org/doc/html/rfc1738#section-2.2",
		probe: func() (string, []string) { return around("%ff", "ÿ") }},
	{name: "surrogate replacement", sev: scanner.Medium, means: meansRewrite, ref: "https://lab.ctbb.show/research/unicode-surrogates-to-replacement-characters", notJSON: true,
		// A lone surrogate (U+DC2A) as raw bytes; it has no valid UTF-8 form.
		probe: func() (string, []string) { return around("\xed\xb0\xaa", "?") }},
	{name: "unicode bitwise overflow", sev: scanner.Medium, means: meansRewrite, ref: overflowRef,
		probe: func() (string, []string) { return around("茶", "6") }},
	{name: "unicode space conversion", sev: scanner.Medium, means: meansRewrite, ref: "https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes",
		probe: func() (string, []string) { return around(" ", " ", "") }},
}

// around puts in, and each of out, between the same two random anchors.
func around(in string, out ...string) (string, []string) {
	left, right := randomString(6), randomString(6)
	expect := make([]string, len(out))
	for i, o := range out {
		expect[i] = left + o + right
	}
	return left + in + right, expect
}

// product returns a probe for x*y between prefix and suffix, expecting the
// result.
func product(prefix, suffix string) func() (string, []string) {
	return func() (string, []string) {
		x, y := 99+rand.IntN(9901), 99+rand.IntN(9901)
		return fmt.Sprintf("%s%d*%d%s", prefix, x, y, suffix), []string{strconv.Itoa(x * y)}
	}
}

// checkTransforms reports a transformation when it shows twice in a row, with
// fresh values each time.
func (r *runner) checkTransforms(ip insertionPoint) {
	for _, t := range transforms {
		if r.ctx.Err() != nil {
			return
		}
		if t.notJSON && ip.where == "json" {
			continue
		}
		var payload, hit string
		for attempt := 0; attempt < 2; attempt++ {
			p, expect := t.probe()
			hit = ""
			f := r.send(ip, p)
			if f == nil {
				break
			}
			body := f.Response.DecodedBodyString()
			for _, e := range expect {
				// Already in the page, or in the payload itself, it proves nothing.
				if strings.Contains(body, e) && !strings.Contains(r.baseBody, e) && !strings.Contains(p, e) {
					hit = e
					break
				}
			}
			if hit == "" {
				break
			}
			payload = p
		}
		if hit == "" {
			continue
		}
		detail := fmt.Sprintf("Sent %s in %s parameter '%s', the response contained %s, which the baseline doesn't (twice, with fresh values): %s. Verify manually.",
			strconv.QuoteToASCII(payload), ip.where, ip.label, strconv.QuoteToASCII(hit), t.means)
		if t.ref != "" {
			detail += " See " + t.ref + "."
		}
		r.add(t.sev, "Suspicious input transformation ("+t.name+") in "+ip.label, detail)
	}
}

// fuzzString breaks out of most quoting and template syntaxes at once.
const fuzzString = `a'a\'b"c>?>%}}%%>c<[[?${{%}}cake\`

// templateErrors and runtimeErrors are fragments of error pages, from template
// engines and from language runtimes and frameworks. They are matched against
// a lower-cased body. Database errors are left to checkSQLError.
var (
	templateErrors = []string{
		"jinja2.exceptions.",
		"django.template.exceptions",
		"freemarker.core.",
		"freemarker.template.templateexception",
		"org.apache.velocity.exception",
		"twig\\error\\syntaxerror",
		"twig_error_syntax",
		"smartycompilerexception",
		"mako.exceptions.",
		"liquid syntax error",
		"org.thymeleaf.exceptions",
		"com.mitchellbosecke.pebble",
	}
	runtimeErrors = []string{
		"traceback (most recent call last)",
		"werkzeug debugger",
		"you're seeing this error because you have",
		"java.lang.",
		"javax.servlet.servletexception",
		"org.springframework.",
		"whitelabel error page",
		"server error in '/' application",
		"system.nullreferenceexception",
		"system.formatexception",
		"<b>fatal error</b>:",
		"<b>parse error</b>:",
		"<b>warning</b>:",
		"fatal error: uncaught",
		"illuminate\\",
		"symfony\\component\\",
		"actioncontroller::",
		"actionview::template::error",
		"syntaxerror: unexpected token",
		"at json.parse",
		"runtime error: ",
		"unhandled exception",
	}
)

// checkErrorFuzz sends a string full of syntax characters and looks for an
// error page the baseline doesn't show.
func (r *runner) checkErrorFuzz(ip insertionPoint) {
	f := r.send(ip, fuzzString)
	if f == nil {
		return
	}
	lower := strings.ToLower(f.Response.DecodedBodyString())
	fresh := func(sigs []string) string {
		for _, sig := range sigs {
			if strings.Contains(lower, sig) && !strings.Contains(r.baseLower, sig) {
				return sig
			}
		}
		return ""
	}
	if sig := fresh(templateErrors); sig != "" {
		r.add(scanner.Medium, "Template error triggered in "+ip.label,
			"Syntax characters in "+ip.where+" parameter '"+ip.label+"' produced a template engine error ("+sig+") absent from the baseline: the input may reach a template. Verify for SSTI.")
		return
	}
	if sig := fresh(runtimeErrors); sig != "" {
		r.add(scanner.Low, "Error message triggered in "+ip.label,
			"Syntax characters in "+ip.where+" parameter '"+ip.label+"' produced an error message ("+sig+") absent from the baseline. It may disclose internals, and shows where input breaks the code; verify manually.")
	}
}
