// Package activescan performs a bounded set of probes against a single
// operator-chosen request to flag common web issue classes: reflected input and
// reflected XSS, error-based SQL injection, path traversal, open redirect,
// server-side template injection and CRLF/header injection. With Aggressive
// enabled it also runs boolean- and time-based SQL injection and time-based OS
// command injection probes — techniques that make the target do observable work
// and so are off by default.
//
// Every check is detection-only: it compares a probe response against a baseline
// and reports a lead to verify by hand. It never attempts exploitation, never
// sends destructive payloads, and bounds the number of insertion points it
// touches. Use it strictly for authorised assessment of systems you own or have
// explicit permission to test, and only inside your defined scope.
package activescan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
)

// Config describes one active scan of a single base request.
type Config struct {
	Scheme string
	Host   string
	Raw    []byte // the base request, as raw HTTP/1.1 bytes

	// MaxParams caps how many insertion points are probed (default 20), so a
	// request with a huge query string or body cannot fan out without limit.
	MaxParams int
	// InsecureUpstream mirrors the proxy's interception posture.
	InsecureUpstream bool
	// Aggressive enables boolean/time-based SQLi and time-based command-injection
	// probes. These cause the target to do measurable work (e.g. a bounded sleep)
	// and are therefore opt-in.
	Aggressive bool
	// TimeDelay is the delay a time-based probe asks the target to incur
	// (default 3s). Lower values make tests fast; it also tunes the detection
	// threshold.
	TimeDelay time.Duration
}

// reflectionToken is a benign, unique marker injected to detect whether input
// is reflected verbatim into the response.
const reflectionToken = "kancaR3FL3CT0K"

// oobHost is a benign, non-routable marker authority used by the open-redirect
// probe; a Location pointing at it indicates the parameter controls redirects.
const oobHost = "kanca-oob.invalid"

// crlfHeader is the marker header name the CRLF probe tries to inject.
const crlfHeader = "X-Kanca-Inject"

// sstiResult is 991*991; a distinctive product that appearing in the response
// (while the literal expression does not) indicates the expression was
// evaluated server-side.
const sstiResult = "982081"

// sqlErrorSignatures are substrings that commonly appear in database error
// messages. Their appearance after a single-quote probe (and absence from the
// baseline) is an error-based injection indicator — a lead to verify by hand.
var sqlErrorSignatures = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"pg_query()",
	"psql: error",
	"sqlite3.operationalerror",
	"sqlstate[",
	"ora-01756",
	"odbc sql server driver",
}

// lfiSignatures are substrings of well-known system files; seeing one (absent
// from the baseline) after a traversal probe indicates the parameter can reach
// the filesystem. Matching is done against a lower-cased body.
var lfiSignatures = []string{
	"root:x:0:0",
	"[extensions]",
	"[fonts]",
	"; for 16-bit app support",
}

// Run executes the probes and returns findings. It stops early on ctx
// cancellation.
func Run(ctx context.Context, cfg Config) ([]scanner.Finding, error) {
	if cfg.MaxParams <= 0 {
		cfg.MaxParams = 20
	}
	if cfg.TimeDelay <= 0 {
		cfg.TimeDelay = 3 * time.Second
	}
	baseReq, err := proxy.ParseRawRequest(cfg.Raw, cfg.Scheme, cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("activescan: parse base request: %w", err)
	}
	baseBody := readBody(baseReq)
	sender := proxy.NewSender(proxy.SenderConfig{InsecureUpstream: cfg.InsecureUpstream})

	// Baseline response, used to avoid reporting signals that are always present
	// regardless of input, and as the reference for timing/differential checks.
	baseFlow := sender.Send(ctx, cfg.Raw, cfg.Scheme, cfg.Host)
	r := &runner{
		ctx:      ctx,
		sender:   sender,
		cfg:      cfg,
		baseURL:  cfg.Scheme + "://" + cfg.Host + baseReq.URL.RequestURI(),
		baseBody: baseFlow.Response.BodyString(),
		baseDur:  baseFlow.Duration,
	}
	r.baseLower = strings.ToLower(r.baseBody)

	points := collectPoints(baseReq, baseBody, cfg.MaxParams)
	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		r.checkReflection(ip)
		r.checkSQLError(ip)
		r.checkTraversal(ip)
		r.checkOpenRedirect(ip)
		r.checkSSTI(ip)
		r.checkCRLF(ip)
		if cfg.Aggressive {
			r.checkBooleanSQL(ip)
			r.checkTimeBased(ip)
		}
	}
	return r.findings, nil
}

// runner carries per-scan state across the checks.
type runner struct {
	ctx       context.Context
	sender    *proxy.Sender
	cfg       Config
	baseURL   string
	baseBody  string
	baseLower string
	baseDur   int64 // baseline round-trip in milliseconds

	seq      int64
	findings []scanner.Finding
}

func (r *runner) add(sev scanner.Severity, title, detail string) {
	r.seq++
	r.findings = append(r.findings, scanner.Finding{
		ID: r.seq, Severity: sev, Title: title, Detail: detail,
		Host: r.cfg.Host, URL: r.baseURL,
	})
}

// send issues one probe against an insertion point and returns the flow, or nil
// on a transport error.
func (r *runner) send(ip insertionPoint, value string) *proxy.Flow {
	f := r.sender.Send(r.ctx, ip.build(value), r.cfg.Scheme, r.cfg.Host)
	if f.Error != "" {
		return nil
	}
	return f
}

// sendRaw issues a probe where value is already URL-encoded and must be placed
// verbatim (used by the CRLF probe, which needs a literal %0d%0a the server will
// decode). Points that cannot carry a raw value (e.g. JSON) have build only.
func (r *runner) sendRaw(ip insertionPoint, encoded string) *proxy.Flow {
	if ip.buildRaw == nil {
		return nil
	}
	f := r.sender.Send(r.ctx, ip.buildRaw(encoded), r.cfg.Scheme, r.cfg.Host)
	if f.Error != "" {
		return nil
	}
	return f
}

func (r *runner) checkReflection(ip insertionPoint) {
	// A benign marker plus the characters that matter for HTML/JS contexts. This
	// is not a working script — we only observe whether the server encodes them.
	special := reflectionToken + `"'<>`
	f := r.send(ip, special)
	if f == nil {
		return
	}
	body := f.Response.BodyString()
	if !strings.Contains(body, reflectionToken) {
		return
	}
	r.add(scanner.Medium, "Reflected input in "+ip.label,
		"The value of "+ip.where+" parameter '"+ip.label+"' is reflected unmodified in the response; verify the output context for XSS.")
	if strings.Contains(body, special) {
		r.add(scanner.High, "Possible reflected XSS in "+ip.label,
			"Characters < > \" ' injected via "+ip.where+" parameter '"+ip.label+"' are reflected unescaped; verify for XSS in the output context.")
	}
}

func (r *runner) checkSQLError(ip insertionPoint) {
	f := r.send(ip, ip.orig+"'")
	if f == nil {
		return
	}
	lower := strings.ToLower(f.Response.BodyString())
	for _, sig := range sqlErrorSignatures {
		if strings.Contains(lower, sig) && !strings.Contains(r.baseLower, sig) {
			r.add(scanner.High, "Possible SQL injection in "+ip.label,
				"A single-quote in "+ip.where+" parameter '"+ip.label+"' triggered a database error signature ("+sig+") absent from the baseline; verify manually.")
			return
		}
	}
}

func (r *runner) checkTraversal(ip insertionPoint) {
	for _, probe := range []string{
		"../../../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\windows\\win.ini",
	} {
		f := r.send(ip, probe)
		if f == nil {
			continue
		}
		lower := strings.ToLower(f.Response.BodyString())
		for _, sig := range lfiSignatures {
			if strings.Contains(lower, sig) && !strings.Contains(r.baseLower, sig) {
				r.add(scanner.High, "Possible path traversal in "+ip.label,
					"A traversal sequence in "+ip.where+" parameter '"+ip.label+"' returned a system-file signature ("+sig+") absent from the baseline; verify manually.")
				return
			}
		}
	}
}

func (r *runner) checkOpenRedirect(ip insertionPoint) {
	for _, probe := range []string{"https://" + oobHost + "/", "//" + oobHost + "/"} {
		f := r.send(ip, probe)
		if f == nil {
			continue
		}
		if f.StatusCode >= 300 && f.StatusCode < 400 {
			if loc := f.Response.Headers.Get("Location"); strings.Contains(loc, oobHost) {
				r.add(scanner.High, "Possible open redirect in "+ip.label,
					"Setting "+ip.where+" parameter '"+ip.label+"' to an external URL produced a redirect to it (Location: "+loc+"); verify manually.")
				return
			}
		}
	}
}

func (r *runner) checkSSTI(ip insertionPoint) {
	for _, probe := range []string{"${991*991}", "{{991*991}}", "#{991*991}"} {
		f := r.send(ip, probe)
		if f == nil {
			continue
		}
		body := f.Response.BodyString()
		// The product must appear while the literal expression does not: that
		// distinguishes evaluation from mere reflection.
		if strings.Contains(body, sstiResult) && !strings.Contains(r.baseLower, sstiResult) && !strings.Contains(body, probe) {
			r.add(scanner.High, "Possible template injection in "+ip.label,
				"An arithmetic expression ("+probe+") injected via "+ip.where+" parameter '"+ip.label+"' was evaluated server-side; verify for SSTI.")
			return
		}
	}
}

func (r *runner) checkCRLF(ip insertionPoint) {
	if ip.buildRaw == nil {
		return // can't carry a literal %0d%0a through this insertion point
	}
	encoded := url.QueryEscape(ip.orig) + "%0d%0a" + crlfHeader + ":1"
	f := r.sendRaw(ip, encoded)
	if f == nil {
		return
	}
	if f.Response.Headers.Get(crlfHeader) != "" {
		r.add(scanner.High, "Possible CRLF/header injection in "+ip.label,
			"An encoded CRLF in "+ip.where+" parameter '"+ip.label+"' was reflected into a response header ("+crlfHeader+"); verify for response splitting.")
	}
}

func (r *runner) checkBooleanSQL(ip insertionPoint) {
	tf := r.send(ip, ip.orig+"' AND '1'='1")
	ff := r.send(ip, ip.orig+"' AND '1'='2")
	if tf == nil || ff == nil {
		return
	}
	tb, fb := tf.Response.BodyString(), ff.Response.BodyString()
	// A boolean-injectable parameter makes the always-true response resemble the
	// baseline while the always-false response differs materially.
	if similarLen(tb, r.baseBody) && !similarLen(fb, r.baseBody) && !similarLen(tb, fb) {
		r.add(scanner.High, "Possible boolean-based SQL injection in "+ip.label,
			"True and false SQL conditions in "+ip.where+" parameter '"+ip.label+"' produced materially different responses; verify manually.")
	}
}

func (r *runner) checkTimeBased(ip insertionPoint) {
	// Only meaningful when the baseline is fast enough for a delay to stand out.
	if r.baseDur > 2000 {
		return
	}
	secs := int(r.cfg.TimeDelay.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	thresholdMs := r.baseDur + r.cfg.TimeDelay.Milliseconds()*2/3

	sqlProbes := []string{
		fmt.Sprintf("%s' AND SLEEP(%d)-- -", ip.orig, secs),
		fmt.Sprintf("%s'; WAITFOR DELAY '0:0:%d'-- -", ip.orig, secs),
	}
	if r.confirmDelay(ip, sqlProbes, thresholdMs) {
		r.add(scanner.High, "Possible time-based SQL injection in "+ip.label,
			"A time-delay SQL payload in "+ip.where+" parameter '"+ip.label+"' reproducibly delayed the response by ~"+fmt.Sprint(secs)+"s; verify manually.")
	}

	cmdProbes := []string{
		fmt.Sprintf("%s; sleep %d", ip.orig, secs),
		fmt.Sprintf("%s| sleep %d", ip.orig, secs),
		fmt.Sprintf("%s& ping -n %d 127.0.0.1", ip.orig, secs+1),
	}
	if r.confirmDelay(ip, cmdProbes, thresholdMs) {
		r.add(scanner.High, "Possible OS command injection in "+ip.label,
			"A time-delay shell payload in "+ip.where+" parameter '"+ip.label+"' reproducibly delayed the response by ~"+fmt.Sprint(secs)+"s; verify manually.")
	}
}

// confirmDelay returns true when a probe crosses the delay threshold twice in a
// row, which filters out one-off network jitter.
func (r *runner) confirmDelay(ip insertionPoint, probes []string, thresholdMs int64) bool {
	for _, p := range probes {
		if r.ctx.Err() != nil {
			return false
		}
		f := r.send(ip, p)
		if f == nil || f.Duration < thresholdMs {
			continue
		}
		f2 := r.send(ip, p)
		if f2 != nil && f2.Duration >= thresholdMs {
			return true
		}
	}
	return false
}

// ---- insertion points ------------------------------------------------------

// insertionPoint is one place a probe value can be substituted. build renders a
// request with value URL-encoded normally; buildRaw (when non-nil) places an
// already-encoded value verbatim, for probes that must carry literal metacharacters.
type insertionPoint struct {
	label    string // bare parameter name / JSON path, used in finding titles
	where    string // "query" | "body" | "json", used in finding detail
	orig     string // original value
	build    func(value string) []byte
	buildRaw func(encoded string) []byte
}

// collectPoints builds insertion points from the query string and, when the
// body is form-urlencoded or JSON, from its fields. It caps the total at max.
func collectPoints(baseReq *http.Request, baseBody []byte, max int) []insertionPoint {
	var pts []insertionPoint

	query := baseReq.URL.Query()
	for _, name := range sortedKeys(query) {
		name, orig := name, query.Get(name)
		pts = append(pts, insertionPoint{
			label: name, where: "query", orig: orig,
			build: func(value string) []byte {
				q := cloneValues(query)
				q.Set(name, value)
				c := baseReq.Clone(context.Background())
				c.URL.RawQuery = q.Encode()
				return proxy.SerializeRequest(c, baseBody)
			},
			buildRaw: func(encoded string) []byte {
				c := baseReq.Clone(context.Background())
				c.URL.RawQuery = rawQuery(query, name, encoded)
				return proxy.SerializeRequest(c, baseBody)
			},
		})
	}

	ct := strings.ToLower(baseReq.Header.Get("Content-Type"))
	switch {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded") && len(baseBody) > 0:
		if form, err := url.ParseQuery(string(baseBody)); err == nil {
			for _, name := range sortedKeys(form) {
				name, orig := name, form.Get(name)
				pts = append(pts, insertionPoint{
					label: name, where: "body", orig: orig,
					build: func(value string) []byte {
						fm := cloneValues(form)
						fm.Set(name, value)
						return proxy.SerializeRequest(baseReq.Clone(context.Background()), []byte(fm.Encode()))
					},
					buildRaw: func(encoded string) []byte {
						return proxy.SerializeRequest(baseReq.Clone(context.Background()), []byte(rawQuery(form, name, encoded)))
					},
				})
			}
		}
	case strings.Contains(ct, "application/json") && len(baseBody) > 0:
		var root interface{}
		if json.Unmarshal(baseBody, &root) == nil {
			var paths [][]interface{}
			collectJSONStringPaths(root, nil, &paths)
			for _, p := range paths {
				p := p
				orig, _ := getJSONPath(root, p).(string)
				pts = append(pts, insertionPoint{
					label: jsonPathLabel(p), where: "json", orig: orig,
					build: func(value string) []byte {
						var fresh interface{}
						_ = json.Unmarshal(baseBody, &fresh)
						setJSONPath(fresh, p, value)
						nb, _ := json.Marshal(fresh)
						return proxy.SerializeRequest(baseReq.Clone(context.Background()), nb)
					},
				})
			}
		}
	}

	if len(pts) > max {
		pts = pts[:max]
	}
	return pts
}

// rawQuery renders values into a query string, substituting target's value with
// an already-encoded literal and leaving the rest normally encoded.
func rawQuery(values url.Values, target, encoded string) string {
	parts := make([]string, 0, len(values))
	for _, k := range sortedKeys(values) {
		if k == target {
			parts = append(parts, url.QueryEscape(k)+"="+encoded)
		} else {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(values.Get(k)))
		}
	}
	return strings.Join(parts, "&")
}

// ---- JSON path helpers -----------------------------------------------------

// collectJSONStringPaths records the path to every string leaf, descending maps
// (keys sorted for determinism) and arrays.
func collectJSONStringPaths(node interface{}, prefix []interface{}, out *[][]interface{}) {
	switch v := node.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectJSONStringPaths(v[k], appendSeg(prefix, k), out)
		}
	case []interface{}:
		for i, e := range v {
			collectJSONStringPaths(e, appendSeg(prefix, i), out)
		}
	case string:
		*out = append(*out, appendSeg(prefix))
	}
}

func appendSeg(prefix []interface{}, segs ...interface{}) []interface{} {
	out := make([]interface{}, 0, len(prefix)+len(segs))
	out = append(out, prefix...)
	return append(out, segs...)
}

func getJSONPath(node interface{}, path []interface{}) interface{} {
	cur := node
	for _, seg := range path {
		switch s := seg.(type) {
		case string:
			m, ok := cur.(map[string]interface{})
			if !ok {
				return nil
			}
			cur = m[s]
		case int:
			a, ok := cur.([]interface{})
			if !ok || s < 0 || s >= len(a) {
				return nil
			}
			cur = a[s]
		}
	}
	return cur
}

func setJSONPath(root interface{}, path []interface{}, value string) {
	if len(path) == 0 {
		return
	}
	cur := root
	for _, seg := range path[:len(path)-1] {
		switch s := seg.(type) {
		case string:
			m, ok := cur.(map[string]interface{})
			if !ok {
				return
			}
			cur = m[s]
		case int:
			a, ok := cur.([]interface{})
			if !ok || s < 0 || s >= len(a) {
				return
			}
			cur = a[s]
		}
	}
	switch s := path[len(path)-1].(type) {
	case string:
		if m, ok := cur.(map[string]interface{}); ok {
			m[s] = value
		}
	case int:
		if a, ok := cur.([]interface{}); ok && s >= 0 && s < len(a) {
			a[s] = value
		}
	}
}

func jsonPathLabel(path []interface{}) string {
	var b strings.Builder
	for i, seg := range path {
		switch s := seg.(type) {
		case string:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(s)
		case int:
			fmt.Fprintf(&b, "[%d]", s)
		}
	}
	return b.String()
}

// ---- misc helpers ----------------------------------------------------------

// similarLen reports whether two bodies are close in size (within 5%, or 32
// bytes for small bodies) — a cheap stand-in for response equivalence.
func similarLen(a, b string) bool {
	la, lb := len(a), len(b)
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	max := la
	if lb > max {
		max = lb
	}
	tol := max / 20
	if tol < 32 {
		tol = 32
	}
	return diff <= tol
}

func readBody(req *http.Request) []byte {
	if req.Body == nil {
		return nil
	}
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	return b
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func sortedKeys(v url.Values) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
