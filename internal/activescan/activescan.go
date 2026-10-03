// Package activescan performs a small, bounded set of non-destructive probes
// against a single operator-chosen request to flag common web issue classes
// (input reflection, error-based injection indicators). It is detection-only:
// it never attempts exploitation, never sends destructive payloads, and is
// bounded in the number of requests it makes.
//
// It is intended strictly for authorised assessment of systems the operator
// owns or has explicit permission to test. Run it only inside your defined
// scope.
package activescan

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
)

// Config describes one active scan of a single base request.
type Config struct {
	Scheme string
	Host   string
	Raw    []byte // the base request, as raw HTTP/1.1 bytes

	// MaxParams caps how many query parameters are probed (default 20), so a
	// request with a huge query string cannot fan out without limit.
	MaxParams int
	// InsecureUpstream mirrors the proxy's interception posture.
	InsecureUpstream bool
}

// reflectionToken is a benign, unique marker injected to detect whether input
// is reflected verbatim into the response.
const reflectionToken = "kancaR3FL3CT0K"

// sqlErrorSignatures are substrings that commonly appear in database error
// messages. Their appearance after a single-quote probe (and absence from the
// baseline) is an error-based injection indicator — a lead to verify by hand,
// not a confirmed vulnerability.
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

// Run executes the probes and returns findings. It stops early on ctx
// cancellation. The base request is sent once for a baseline, then each probed
// parameter costs at most two extra requests.
func Run(ctx context.Context, cfg Config) ([]scanner.Finding, error) {
	if cfg.MaxParams <= 0 {
		cfg.MaxParams = 20
	}
	baseReq, err := proxy.ParseRawRequest(cfg.Raw, cfg.Scheme, cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("activescan: parse base request: %w", err)
	}
	sender := proxy.NewSender(proxy.SenderConfig{InsecureUpstream: cfg.InsecureUpstream})

	baseURL := cfg.Scheme + "://" + cfg.Host + baseReq.URL.RequestURI()
	query := baseReq.URL.Query()
	params := sortedKeys(query)
	if len(params) > cfg.MaxParams {
		params = params[:cfg.MaxParams]
	}

	// Baseline response, used to avoid reporting error strings that are always
	// present regardless of input.
	baseFlow := sender.Send(ctx, cfg.Raw, cfg.Scheme, cfg.Host)
	baseBody := strings.ToLower(baseFlow.Response.BodyString())

	var findings []scanner.Finding
	seq := int64(0)
	add := func(sev scanner.Severity, title, detail string) {
		seq++
		findings = append(findings, scanner.Finding{
			ID: seq, Severity: sev, Title: title, Detail: detail,
			Host: cfg.Host, URL: baseURL,
		})
	}

	if len(params) == 0 {
		// Nothing query-injectable; a reflected-input probe on the whole query
		// isn't meaningful, so report that there was nothing to probe.
		return findings, nil
	}

	for _, name := range params {
		if ctx.Err() != nil {
			break
		}
		orig := query.Get(name)

		// Probe 1: reflection. Inject a unique benign token.
		if body, ok := sendWithParam(ctx, sender, baseReq, cfg, query, name, reflectionToken); ok {
			if strings.Contains(body, reflectionToken) {
				add(scanner.Medium, "Reflected input in "+name,
					"The value of parameter '"+name+"' is reflected unmodified in the response; verify the output context for XSS.")
			}
		}

		// Probe 2: error-based indicator. Append a single quote (non-destructive).
		if body, ok := sendWithParam(ctx, sender, baseReq, cfg, query, name, orig+"'"); ok {
			lower := strings.ToLower(body)
			for _, sig := range sqlErrorSignatures {
				if strings.Contains(lower, sig) && !strings.Contains(baseBody, sig) {
					add(scanner.High, "Possible SQL injection in "+name,
						"A single-quote in parameter '"+name+"' triggered a database error signature ("+sig+") absent from the baseline; verify manually.")
					break
				}
			}
		}

		// Restore the parameter for subsequent probes.
		query.Set(name, orig)
	}

	return findings, nil
}

// sendWithParam sends a copy of the base request with one query parameter set
// to value, returning the response body and whether the send succeeded.
func sendWithParam(ctx context.Context, sender *proxy.Sender, baseReq *http.Request, cfg Config, query url.Values, name, value string) (string, bool) {
	q := cloneValues(query)
	q.Set(name, value)
	clone := baseReq.Clone(context.Background())
	clone.URL.RawQuery = q.Encode()
	// Active-scan probes target the query string only, so send no body.
	raw := proxy.SerializeRequest(clone, nil)

	f := sender.Send(ctx, raw, cfg.Scheme, cfg.Host)
	if f.Error != "" {
		return "", false
	}
	return f.Response.BodyString(), true
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
