package activescan

// The Plus checks port PortSwigger's ActiveScan++
// (https://github.com/PortSwigger/active-scan-plus-plus, Apache License 2.0)
// to Kanca. Like the rest of the package they only look for signs of an issue.
// Left out are the checks that need an out-of-band interaction server (Solr,
// Struts S2-052 and S2-053, blind XXE), the blind code-injection and Struts
// S2-045 probes, which make the target run injected code, and JetLeak, which
// needs a NUL byte in a header.
//
// They run at three levels: once per host (plusHost), once per request
// (plusRequest) and once per insertion point (plusParam).

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// HostSet remembers hosts. It is safe for concurrent use, and its zero value
// is ready to use.
type HostSet struct {
	mu   sync.Mutex
	seen map[string]bool
}

// claim reports whether host is new, and remembers it. A nil set never
// remembers anything.
func (s *HostSet) claim(host string) bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if s.seen[host] {
		return false
	}
	s.seen[host] = true
	return true
}

// plusHost runs the checks that concern the whole host.
func (r *runner) plusHost() {
	if !r.cfg.PlusHosts.claim(r.cfg.Scheme + "://" + strings.ToLower(r.cfg.Host)) {
		return
	}
	r.checkInterestingFiles()
	r.checkServerAction()
	r.checkPHPSession()
}

// plusRequest runs the checks that concern the base request as a whole.
func (r *runner) plusRequest() {
	r.checkPHPVersion()
	r.checkGoogleAPIKey()
	r.checkHostHeader()
	r.checkXMLInput()
	r.checkRailsAccept()
}

// plusParam runs the checks for one insertion point.
func (r *runner) plusParam(ip insertionPoint) {
	r.checkESI(ip)
	r.checkTransforms(ip)
	r.checkErrorFuzz(ip)
	r.checkSAML(ip)
}

// ---- requests --------------------------------------------------------------

// clone returns a copy of the base request to change.
func (r *runner) clone() *http.Request {
	return r.req.Clone(context.Background())
}

// sendReq sends req with body to the scanned host.
func (r *runner) sendReq(req *http.Request, body []byte) *proxy.Flow {
	return r.dispatch(proxy.SerializeRequest(req, body), false)
}

// get fetches path on the scanned host as a GET without a body. The base
// request's other headers stay, so cookies still apply.
func (r *runner) get(path string) *proxy.Flow {
	req := r.clone()
	req.Method = http.MethodGet
	req.URL.Path, req.URL.RawPath, req.URL.RawQuery = path, "", ""
	req.Header.Del("Content-Type")
	return r.sendReq(req, nil)
}

// post starts a POST to path on the scanned host, keeping the base request's
// other headers.
func (r *runner) post(path, contentType string) *http.Request {
	req := r.clone()
	req.Method = http.MethodPost
	req.URL.Path, req.URL.RawPath, req.URL.RawQuery = path, "", ""
	req.Header.Set("Content-Type", contentType)
	return req
}

// rootURL is the scanned host's root, the URL of host-level findings.
func (r *runner) rootURL() string {
	return r.cfg.Scheme + "://" + r.cfg.Host + "/"
}

// basicAuthPoints turns the user name and password of an Authorization: Basic
// header into insertion points.
func basicAuthPoints(baseReq *http.Request, baseBody []byte) []insertionPoint {
	user, pass, ok := baseReq.BasicAuth()
	if !ok {
		return nil
	}
	point := func(label, orig string, creds func(value string) (string, string)) insertionPoint {
		return insertionPoint{
			label: label, where: "header", orig: orig,
			build: func(value string) []byte {
				c := baseReq.Clone(context.Background())
				c.SetBasicAuth(creds(value))
				return proxy.SerializeRequest(c, baseBody)
			},
		}
	}
	return []insertionPoint{
		point("basic-auth user", user, func(v string) (string, string) { return v, pass }),
		point("basic-auth password", pass, func(v string) (string, string) { return user, v }),
	}
}

// ---- misc helpers ----------------------------------------------------------

const randomChars = "abcdefghijklmnopqrstuvwxyz0123456789"

// randomString returns n random lower-case letters and digits, for canaries
// that can't already be in a response. Lower case survives servers that fold
// the Host header.
func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = randomChars[rand.IntN(len(randomChars))]
	}
	return string(b)
}

// randomUUID returns a random version 4 UUID.
func randomUUID() string {
	return fmt.Sprintf("%08x-%04x-4%03x-%04x-%012x",
		rand.Uint32(), rand.IntN(1<<16), rand.IntN(1<<12), 0x8000|rand.IntN(1<<14), rand.Uint64()&(1<<48-1))
}

var tagRe = regexp.MustCompile(`(?i)<[a-z]+`)

// tagmap reduces a page to the sequence of its opening tags: its structure,
// without the text that changes from one response to the next.
func tagmap(body string) string {
	return strings.Join(tagRe.FindAllString(body, -1), "")
}
