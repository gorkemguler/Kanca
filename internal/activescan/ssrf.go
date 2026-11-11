package activescan

import (
	"regexp"
	"strings"

	"github.com/gorkemguler/kanca/internal/scanner"
)

// SSRF detection is best-effort without an out-of-band interaction server: it
// cannot confirm blind SSRF, where the server fetches a URL but puts nothing in
// the response. It looks for the two signals that do show in-band — cloud
// metadata reflected into the response, and a server-side fetch error that the
// baseline did not have — and reports them as leads to verify by hand. Because
// the probes make the target open connections to internal addresses, the check
// runs only under Aggressive.

// ssrfParamNames are parameter names that commonly carry a URL or host the
// server will fetch. Matching one makes a point worth probing even when its
// value doesn't already look like a URL.
var ssrfParamNames = map[string]bool{
	"url": true, "uri": true, "u": true, "link": true, "src": true, "source": true,
	"dest": true, "destination": true, "redirect": true, "redirect_uri": true,
	"redirecturl": true, "return": true, "returnurl": true, "next": true,
	"callback": true, "webhook": true, "callbackurl": true, "image": true,
	"imageurl": true, "img": true, "file": true, "path": true, "feed": true,
	"rss": true, "proxy": true, "fetch": true, "load": true, "host": true,
	"domain": true, "site": true, "target": true, "page": true, "data": true,
	"reference": true, "ref": true, "continue": true, "out": true, "to": true,
}

// ssrfURLish matches a value that already looks like a URL or a bare host, so a
// parameter named unhelpfully (e.g. "q") is still probed when its value is one.
var ssrfURLish = regexp.MustCompile(`(?i)^(https?://|//|www\.)|^[a-z0-9.-]+\.[a-z]{2,}(/|$|:)`)

// ssrfMetadataMarkers are strings from cloud metadata services. One appearing
// after a metadata probe (and not in the baseline) means the server fetched the
// internal address and handed its contents back.
var ssrfMetadataMarkers = []string{
	"ami-id", "instance-id", "instance-action", "security-credentials",
	"iam/security-credentials", "instance-identity", "local-ipv4",
	"computemetadata", "metadata.google.internal", "accountid",
}

// ssrfFetchErrors are fragments of the errors HTTP client libraries emit when a
// server-side fetch of a supplied URL fails. One appearing after a URL probe
// (and not in the baseline) shows the parameter is fetched server-side.
var ssrfFetchErrors = []string{
	"getaddrinfo", "econnrefused", "connection refused", "no route to host",
	"failed to open stream", "curl error", "couldn't connect to host",
	"could not resolve host", "name resolution", "dial tcp",
	"connection timed out", "unknownhostexception", "java.net.connectexception",
	"name or service not known", "network is unreachable", "connect econnrefused",
}

// ssrfCandidate reports whether an insertion point is worth an SSRF probe.
func ssrfCandidate(ip insertionPoint) bool {
	if ssrfParamNames[strings.ToLower(ip.label)] {
		return true
	}
	return ssrfURLish.MatchString(strings.TrimSpace(ip.orig))
}

// ssrfProbes are the URLs tried, in order. The metadata address is first since
// a hit there is the strongest signal; the loopback port is one nothing
// ordinarily serves, so a connection error names the server as the client.
var ssrfProbes = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://127.0.0.1:9/",
}

func (r *runner) checkSSRF(ip insertionPoint) {
	if !ssrfCandidate(ip) {
		return
	}
	for _, probe := range ssrfProbes {
		if r.ctx.Err() != nil {
			return
		}
		f := r.send(ip, probe)
		if f == nil {
			continue
		}
		lower := strings.ToLower(f.Response.DecodedBodyString())
		lowerProbe := strings.ToLower(probe)
		for _, m := range ssrfMetadataMarkers {
			// A marker that is part of the probe URL (e.g. "metadata.google.internal")
			// proves nothing when the server merely echoes the value back.
			if strings.Contains(lowerProbe, m) {
				continue
			}
			if strings.Contains(lower, m) && !strings.Contains(r.baseLower, m) {
				r.add(scanner.High, "Possible SSRF (cloud metadata) in "+ip.label,
					"Setting "+ip.where+" parameter '"+ip.label+"' to "+probe+" brought cloud metadata ('"+m+"') into the response that the baseline did not have: the server fetches the supplied URL and can reach its metadata service. Verify by hand.")
				return
			}
		}
		for _, e := range ssrfFetchErrors {
			if strings.Contains(lower, e) && !strings.Contains(r.baseLower, e) {
				r.add(scanner.Medium, "Possible SSRF in "+ip.label,
					"A URL in "+ip.where+" parameter '"+ip.label+"' produced a server-side fetch error ('"+e+"') absent from the baseline: the parameter value is fetched on the server. Point it at internal hosts to confirm SSRF.")
				return
			}
		}
	}
}
