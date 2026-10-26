package activescan

// The crash probe is ported from pentestershell/php2shellbt (MIT). It detects
// the PHP2Shell memory-corruption path (CVE-2026-109618 / CVE-2026-109619)
// even when display_errors is off, where checkPHPSession sees nothing: it sends
// a large malformed multipart body and watches for the worker dying. Because it
// strains the target, it runs only under Aggressive.
//
// It is detection-only: it never forges heap structures or runs code, unlike
// the weaponised exploits published for the same bug.

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
)

// crashProbe is one malformed body, sized in MiB with a number of nested-array
// parts. The sizes come from the upstream tool.
type crashProbe struct{ sizeMiB, parts int }

var crashProbes = []crashProbe{{1, 4000}, {8, 1020}, {20, 1020}}

// crashNestedKeys is the array nesting depth in each part, deep enough to make
// cleanup of the parsed body expensive.
const crashNestedKeys = 62

// crashControlBody is a minimal, well-formed multipart body. Its response is
// the baseline a probe response is judged against.
var crashControlBody = []byte("--x\nContent-Disposition:name=a;filename=\n\n")

// crashRejected are the statuses a proxy or WAF returns when it refuses an
// oversized body; once one appears, larger probes are pointless.
var crashRejected = map[int]bool{
	400: true, 403: true, 411: true, 413: true, 414: true,
	417: true, 422: true, 429: true, 431: true,
}

// buildCrashProbe builds a malformed multipart body of about sizeMiB with parts
// deeply nested array fields, padded with filler lines.
func buildCrashProbe(sizeMiB, parts int) []byte {
	size := sizeMiB << 20
	name := append([]byte("a[]"), bytes.Repeat([]byte("[a]"), crashNestedKeys)...)
	part := append(append([]byte("--\nContent-Disposition:name="), name...), []byte(";filename=\n\n")...)
	base := bytes.Repeat(part, parts)
	if size <= len(base) {
		return base // already at least the target size
	}
	filler := (size - len(base)) / 3
	var b bytes.Buffer
	b.Grow(size)
	b.WriteString("--\n")
	for i := 0; i < filler; i++ {
		b.WriteString("x:\n")
	}
	b.Write(base[3:])
	out := b.Bytes()
	return out[:len(out)-1]
}

// checkCrashProbe sends a control request, then the probes, and reports when a
// probe kills the request handler.
func (r *runner) checkCrashProbe() {
	path := r.req.URL.Path
	if path == "" {
		path = "/"
	}
	ctrl := r.sendReq(r.post(path, "multipart/form-data; boundary=x"), crashControlBody)
	// Unreachable, or already unstable: a later crash signal would prove nothing.
	if ctrl == nil || ctrl.StatusCode >= 500 {
		return
	}
	ctrlBody := ctrl.Response.DecodedBodyString()

	for _, p := range crashProbes {
		if r.ctx.Err() != nil {
			return
		}
		body := buildCrashProbe(p.sizeMiB, p.parts)
		probe := r.sendReq(r.post(path, "multipart/form-data; boundary="), body)
		if probe == nil {
			continue // network error mid-probe: inconclusive, try the next size
		}
		if crashRejected[probe.StatusCode] {
			return // a size limit in front of the app: no probe will get through
		}
		sig, strong := crashSignal(ctrlBody, probe)
		if sig == "" {
			continue
		}
		if !strong {
			// A status-only signal can be a one-off blip; require it to repeat.
			confirm := r.sendReq(r.post(path, "multipart/form-data; boundary="), body)
			if s2, _ := crashSignal(ctrlBody, confirm); s2 == "" {
				continue
			}
		}
		r.addAt(scanner.High, "Possible PHP crash via malformed multipart (CVE-2026-109618 / CVE-2026-109619)",
			"A "+strconv.Itoa(p.sizeMiB)+" MiB malformed multipart body sent to "+path+" "+sig+
				", which the control request did not. This is the PHP2Shell memory-corruption path (CVE-2026-109618 / CVE-2026-109619) and shows even with display_errors off. Verify by hand and patch PHP ("+php2ShellFix+").",
			r.cfg.Scheme+"://"+r.cfg.Host+path)
		return
	}
}

// crashSignal compares a probe response against the control body and returns a
// description of any crash signal, plus whether it is strong enough to report
// without a confirming repeat. An empty description means no signal.
func crashSignal(ctrlBody string, probe *proxy.Flow) (string, bool) {
	if probe == nil {
		return "", false
	}
	body := probe.Response.DecodedBodyString()
	// Strong: PHP's own out-of-memory fatal while parsing the body. The
	// "Unknown" location is the tell that it died in the multipart parser.
	if strings.Contains(body, "Allowed memory size of") &&
		strings.Contains(body, "bytes exhausted") &&
		strings.Contains(body, "Unknown") {
		return "produced a PHP fatal error (memory exhausted in Unknown)", true
	}
	switch probe.StatusCode {
	case 502, 503, 504:
		return fmt.Sprintf("got HTTP %d from the server fronting PHP (a worker died mid-request)", probe.StatusCode), false
	case 500:
		if ctrlBody != "" && body == "" {
			return "got HTTP 500 with an empty body", false
		}
	case 200:
		if ctrlBody != "" && body == "" {
			return "got an empty 200 body (a worker may have died mid-request)", false
		}
	}
	return "", false
}
