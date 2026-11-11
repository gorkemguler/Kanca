package scanner

import (
	"regexp"
	"strings"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// DOM-based XSS can't be found from headers alone, and a full taint analysis is
// out of scope for a passive check. Instead this looks, in the JavaScript a
// page already served, for a dangerous sink (one that writes HTML or runs code)
// with an attacker-controllable source (the URL, referrer, name, cookie or web
// storage) close by. Both together is the shape of a DOM-XSS bug; it is a lead
// to review by hand, not a confirmed finding, so it reports as Low.

// domSink matches a sink that writes markup into the page or executes a string.
var domSink = regexp.MustCompile(`(?i)\.(innerHTML|outerHTML)\s*=|\.insertAdjacentHTML\s*\(|document\s*\.\s*write(ln)?\s*\(|\beval\s*\(|\.(html|after|before|append|prepend|replaceWith)\s*\(|\bnew\s+Function\s*\(|(location|location\s*\.\s*href)\s*=`)

// domSource matches input an attacker can influence through the browser.
var domSource = regexp.MustCompile(`(?i)location\s*\.\s*(hash|search|href|pathname)|\blocation\b|document\s*\.\s*(URL|documentURI|baseURI|referrer|cookie)|window\s*\.\s*name|\b(localStorage|sessionStorage)\b|\.\s*(hash|search)\b`)

// domSinkLabel is the sink name shown in a finding, from the matched text.
func domSinkLabel(match string) string {
	m := strings.ToLower(match)
	switch {
	case strings.Contains(m, "innerhtml"):
		return "innerHTML"
	case strings.Contains(m, "outerhtml"):
		return "outerHTML"
	case strings.Contains(m, "insertadjacent"):
		return "insertAdjacentHTML"
	case strings.Contains(m, "write"):
		return "document.write"
	case strings.Contains(m, "eval"):
		return "eval"
	case strings.Contains(m, "function"):
		return "new Function"
	case strings.Contains(m, "location"):
		return "location assignment"
	default:
		return "jQuery HTML sink"
	}
}

// domWindow is how far on each side of a sink a source still counts as feeding
// it. Kept small so unrelated code elsewhere in a bundle doesn't pair up.
const domWindow = 120

// domXSS scans an HTML or JavaScript response for sink/source pairs. It reports
// at most one finding per distinct sink so a big bundle can't flood the list.
func domXSS(f *proxy.Flow) []candidate {
	ct := strings.ToLower(f.Response.Headers.Get("Content-Type"))
	if !strings.Contains(ct, "html") && !strings.Contains(ct, "javascript") && !strings.Contains(ct, "ecmascript") {
		return nil
	}
	body := f.Response.DecodedBodyString()
	if len(body) == 0 || len(body) > 4<<20 {
		return nil // nothing to read, or too large to scan cheaply
	}

	var out []candidate
	seen := map[string]bool{}
	for _, loc := range domSink.FindAllStringIndex(body, -1) {
		label := domSinkLabel(body[loc[0]:loc[1]])
		if seen[label] {
			continue
		}
		lo := loc[0] - domWindow
		if lo < 0 {
			lo = 0
		}
		hi := loc[1] + domWindow
		if hi > len(body) {
			hi = len(body)
		}
		src := domSource.FindString(body[lo:hi])
		if src == "" {
			continue
		}
		seen[label] = true
		out = append(out, candidate{Low, "Potential DOM-based XSS (" + label + ")",
			"A client-side script feeds a browser-controlled source (" + strings.TrimSpace(src) +
				") into the " + label + " sink. If the value isn't sanitised this is DOM-based XSS; review the script by hand."})
		if len(out) >= 5 {
			break
		}
	}
	return out
}
