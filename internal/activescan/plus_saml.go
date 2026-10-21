package activescan

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/scanner"
)

// checkSAML adds a DOCTYPE, then an external entity, to the message in a
// SAMLRequest or SAMLResponse parameter and sees whether the server still
// treats it like the original. A parser that accepts a DTD there is the first
// step towards XXE and SAML parser confusion.
func (r *runner) checkSAML(ip insertionPoint) {
	if !strings.EqualFold(ip.label, "SAMLRequest") && !strings.EqualFold(ip.label, "SAMLResponse") {
		return
	}
	doc, deflated, ok := decodeSAML(ip.orig)
	if !ok || strings.Contains(doc, "<!DOCTYPE") {
		return
	}
	// Whatever differs between the original and an empty value tells an
	// accepted message from a rejected one.
	empty := r.send(ip, "")
	if empty == nil {
		return
	}
	accepted := samlTraits(r.base)
	telling := differingTraits(accepted, samlTraits(empty))
	if len(telling) == 0 {
		return
	}

	body := stripXMLDecl(doc)
	probes := []struct{ name, doc string }{
		{"DOCTYPE", `<!DOCTYPE root SYSTEM "example.dtd">` + body},
	}
	if m := samlIDRe.FindStringSubmatchIndex(body); m != nil {
		probes = append(probes, struct{ name, doc string }{
			"external entity",
			`<!DOCTYPE foo [ <!ENTITY uuid SYSTEM "` + body[m[2]:m[3]] + `"> ]>` + body[:m[2]] + "&uuid;" + body[m[3]:],
		})
	}
	for _, p := range probes {
		value := encodeSAML(p.doc, deflated)
		same := true
		for attempt := 0; attempt < 2 && same; attempt++ {
			f := r.send(ip, value)
			same = f != nil && sameTraits(samlTraits(f), accepted, telling)
		}
		if same {
			r.add(scanner.Info, "SAML message with "+p.name+" accepted in "+ip.label,
				"With a "+p.name+" added, the decoded "+ip.label+" got the same response as the original message, unlike an empty one, twice: the XML parser accepts DTDs here. Test for XXE, entity expansion, round-trip and namespace confusion. See https://portswigger.net/research/saml-roulette-the-hacker-always-wins.")
		}
	}
}

var samlIDRe = regexp.MustCompile(`\sID="([^"&<]+)"`)

// decodeSAML undoes a SAML binding's encoding: base64, plus raw DEFLATE for
// the redirect binding.
func decodeSAML(v string) (doc string, deflated, ok bool) {
	// A '+' left unescaped in a query string arrives as a space.
	v = strings.ReplaceAll(strings.TrimSpace(v), " ", "+")
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(v, "=")); err != nil {
			return "", false, false
		}
	}
	if x, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw))); err == nil && looksXML(x) {
		return string(x), true, true
	}
	if looksXML(raw) {
		return string(raw), false, true
	}
	return "", false, false
}

func encodeSAML(doc string, deflated bool) string {
	if !deflated {
		return base64.StdEncoding.EncodeToString([]byte(doc))
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write([]byte(doc))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func looksXML(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte("<"))
}

// stripXMLDecl drops a leading <?xml …?> declaration, which must come before
// any DOCTYPE.
func stripXMLDecl(doc string) string {
	t := strings.TrimSpace(doc)
	if strings.HasPrefix(t, "<?xml") {
		if i := strings.Index(t, "?>"); i >= 0 {
			return strings.TrimSpace(t[i+2:])
		}
	}
	return t
}

// samlTraits are the parts of a response that tell how a SAML endpoint took a
// message: where it sent the browser, which cookies it set, what it showed.
func samlTraits(f *proxy.Flow) map[string]string {
	loc, _, _ := strings.Cut(f.Response.Headers.Get("Location"), "?")
	var cookies []string
	for _, c := range f.Response.Headers.Values("Set-Cookie") {
		name, _, _ := strings.Cut(c, "=")
		cookies = append(cookies, strings.TrimSpace(name))
	}
	sort.Strings(cookies)
	return map[string]string{
		"status":   strconv.Itoa(f.StatusCode),
		"location": loc,
		"cookies":  strings.Join(cookies, ","),
		"type":     f.Response.Headers.Get("Content-Type"),
		"tags":     tagmap(f.Response.DecodedBodyString()),
	}
}

func differingTraits(a, b map[string]string) []string {
	var keys []string
	for k, v := range a {
		if b[k] != v {
			keys = append(keys, k)
		}
	}
	return keys
}

func sameTraits(a, b map[string]string, keys []string) bool {
	for _, k := range keys {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}
