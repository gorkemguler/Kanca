package activescan

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorkemguler/kanca/internal/scanner"
)

// The GitLab check compares a self-managed instance's version against the
// 21 October 2026 critical security release (19.5.1). It only reads the
// version; it never sends anything that reaches the vulnerable code.

const (
	gitlabAdvisory = "https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/"
	// gitlabCriticalFix lists the releases that carry the CVE-2026-110264 fix.
	gitlabCriticalFix = "19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10 or 18.11.13"
)

var (
	gitlabVersionRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)
	// gitlabFixed is the first patch release of each branch that fixes
	// CVE-2026-110264 (critical, unauthenticated code execution in the regex
	// engine). Branches older than 18.11 get no fix.
	gitlabFixed = map[string]int{
		"19.5": 1, "19.4": 3, "19.3": 6, "19.2": 9, "19.1": 9, "19.0": 10, "18.11": 13,
	}
	// gitlabFullFix is the first patch release of each branch that also fixes
	// the 11 other issues of the release. Only the three newest branches have
	// them; on 19.2 and older the critical fix is the only backport.
	gitlabFullFix = map[string]int{"19.5": 1, "19.4": 3, "19.3": 6}
)

// gitlabStatus classifies a GitLab version string such as "19.4.2-ee".
// critical reports a missing CVE-2026-110264 fix; partial reports a version
// that has it but lacks the release's other fixes.
func gitlabStatus(version string) (critical, partial, ok bool) {
	m := gitlabVersionRe.FindStringSubmatch(version)
	if m == nil {
		return false, false, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	if major > 19 || major == 19 && minor > 5 {
		return false, false, true // newer than the release
	}
	branch := m[1] + "." + m[2]
	fixed, known := gitlabFixed[branch]
	if !known || patch < fixed {
		return true, false, true
	}
	full, has := gitlabFullFix[branch]
	return false, !has || patch < full, true
}

// isGitLab reports whether a page looks like it comes from GitLab.
func isGitLab(body string) bool {
	return strings.Contains(body, `content="GitLab"`) || strings.Contains(body, "gon.gitlab_url")
}

// checkGitLabVersion reads a GitLab instance's version from its API. The API
// answers anonymous requests with 401 on most instances; with the session
// cookie of a signed-in user, which the base request carries when the operator
// browsed signed in, it returns the version.
func (r *runner) checkGitLabVersion() {
	if !isGitLab(r.baseBody) {
		f := r.get("/users/sign_in")
		if f == nil || !isGitLab(f.Response.DecodedBodyString()) {
			return
		}
	}
	var v struct {
		Version string `json:"version"`
	}
	f := r.get("/api/v4/version")
	if f == nil || f.StatusCode != 200 || json.Unmarshal(f.Response.DecodedBody(), &v) != nil || v.Version == "" {
		r.addAt(scanner.Info, "GitLab instance: check its version",
			"This is a GitLab instance, but its version isn't readable without signing in. CVE-2026-110264 (CVSS 10, unauthenticated code execution) is fixed in "+gitlabCriticalFix+"; check the version under Admin → Overview → Dashboard, or scan again while signed in through Kanca. See "+gitlabAdvisory+".",
			r.rootURL())
		return
	}
	critical, partial, ok := gitlabStatus(v.Version)
	switch {
	case !ok:
		return
	case critical:
		r.addAt(scanner.High, "GitLab version affected by CVE-2026-110264",
			"GitLab "+v.Version+" predates the fix for CVE-2026-110264, an integer overflow in the regular expression engine that can let an unauthenticated attacker run code on self-managed servers (CVSS 10). Upgrade to "+gitlabCriticalFix+" or later. See "+gitlabAdvisory+".",
			r.rootURL())
	case partial:
		r.addAt(scanner.Medium, "GitLab version missing fixes from the 19.5.1 security release",
			"GitLab "+v.Version+" has the CVE-2026-110264 backport but not the other 11 fixes of the release, among them two of high severity (OmniAuth/LDAP account takeover, OAuth/OIDC cache poisoning). They are only in 19.5.1, 19.4.3 and 19.3.6. See "+gitlabAdvisory+".",
			r.rootURL())
	}
}
