package control

import (
	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/platform"
	"github.com/sirupsen/logrus"
)

// ControlKeyFor names a finding's control the same way platformFindingControlName
// (cmd/platform_push.go) names it when the finding is PUSHED: the registry lookup's
// ControlName when the code is known, the raw code string otherwise. The two sides
// must agree on this fallback, or a finding whose code the CLI's own registry cannot
// classify would be pushed under its raw code but never matched back against a
// dismissed entry the platform served under that same raw code.
//
// Exported so cmd/platform_push.go's platformFindingControlName calls this SAME
// function rather than re-deriving the fallback independently: two copies of "look
// up the code, else use it raw" can only drift, and a drift here means the push and
// the matcher disagree about a control's name for exactly the findings that most
// need them to agree (the unregistered ones).
func ControlKeyFor(code string) string {
	if info := LookupCode(ErrorCode(code)); info != nil {
		return info.ControlName
	}
	return code
}

// MarkDismissed sets Dismissed on every finding whose platform identity matches a served
// dismissed issue (#447) and returns how many it marked. Entries served under another recipe
// version are skipped (honest non-suppression, never a cross-version match); control_type is
// used only to avoid hashing a finding against entries of other controls, keyed by controlKeyFor
// so it agrees with the raw-code fallback the push side uses. A codeless finding has no identity
// (identity.PlatformHash reports !ok) and never matches. The marker is a claim about what
// /context served; the platform's stored issue status stays the authority.
//
// Served entries (after the version filter) that matched no finding at all are counted and
// logged at Debug, so a systematic mismatch between what the platform served and what this run
// produced is at least diagnosable, not silently absorbed.
func MarkDismissed(findings []opaengine.Finding, served []platform.DismissedIssue) int {
	if len(served) == 0 {
		return 0
	}
	byControl := map[string]map[string]struct{}{}
	total := 0
	for _, d := range served {
		if d.RecipeVersion != identity.RecipeVersion {
			continue
		}
		set, ok := byControl[d.ControlType]
		if !ok {
			set = map[string]struct{}{}
			byControl[d.ControlType] = set
		}
		if _, dup := set[d.IdentityHash]; !dup {
			set[d.IdentityHash] = struct{}{}
			total++
		}
	}
	matched := map[string]struct{}{}
	marked := 0
	for i := range findings {
		key := ControlKeyFor(findings[i].Code)
		set, ok := byControl[key]
		if !ok {
			continue
		}
		hash, _, ok := identity.PlatformHash(findings[i].IdentityInput())
		if !ok {
			continue
		}
		if _, hit := set[hash]; hit {
			findings[i].Dismissed = true
			marked++
			matched[key+"\x00"+hash] = struct{}{}
		}
	}
	if unmatched := total - len(matched); unmatched > 0 {
		logrus.Debugf("dismissed_issues: %d served entries matched no finding", unmatched)
	}
	return marked
}
