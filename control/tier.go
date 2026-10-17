package control

import (
	"strings"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// baseTier is rule 6 over the reach: what the path is worth before any
// modifier. Every impact counts (an unconfirmed one too: the unresolvable
// modifier lowers the path that rests on it), but only proven privilege
// does (provenPrivileged): secrets Plumber could not list and a write
// token nothing settled stay listed in the reach and add no tier.
// contributor is set for an entry anyone opening a pull request controls
// (contributorEntry).
func baseTier(r Reach, contributor bool) PathTier {
	return tierFor(len(r.Impacts) > 0, provenPrivileged(r), contributor)
}

// tierFor is rule 6: a proven privilege (secrets or a write token) with an
// impact, or with an entry anyone opening a pull request controls, is
// Critical; an impact alone (the deploy, publish, write or sign itself is
// the damage) or a proven privilege alone is High; code execution alone
// is Low, the runner it holds being thrown away once the job ends. A
// proven feeds edge reaching a job that is privileged or has an impact
// counts through the reach: reachOver only unions what such an edge
// carries. Medium only comes from a modifier lowering a High path.
func tierFor(impact, privileged, contributor bool) PathTier {
	switch {
	case (impact || contributor) && privileged:
		return TierCritical
	case impact, privileged:
		return TierHigh
	}
	return TierLow
}

// provenPrivileged reports whether a walked job holds a privilege the
// facts prove: secrets of a job whose secrets could be listed
// (SecretsState not unknown), or write scopes of a job whose token write
// was settled (TokenWriteState not unknown, and not the repository
// default read as a guess). A reach built by hand, without parts, counts
// its secrets and a write token that is not assumed.
func provenPrivileged(r Reach) bool {
	for _, part := range partsOf(r) {
		if !part.secretsUnknown && (len(part.secrets) > 0 || part.allSecrets) {
			return true
		}
		if !part.tokenUnknown && len(part.scopes) > 0 {
			return true
		}
	}
	return false
}

// withoutPrivilege is parts with every privilege marked unproven: still
// listed, adding no tier.
func withoutPrivilege(parts []reachPart) []reachPart {
	out := make([]reachPart, len(parts))
	for i, part := range parts {
		part.secretsUnknown, part.tokenUnknown = true, true
		out[i] = part
	}
	return out
}

// pushEscalates reports whether a push entry's walk proves an escalation:
// a walked job, the entry job included, holds a proven privilege or an
// impact. A push to an unprotected branch that reaches neither only runs
// code on a runner the pusher could already reach with write access, so
// it anchors no path and the branch finding is priced on its own.
func pushEscalates(r Reach) bool {
	return provenPrivileged(r) || len(r.Impacts) > 0
}

// keepsSomething reports whether code entering js's runner through an
// entry of kind on subject can leave something a later run reads: an
// artifact the job uploads, or a cache it saves (Mode "save" or "both")
// in a run the entry holds in that saves for the default branch
// (cacheWriterScope, savesShared): a pull_request_target run GitHub keeps
// read-only, or a fork pull request's own scope, poisons no cache another
// run reads. Without either the runner is ephemeral and the "caches or
// uploads" sentences are not said.
func keepsSomething(kind EntryKind, subject string, js JobSituation) bool {
	return js.Uploads || (len(savingCaches(js)) > 0 && savesShared(cacheWriterScope(kind, subject, js)))
}

// advisorySeverityRank orders the severities the GitHub Advisory Database
// rates an advisory with; a severity absent here is unknown.
var advisorySeverityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// advisorySeverityOf is the worst severity among the advisories an
// ISSUE-703 finding names (Data "advisories"), read off its
// "advisorySeverities" (GHSA id to severity); "" when one of them carries
// no known severity, or the finding names none: an unknown severity caps
// nothing.
func advisorySeverityOf(f opaengine.Finding) string {
	ids := stringsOf(f.Data["advisories"])
	if len(ids) == 0 {
		return ""
	}
	sevs := map[string]string{}
	switch m := f.Data["advisorySeverities"].(type) {
	case map[string]any:
		for k, v := range m {
			if s, ok := v.(string); ok {
				sevs[k] = s
			}
		}
	case map[string]string:
		sevs = m
	}
	worst := ""
	for _, id := range ids {
		s := strings.ToLower(sevs[id])
		if advisorySeverityRank[s] == 0 {
			return ""
		}
		if advisorySeverityRank[s] > advisorySeverityRank[worst] {
			worst = s
		}
	}
	return worst
}

// stringsOf reads a finding data list, as decoded JSON ([]any) or as
// built in Go ([]string).
func stringsOf(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// advisoryRating is the severity that holds an advisory_cap path at tier,
// the one advisoryCeiling maps to it: low at Medium, medium at High.
func advisoryRating(tier PathTier) string {
	if tier == TierMedium {
		return "low"
	}
	return "medium"
}

// advisoryCeiling is the highest tier a path its ISSUE-703 anchors start
// can hold, by the worst severity among their advisories: a low one holds
// it at Medium, a medium one at High. A high or critical one, a severity
// not read, or another known-bad anchor on the same subject (an impostor
// commit, an obfuscated fetch) caps nothing. ok is false when nothing
// caps.
func (g *pathGroup) advisoryCeiling() (PathTier, bool) {
	if !g.codes[CodeKnownVulnerableAction] || g.codes[CodeImpostorCommit] || g.codes[CodeActionObfuscatedRemoteExec] {
		return "", false
	}
	worst := ""
	for _, s := range g.advisorySeverities {
		if advisorySeverityRank[s] == 0 {
			return "", false
		}
		if advisorySeverityRank[s] > advisorySeverityRank[worst] {
			worst = s
		}
	}
	switch worst {
	case "low":
		return TierMedium, true
	case "medium":
		return TierHigh, true
	}
	return "", false
}
