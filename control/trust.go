package control

import (
	"strings"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/runners"
)

// This file decides who an attacker acts as through a mutable_dependency
// anchor, and whether that anchor exists at all: trust follows the
// party that can change the code, not the party a workflow merely
// names. A SHA-pinned action whose remote exec never actually runs (a
// preinstalled-tool guard that fires, a checksum-verified download) and
// an archived action's immutable tag anchor nothing; a first-party
// script or a sibling organisation's redirected action anchors an
// insider, capped at the Medium ceiling, never an outsider's High.

// insiderCeiling is the highest tier a mutable_dependency path can hold
// when actorFor reads its anchor as an insider (GateInsider): closer to
// home than an outside dependency, so it never starts a path above
// Medium on its own, whatever else the anchor's codes say.
const insiderCeiling = TierMedium

// siblingOrganizations is the tiny, dated (2026-10-15) list of owner
// pairs treated as one organisation family for a redirect's sibling
// check. Keep this list short: only a documented, deliberate split
// belongs here, never a guess.
var siblingOrganizations = [][2]string{
	{"cloudflare", "cloudflare-studio"},
}

// suppressed decides whether an anchor-candidate finding should start
// no path at all, even though the finding itself still stands: a
// preinstalled-tool guard that actually fires on this job's own runner
// image, a checksum- or signature-verified download, and an archived
// action's tag (nobody can retarget it) are all immutable in practice.
// unknownRunner reports that the anchor should still exist, but with
// its fact state unknown: the guard is real, but whether it fires cannot
// be decided statically, because the job runs its steps inside a
// container (container:, job.image: the guard checks the container, not
// the hosted image) or its runner label is not a plain hosted label
// runners.LabelImages can answer for.
func suppressed(f opaengine.Finding) (suppress, unknownRunner bool) {
	data := f.Data
	if truthy(data["downloadVerified"]) {
		return true, false
	}
	if truthy(data["archivedTag"]) {
		return true, false
	}
	guard, _ := data["downloadGuard"].(string)
	if guard == "" {
		return false, false
	}
	if truthy(data["container"]) {
		return false, true
	}
	images, known := runnerImagesFromData(data)
	if !known {
		return false, true
	}
	for _, image := range images {
		preinstalled, known := runners.Preinstalled(image, guard)
		if !known {
			return false, true
		}
		if !preinstalled {
			return false, false
		}
	}
	return true, false
}

// runnerImagesFromData reads the job's own runs-on facts (runsOn,
// runsOnExpression) off a finding's Data, as action_mutable_remote_exec
// .rego carries them on an ISSUE-714 finding that names a download
// guard, and resolves them to the hosted images they run
// (runners.LabelImages).
func runnerImagesFromData(data map[string]any) (images []string, known bool) {
	expr, _ := data["runsOnExpression"].(bool)
	raw, _ := data["runsOn"].([]any)
	labels := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			labels = append(labels, s)
		}
	}
	return runners.LabelImages(labels, expr)
}

// actorFor decides who an attacker acts as through anchor, and the
// gate class that caps the tier of the path it starts. GateInsider for
// a first-party script (the scanned repository's own owner or domain)
// or a sibling organisation's redirected action; GateOutsider for a
// SHA-pinned action that downloads at run time from an outside host,
// unguarded and unverified (the actor names that host directly); ""
// (no opinion) for everything else, which keeps the existing
// dependency wording and ceiling unchanged.
func actorFor(anchor pathAnchor, own string) (actor string, class ir.GateClass) {
	if anchor.kind != EntryMutableDependency {
		return "", ""
	}
	data := anchor.data
	if truthy(data["firstParty"]) {
		return firstPartyActor(anchor.fact.Subject), ir.GateInsider
	}
	if owner, ok := redirectedSiblingOwner(data, own); ok {
		return "as someone with write access to " + owner + "'s repository", ir.GateInsider
	}
	if actor := downloadHostActor(data); actor != "" {
		return actor, ir.GateOutsider
	}
	return "", ""
}

// downloadHostActor is the So-line actor for a SHA-pinned action that
// downloads at run time from an outside host (action_mutable_remote_
// exec.rego's fetchUrl), unguarded and unverified: "if <host> is
// compromised", naming the actual host the code comes from rather than
// the generic "if this action is compromised". "" when the fetch has no
// recorded host, is guarded, or is verified (those read some other way).
func downloadHostActor(data map[string]any) string {
	url, _ := data["fetchUrl"].(string)
	if url == "" || truthy(data["downloadVerified"]) {
		return ""
	}
	if guard, _ := data["downloadGuard"].(string); guard != "" {
		return ""
	}
	host := urlHost(url)
	if host == "" {
		return ""
	}
	return "if " + host + " is compromised"
}

// downloadClaimSource is the download claim's source (claimsFor,
// control/pathclaims.go) for a mutable_dependency anchor's own finding
// data: "verified" when the download is checksum- or signature-verified,
// "guarded" when a preinstalled-tool check guards it (named whether or
// not suppressed proved that guard fires: a path reaching here with a
// named guard either has an unknown-runner fact, in which case the entry
// claim itself carries the gap, or the guard is simply not one of this
// anchor's reasons to be suppressed), "unguarded" when the anchor names a
// run-time fetch host with neither. "" when the finding carries none of
// the three facts at all (no run-time download to claim anything about).
func downloadClaimSource(data map[string]any) string {
	if data == nil {
		return ""
	}
	if truthy(data["downloadVerified"]) {
		return "verified"
	}
	if guard, _ := data["downloadGuard"].(string); guard != "" {
		return "guarded"
	}
	if url, _ := data["fetchUrl"].(string); url != "" {
		return "unguarded"
	}
	return ""
}

// redirectedSiblingOwner reads a finding's redirectedOwner (the owner
// its action repository currently reports, from action_unpinned.rego)
// and reports whether it is a sibling of own's owner: the literal same
// owner (a rename the workflow's `uses:` text has not caught up with),
// or a documented sibling organisation (siblingOrganizations).
func redirectedSiblingOwner(data map[string]any, own string) (string, bool) {
	redirected, _ := data["redirectedOwner"].(string)
	if redirected == "" {
		return "", false
	}
	redirectedLower := strings.ToLower(redirected)
	ownOwner := ownerOf(own)
	if ownOwner == "" {
		return "", false
	}
	if redirectedLower == ownOwner || siblingFamily(ownOwner, redirectedLower) {
		return redirected, true
	}
	return "", false
}

// siblingFamily reports whether a and b (both lower case) are the two
// halves of one documented sibling pair.
func siblingFamily(a, b string) bool {
	for _, pair := range siblingOrganizations {
		x, y := strings.ToLower(pair[0]), strings.ToLower(pair[1])
		if (a == x && b == y) || (a == y && b == x) {
			return true
		}
	}
	return false
}

// firstPartyActor is the So-line actor for a first-party fetch: someone
// with write access to the fetch's own host, named alone (the owner's
// proper casing is not available anywhere in the finding data, so a
// possessive form would read as "clickhouse's clickhouse.com").
func firstPartyActor(url string) string {
	host := urlHost(url)
	if host == "" {
		return "as someone with write access to this source"
	}
	return "as someone with write access to " + host
}

// urlHost extracts a URL's host, lower case, scheme stripped, a
// "userinfo@" prefix dropped (everything up to and including the LAST
// "@": a password may itself carry one, but the host is always what
// follows the last one), a ":port" suffix dropped, and a leading
// "www." dropped. "" when url does not start with http(s)://.
func urlHost(url string) string {
	lower := strings.ToLower(url)
	var rest string
	switch {
	case strings.HasPrefix(lower, "https://"):
		rest = lower[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		rest = lower[len("http://"):]
	default:
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimPrefix(rest, "www.")
}

// truthy reads a Data value as a bool, false for anything else
// (including absence, a different JSON type, or nil).
func truthy(v any) bool {
	b, _ := v.(bool)
	return b
}
