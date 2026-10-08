package control

import (
	"slices"
	"strings"
)

// entryCode is everything the report says about one code that anchors an
// attack path, in one row: what the entry is, in the words of the Entry
// line (nature), which the summary table reads too; who the attacker acts
// as (actor); and the one thing to do (fix). The code's role and entry kind
// stay in the registry (errorCodeRegistry), which the catalog serializes;
// TestEveryEntryCodeHasACompleteRow keeps the two in step.
type entryCode struct {
	// dependency is the kind of dependency the code is about, or
	// depNotADependency.
	dependency entryDependency
	// family is what the entry is in one word, the word the best fix names
	// it by: "image", "expression", "push to";
	// familyAction names a reusable workflow when the subject is one.
	family string
	nature entryNatureWords
	actor  actorRule
	// fix is the short fix of a path the code anchors: one thing to do,
	// imperative, never two ways out joined by "or" (vendoring what an
	// action downloads being the same fix as pinning it). pinnedFix
	// replaces it when the subject is already pinned to a full commit SHA,
	// so the fix never asks for that pin again; actionFix when the
	// reference reads as an action's or a reusable workflow's;
	// untrustedFix when a source code joins the entry (entryAnchor).
	fix, pinnedFix, actionFix, untrustedFix string
}

// entryDependency is the kind of dependency an entry code is about.
type entryDependency int

const (
	_ entryDependency = iota
	// depNotADependency: an expression, a checkout, a cache, a branch.
	depNotADependency
	// depAction: an action, or a reusable workflow when the subject names
	// one ("o/r/.github/workflows/x.yml@v1").
	depAction
	depImage
	depInclude
	depScript
	// depActionOrInclude: a reference naming both a tag and a branch, an
	// action's in a GitHub workflow file, an include's otherwise.
	depActionOrInclude
)

// familyAction is the family of an action code: "reusable workflow" when
// the subject names one, "action" otherwise.
const familyAction = "action"

// entryNatureWords is a code's nature, the words after the subject on the
// Entry line. base is the default; untrusted replaces it on an entry a
// source code joins, an unauthorized source (entryAnchor); own on a
// dependency of the analysed repository's own owner (ownOrganization);
// insider on an expression only an insider sets; workflowRun on a
// checkout of another workflow's run (entryTrigger); unchecked on an
// image whose source no control checks (imageSourceUnchecked). An empty
// variant keeps base. Two slots are filled in: {kind}, the dependency kind
// (dependencyKind), and {dependency}, the dependency as the nature names
// it ("external action", or "action of your organization").
type entryNatureWords struct {
	base, untrusted, own, insider, workflowRun, unchecked string
}

// actorRule is how the So line names who gets in.
type actorRule int

const (
	_ actorRule = iota
	// actorDependency: an action, a reusable workflow, an image, an
	// include or a script, read by its trust and its mutability
	// (dependencyTrust): a trusted dependency can only be compromised, an
	// untrusted one can also be malicious, and only one whose code can
	// change can be compromised.
	actorDependency
	actorKnownVulnerability
	actorImpostorCommit
	// actorHiddenFetch: an action hiding a code fetch, which is evidence
	// of malice whatever its trust.
	actorHiddenFetch
	// actorInjection: who sets the expression.
	actorInjection
	actorCheckout
	actorCache
	actorPush
	// actorForkPR is the actor of a fork pull request entry, which no code
	// anchors: a path read by its entry kind alone (kindActors).
	actorForkPR
)

// The words more than one row reads.
const (
	pinOnCommitSHA      = "pin the version on the commit SHA"
	untrustedImageFix   = "use an image from a trusted registry and pin it by digest"
	remoteCodeFix       = "pin what the action downloads, or vendor it"
	untrustedRemoteFix  = "use an action from a trusted source and pin what it downloads, or vendor it"
	cacheFix            = "do not restore a cache that untrusted runs can write in a release job"
	injectionFix        = "pass the input through an environment variable"
	checkoutFix         = "never check out the pull request head in a privileged workflow"
	pullRequestCheckout = "pull request code checked out in a privileged workflow"
)

// The natures more than one row reads.
var (
	mutableImageNature = entryNatureWords{
		base: "mutable image tag", own: "mutable image tag of your organization", untrusted: "untrusted and mutable image",
		unchecked: "mutable image tag, source not checked on GitHub",
	}
	mutableReferenceNature = entryNatureWords{
		base: "mutable {dependency}", untrusted: "untrusted and mutable external {kind}",
	}
	injectedInputNature = entryNatureWords{
		base: "user-controlled input injected in a script", insider: "input an insider controls, injected in a script",
	}
	cacheNature = entryNatureWords{base: "cache an untrusted run can write"}
)

// entryCodes is the row of every code that anchors a path: each entry-role
// code of the registry, the branch findings that anchor a push path, and
// the source codes that join a dependency path (sourceDependencyCodes),
// which have no phrase of their own and read as their family.
var entryCodes = map[ErrorCode]entryCode{
	CodeImageUnauthorizedSource: {
		dependency: depImage, family: "image",
		nature: entryNatureWords{base: "untrusted image"}, actor: actorDependency,
		fix: untrustedImageFix,
	},
	CodeImageForbiddenTag: {
		dependency: depImage, family: "image",
		nature: mutableImageNature, actor: actorDependency,
		fix: "pin the image by digest",
	},
	CodeImageNotPinnedByDigest: {
		dependency: depImage, family: "image",
		nature: mutableImageNature, actor: actorDependency,
		fix: "pin the image by digest",
	},
	CodeActionUnpinned: {
		dependency: depAction, family: familyAction,
		nature: mutableReferenceNature, actor: actorDependency,
		fix: pinOnCommitSHA,
	},
	CodeActionUnauthorizedSource: {
		dependency: depAction, family: familyAction,
		nature: entryNatureWords{base: "untrusted external {kind}"}, actor: actorDependency,
		fix: untrustedActionFix("action"), pinnedFix: "use an action from a trusted source",
	},
	CodeActionMutableRemoteExec: {
		dependency: depAction, family: familyAction,
		nature: entryNatureWords{
			base:      "{dependency} that downloads code at run time from a mutable source",
			untrusted: "untrusted {dependency} that downloads code at run time from a mutable source",
		},
		actor: actorDependency,
		fix:   remoteCodeFix, untrustedFix: untrustedRemoteFix,
	},
	CodeActionObfuscatedRemoteExec: {
		dependency: depAction, family: familyAction,
		nature: entryNatureWords{
			base:      "{dependency} that downloads obfuscated code at run time",
			untrusted: "untrusted {dependency} that downloads obfuscated code at run time",
		},
		actor: actorHiddenFetch,
		fix:   remoteCodeFix, untrustedFix: untrustedRemoteFix,
	},
	CodeActionRemoteExecUnverified: {
		dependency: depAction, family: familyAction,
		nature: entryNatureWords{
			base:      "{dependency} that downloads code at run time Plumber could not check",
			untrusted: "untrusted {dependency} that downloads code at run time Plumber could not check",
		},
		actor: actorDependency,
		fix:   remoteCodeFix, untrustedFix: untrustedRemoteFix,
	},
	CodeImpostorCommit: {
		dependency: depAction, family: familyAction,
		nature: entryNatureWords{base: "{dependency} pinned to a commit that is not in its repository"}, actor: actorImpostorCommit,
		fix: "pin a commit that exists in the action's repository",
	},
	CodeKnownVulnerableAction: {
		dependency: depAction, family: familyAction,
		nature: entryNatureWords{base: "{dependency} with a known vulnerability"}, actor: actorKnownVulnerability,
		fix: "move to a version without the advisory",
	},
	CodeRefConfusion: {
		dependency: depActionOrInclude, family: "reference",
		nature: mutableReferenceNature, actor: actorDependency,
		fix: "pin the include on a commit SHA", actionFix: pinOnCommitSHA,
	},
	CodeIncludeForbiddenVersion: {
		dependency: depInclude, family: "include",
		nature: entryNatureWords{base: "mutable external include"}, actor: actorDependency,
		fix: "pin the include on a commit SHA",
	},
	CodeUnverifiedScriptExecution: {
		dependency: depScript, family: "script",
		nature: entryNatureWords{base: "script downloaded and run at build time"}, actor: actorDependency,
		fix: "download the script, check its checksum, then run it",
	},
	CodeUnsafeVariableExpansion: {
		dependency: depNotADependency, family: "variable",
		nature: entryNatureWords{
			base: "user-controlled variable expanded in a script", insider: "variable an insider controls, expanded in a script",
		},
		actor: actorInjection,
		fix:   "keep the variable out of eval and sub-shells",
	},
	CodeTemplateInjection: {
		dependency: depNotADependency, family: "expression",
		nature: injectedInputNature, actor: actorInjection,
		fix: injectionFix,
	},
	CodeGitHubEnvInjection: {
		dependency: depNotADependency, family: "expression",
		nature: injectedInputNature, actor: actorInjection,
		fix: injectionFix,
	},
	CodeUnsafeGithubContextDump: {
		dependency: depNotADependency, family: "expression",
		nature: entryNatureWords{base: "whole github context dumped into a script"}, actor: actorInjection,
		fix: "pass the fields you need by name, not the whole context",
	},
	CodeDangerousTriggers: {
		dependency: depNotADependency, family: "checkout",
		nature: entryNatureWords{base: pullRequestCheckout, workflowRun: "code of another workflow's run checked out"},
		actor:  actorCheckout,
		fix:    checkoutFix,
	},
	CodePullRequestTargetWithHeadCheckout: {
		dependency: depNotADependency, family: "checkout",
		nature: entryNatureWords{base: pullRequestCheckout}, actor: actorCheckout,
		fix: checkoutFix,
	},
	CodeBranchUnprotected: {
		dependency: depNotADependency, family: "push to",
		nature: entryNatureWords{base: "branch anyone with write access can push to, not protected"}, actor: actorPush,
		fix: "protect the default branch",
	},
	CodeBranchNonCompliant: {
		dependency: depNotADependency, family: "push to",
		nature: entryNatureWords{base: "branch anyone with write access can push to, protection not compliant"}, actor: actorPush,
		fix: "protect the default branch",
	},
	CodeCachePoisoning: {
		dependency: depNotADependency, family: "cache",
		nature: cacheNature, actor: actorCache,
		fix: cacheFix,
	},
	CodeCachePoisoningUnresolved: {
		dependency: depNotADependency, family: "cache",
		nature: cacheNature, actor: actorCache,
		fix: cacheFix,
	},
}

// kindActors is the actor of a path whose anchoring code has no row, by
// its entry kind.
var kindActors = map[EntryKind]actorRule{
	EntryMutableDependency:   actorDependency,
	EntryUntrustedExpression: actorInjection,
	EntryPRTarget:            actorCheckout,
	EntryForkPR:              actorForkPR,
	EntryPoisonedCache:       actorCache,
	EntryUnprotectedPush:     actorPush,
}

// entryRow is the entryCodes entry of the code the block reads p by
// (entryAnchor).
func entryRow(p AttackPath) (entryCode, bool) {
	code, _ := entryAnchor(p)
	row, ok := entryCodes[code]
	return row, ok
}

// runTimeFetchCodes are the codes saying an action downloads code at run
// time from a source that can change (ISSUE-714) or that could not be
// checked (ISSUE-716). One that hides the fetch (ISSUE-715) says the
// action is already bad (knownBadDependencyCodes).
var runTimeFetchCodes = map[ErrorCode]bool{
	CodeActionMutableRemoteExec:    true,
	CodeActionRemoteExecUnverified: true,
}

// anchorRank is how serious an anchoring code is, for entryAnchor: a
// dependency known bad, then one fetching code at run time, then a
// reference not pinned, then a source outside the authorized list; 0 for
// any other code.
func anchorRank(c ErrorCode) int {
	switch {
	case knownBadDependencyCodes[c]:
		return 4
	case runTimeFetchCodes[c]:
		return 3
	case pinningDependencyCodes[c]:
		return 2
	case sourceDependencyCodes[c]:
		return 1
	}
	return 0
}

// entryAnchor is the one code the block and the table read p by when
// several anchor it, so the Entry line's nature, the So line's actor, the
// fix and the table's entry agree: the most serious of p.AnchorCodes
// (anchorRank), a path anchored by a code of no rank keeping AnchorCode.
// untrusted is set when the dependency is not trusted (dependencyTrust)
// and the entry is anchored by a code other than a source code whose
// nature has an untrusted variant: the entry reads as untrusted in each
// of the four.
func entryAnchor(p AttackPath) (code ErrorCode, untrusted bool) {
	code = p.AnchorCode
	for _, c := range p.AnchorCodes {
		if anchorRank(code) > 0 && anchorRank(c) > anchorRank(code) {
			code = c
		}
	}
	if p.EntryKind != EntryMutableDependency || sourceDependencyCodes[code] {
		return code, false
	}
	trusted, _ := dependencyTrust(p)
	return code, !trusted && entryCodes[code].nature.untrusted != ""
}

// dependencyTrust is what the anchors of a dependency entry say about it,
// the one place the Entry line's nature (entryAnchor) and the So line's
// actor (dependencyActor) read it from. trusted: no source code
// (sourceDependencyCodes) is among the anchors, nor the "source_cap"
// modifier, and the entry is no fetched script (ISSUE-411 only fires on a
// URL outside the trusted list, so a script entry is never trusted).
// mutable: what runs can change, a pinning code (pinningDependencyCodes),
// a run-time fetch (runTimeFetchCodes, a fetched script) or a reference
// computed at run time saying so.
func dependencyTrust(p AttackPath) (trusted, mutable bool) {
	codes := p.AnchorCodes
	if len(codes) == 0 {
		codes = []ErrorCode{p.AnchorCode}
	}
	trusted = !slices.Contains(p.Modifiers, "source_cap")
	for _, c := range codes {
		switch {
		case sourceDependencyCodes[c]:
			trusted = false
		case c == CodeUnverifiedScriptExecution:
			trusted, mutable = false, true
		case pinningDependencyCodes[c], runTimeFetchCodes[c]:
			mutable = true
		}
		mutable = mutable || computedAtRunTime(c, p.Entry.Subject)
	}
	return trusted, mutable
}

// actionOrWorkflow is "reusable workflow" when the entry's subject names
// one, "action" otherwise.
func actionOrWorkflow(p AttackPath) string {
	if strings.Contains(p.Entry.Subject, "/.github/workflows/") {
		return "reusable workflow"
	}
	return "action"
}

// untrustedActionFix is the fix of an action or a reusable workflow (kind)
// from a source outside the authorized list.
func untrustedActionFix(kind string) string {
	return "use " + article(kind) + " " + kind + " from a trusted source and " + pinOnCommitSHA
}

// article is "an" before a word opening on a vowel, "a" otherwise.
func article(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "an"
	}
	return "a"
}
