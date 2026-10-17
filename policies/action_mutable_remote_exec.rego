# action-mutable-remote-exec — a third-party action's OWN source fetches
# and runs code from a moving ref at runtime, so pinning the action by SHA
# does not make its execution immutable (the anchore/scan-action → grype
# case). Driven by the collector's per-action source analysis, exposed on
# the IR as action.metadata.mutableRemoteExec (consumer side) and
# pipeline.selfActionMutableExec (producer side: the scanned repo IS the
# action).
#
# Graded by INTENT-TO-HIDE and VERIFIABILITY, not by a single flat
# severity — a static text match on an unbounded evasion space cannot
# prove absence, so:
#
#   ISSUE-715 critical — "obfuscated": decode-then-exec / eval(atob). No
#                        legitimate action hides what it runs. Hiding IS
#                        the finding; this is host/ref/encoding-agnostic.
#   ISSUE-714 high     — "exec": a script fetched from a moving ref and
#                        run, in the open, with NO checksum. A clean
#                        result asserts "no known pattern seen", not
#                        "safe". A checksum-verified fetch is content-
#                        pinned and is NOT flagged.
#   ISSUE-716 low      — "unverified": the source could not be fetched
#                        (offline/GHES/private/rate-limit/Docker-image).
#                        Surfaced as could-not-verify, never a silent pass.
package action_mutable_remote_exec

import rego.v1

# _signals unifies every mutable-remote-exec signal: one per used action
# that carries one (consumer side) plus the scanned repo's own action
# (producer side).
_signals contains sig if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	mre := action.metadata.mutableRemoteExec
	sig := {
		"tier": mre.tier,
		"url":  object.get(mre, "url", ""),
		"who":  sprintf("action %q (used by job %q)", [action.uses, job.name]),
		"job":  job.name,
		"uses": action.uses,
		"line": object.get(action, "line", 0),
		"guard": object.get(mre, "downloadGuard", ""),
		"verified": object.get(mre, "downloadVerified", false),
		"runsOn": object.get(job, "runsOn", []),
		"runsOnExpression": object.get(job, "runsOnExpression", false),
		"container": object.get(job, "image", null) != null,
	}
}

_signals contains sig if {
	mre := input.pipeline.selfActionMutableExec
	sig := {
		"tier": mre.tier,
		"url":  object.get(mre, "url", ""),
		"who":  "the action published by this repository",
		"job":  "",
		"uses": "",
		"line": 0,
		"guard": object.get(mre, "downloadGuard", ""),
		"verified": object.get(mre, "downloadVerified", false),
		"runsOn": [],
		"runsOnExpression": false,
		"container": false,
	}
}

deny contains finding if {
	some sig in _signals
	sig.tier == "obfuscated"
	finding := {
		"code":     "ISSUE-715",
		"severity": "critical",
		"message":  sprintf("%s obfuscates a remote code fetch/exec (`%s`) — hiding what an action runs at runtime is treated as the strongest signal, whatever host/ref/encoding is used", [sig.who, sig.url]),
		"job":      sig.job,
		"uses":     sig.uses,
		"line":     sig.line,
	}
}

# _guard_fields and _verified_fields are additive: a signal with no guard
# and no verification carries neither key, so an ISSUE-714 finding keeps
# its original shape except where one of the two trust signals actually
# applies (trust follows the party that can change the code, not the
# party the workflow merely names).
default _guard_fields(_) := {}

_guard_fields(sig) := object.union(
	{
		"downloadGuard": sig.guard,
		"runsOn": sig.runsOn,
		"runsOnExpression": sig.runsOnExpression,
	},
	_container_fields(sig),
) if sig.guard != ""

# _container_fields carries `container: true` when the job runs its steps
# inside a container (container:, job.image): the guard then checks the
# container, not the hosted runner image, so the runner label proves
# nothing about it (control/trust.go reads the anchor as unknown).
default _container_fields(_) := {}

_container_fields(sig) := {"container": true} if sig.container

default _verified_fields(_) := {}

_verified_fields(sig) := {"downloadVerified": true} if sig.verified

# _url_fields carries the fetch's own URL, for the download-host actor
# (control/trust.go's "if <host> is compromised") to read the host
# off. sig.url is often the whole matched command snippet, not a bare
# URL (a pipe-to-shell hit's own url is "curl -sSf https://host/x |
# sh"), so the first http(s):// substring is extracted out of it here
# rather than carried through as-is: urlHost's own scheme check would
# otherwise never match a command snippet, and the generic dependency
# wording would come back for exactly the fetches this actor exists
# to name.
_fetch_url_pattern := `(?i)https?://[^\s|;&'")]+`

default _url_fields(_) := {}

_url_fields(sig) := {"fetchUrl": url} if {
	sig.url != ""
	matches := regex.find_n(_fetch_url_pattern, sig.url, 1)
	count(matches) > 0
	url := matches[0]
}

deny contains finding if {
	some sig in _signals
	sig.tier == "exec"
	base := {
		"code":     "ISSUE-714",
		"severity": "high",
		"message":  sprintf("%s fetches and runs remote code from a mutable ref with no checksum (`%s`) — a SHA pin on the action does not reach this; a clean result means \"no known pattern seen\", not \"safe\"", [sig.who, sig.url]),
		"job":      sig.job,
		"uses":     sig.uses,
		"line":     sig.line,
	}
	with_guard := object.union(base, _guard_fields(sig))
	with_verified := object.union(with_guard, _verified_fields(sig))
	finding := object.union(with_verified, _url_fields(sig))
}

deny contains finding if {
	some sig in _signals
	sig.tier == "unverified"
	finding := {
		"code":     "ISSUE-716",
		"severity": "low",
		"message":  sprintf("%s: could not fetch the action source to verify it (offline, GHES, private, rate-limited, or a Docker-image action) — reported as could-not-verify, not a pass", [sig.who]),
		"job":      sig.job,
		"uses":     sig.uses,
		"line":     sig.line,
	}
}
