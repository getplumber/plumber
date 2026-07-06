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

deny contains finding if {
	some sig in _signals
	sig.tier == "exec"
	finding := {
		"code":     "ISSUE-714",
		"severity": "high",
		"message":  sprintf("%s fetches and runs remote code from a mutable ref with no checksum (`%s`) — a SHA pin on the action does not reach this; a clean result means \"no known pattern seen\", not \"safe\"", [sig.who, sig.url]),
		"job":      sig.job,
		"uses":     sig.uses,
		"line":     sig.line,
	}
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
