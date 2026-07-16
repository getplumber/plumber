# artipacked — detect jobs that check out the repository with
# `actions/checkout` without disabling credential persistence. By
# default, actions/checkout writes the GITHUB_TOKEN into the cloned
# repository's .git/config, where it survives for the lifetime of the
# job. Any later step that uploads `.git` as part of an artifact, or
# that executes fork-controlled code, can exfiltrate the token. The
# documented mitigation is a one-liner: `with: persist-credentials:
# false`.
#
# This check pairs with dangerous-triggers (ISSUE-802) and
# template-injection (ISSUE-207): the persisted credential is
# precisely what an attacker harvests once they escalate through the
# trigger / injection path.
package artipacked

import rego.v1

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	startswith(action.uses, "actions/checkout@")
	not _credentials_disabled(action)
	finding := {
		"code":     "ISSUE-307",
		"severity": "high",
		"message":  sprintf("job %q runs %q without `persist-credentials: false` — GITHUB_TOKEN lingers in .git/config and is exfiltrable by later steps", [job.name, action.uses]),
		"job":      job.name,
		"uses":     action.uses,
		"line":     object.get(action, "line", 0),
	}
}

# YAML represents `persist-credentials: false` as the boolean false.
# Accept both forms defensively in case a workflow uses quotes.
_credentials_disabled(action) if {
	action.with["persist-credentials"] == false
}

_credentials_disabled(action) if {
	action.with["persist-credentials"] == "false"
}
