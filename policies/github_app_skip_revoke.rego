# github-app-skip-revoke — flag workflows that mint a GitHub App
# installation token and disable revocation on exit. The canonical
# action (`actions/create-github-app-token`) exposes a
# `skip-token-revoke:` input that defaults to `false`; setting it to
# `true` keeps the minted token alive long after the workflow
# terminates. A later leak (log fragment, artefact, cache) then
# hands the attacker a still-working token with the App's full
# permission set.
#
# The policy matches the `with.skip-token-revoke` input on any step
# whose `uses:` starts with the canonical app-token actions. Other
# community actions that follow the same input naming pick up the
# check for free.
package github_app_skip_revoke

import rego.v1

token_actions := {
	"actions/create-github-app-token",
	"tibdex/github-app-token",
	"getsentry/action-github-app-token",
	"peter-murray/workflow-application-token-action",
}

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	_is_app_token_action(action.uses)
	_revocation_disabled(action)
	finding := {
		"code":     "ISSUE-306",
		"severity": "high",
		"message":  sprintf("job %q mints a GitHub App token via %q with `skip-token-revoke: true` — the token survives the run and any later leak stays exploitable", [job.name, action.uses]),
		"job":      job.name,
		"uses":     action.uses,
	}
}

_is_app_token_action(uses) if {
	some prefix in token_actions
	startswith(uses, sprintf("%s@", [prefix]))
}

_is_app_token_action(uses) if {
	some prefix in token_actions
	uses == prefix
}

_revocation_disabled(action) if {
	action.with["skip-token-revoke"] == true
}

_revocation_disabled(action) if {
	action.with["skip-token-revoke"] == "true"
}
