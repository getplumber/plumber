# impostor-commit — flag workflow steps pinned to a 40-character
# SHA that does not resolve in the action's upstream repository.
# Either a typo (the runner silently falls back to the default
# branch) or the literal `impostor commit` attack vector: a commit
# that looks legitimate in a PR comment / stargazer URL but was
# never merged upstream.
#
# Requires the collector to have resolved the action's GitHub
# metadata. When metadata is missing we stay silent — verifying a
# SHA against the upstream repo needs an API call and we refuse to
# guess.
package impostor_commit

import rego.v1

sha_pattern := `^[0-9a-f]{40}$`

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	ref := _ref_of(action.uses)
	regex.match(sha_pattern, ref)
	action.metadata
	action.metadata.refExists == false
	finding := {
		"code":     "ISSUE-109",
		"severity": "critical",
		"message":  sprintf("job %q pins action %q to a commit SHA that does not exist in the upstream repository — typo or impostor-commit attack", [job.name, action.uses]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

_ref_of(uses) := ref if {
	idx := indexof(uses, "@")
	idx >= 0
	ref := substring(uses, idx + 1, -1)
}
