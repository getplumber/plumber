# component-overridden — flag pipelines that import a required CI/CD
# component but redefine some of its jobs with forbidden CI/CD keys
# (script, image, rules, …). Overriding a required component locally
# silently defeats the compliance intent: the job name is still there,
# but its behaviour is no longer the component's behaviour. The match
# set comes from pipelineMustIncludeComponent.requiredGroups; the
# overridden-job list is populated by the collector.
package component_overridden

import rego.v1

deny contains finding if {
	input.config.pipelineMustIncludeComponent
	groups := input.config.pipelineMustIncludeComponent.requiredGroups
	count(groups) > 0
	some i, j, k
	group := groups[i]
	required := group[j]
	inc := input.pipeline.includes[k]
	inc.kind == "component"
	_paths_match(inc, required)
	count(inc.overriddenJobs) > 0
	jobs := _overridden_jobs(inc)
	finding := {
		"code":     "ISSUE-409",
		"severity": "high",
		"message":  sprintf("The required component `%s` is imported but the project overrides %d of its jobs.", [required, count(inc.overriddenJobs)]),
		# No "job": an overridden component is not a job. componentPath names
		# what this finding is about, so its identity does not depend on the
		# message above, whose override count moves as jobs are added.
		"componentPath": required,
		# The digest of the override content the collector computed. It moves
		# when the override changes, so a decision keyed on it lapses exactly
		# then, and it carries none of the overridden content itself.
		"overrideFingerprint": object.get(inc, "overrideFingerprint", ""),
		"overriddenJobs":      jobs,
	}
}

# _overridden_jobs reports what was overridden, for a reader: the job name and
# the CI/CD keys it redefines. The values behind those keys stay in the CLI,
# where they only feed the fingerprint above.
#
# Both lookups default rather than dereference: an absent evidence field must
# leave the finding thinner, never make the deny rule drop a real override.
_overridden_jobs(inc) := [{"name": j.name, "keys": object.get(j, "keys", [])} |
	some j in inc.overriddenJobs
]

_paths_match(inc, required) if {
	inc.path != ""
	inc.path == required
}

_paths_match(inc, required) if {
	inc.altPath != ""
	inc.altPath == required
}

_paths_match(inc, required) if {
	inc.source != ""
	inc.source == required
}
