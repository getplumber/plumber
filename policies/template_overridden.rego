# template-overridden — flag pipelines that import a required CI/CD
# template but redefine some of its jobs with forbidden CI/CD keys
# (script, image, rules, …). The match set comes from
# pipelineMustIncludeTemplate.requiredGroups and the per-origin
# overridden-job list is populated by the collector (same regex as the
# legacy Go control).
package template_overridden

import rego.v1

deny contains finding if {
	input.config.pipelineMustIncludeTemplate
	groups := input.config.pipelineMustIncludeTemplate.requiredGroups
	count(groups) > 0
	some i, j, k
	group := groups[i]
	required := group[j]
	inc := input.pipeline.includes[k]
	_is_template_kind(inc.kind)
	_paths_match(inc, required)
	count(inc.overriddenJobs) > 0
	jobs := _overridden_jobs(inc)
	finding := {
		"code":     "ISSUE-406",
		"severity": "high",
		"message":  sprintf("required template %q is imported but %d of its job(s) are overridden locally", [required, count(inc.overriddenJobs)]),
		# No "job": an overridden template is not a job. templatePath names what
		# this finding is about, so its identity does not depend on the message
		# above, whose override count moves as jobs are added.
		"templatePath": required,
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

_is_template_kind(kind) if {
	kind != "component"
	kind != "hardcoded"
	kind != ""
}

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
