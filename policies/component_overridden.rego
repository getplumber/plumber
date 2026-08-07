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
	finding := {
		"code":     "ISSUE-409",
		"severity": "high",
		"message":  sprintf("required component %q is imported but %d of its job(s) are overridden locally", [required, count(inc.overriddenJobs)]),
		# No "job": an overridden component is not a job. componentPath names
		# what this finding is about, so its identity does not depend on the
		# message above, whose override count moves as jobs are added.
		"componentPath": required,
	}
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
