# cicd-variables-must-be-protected — flag project CI/CD settings variables
# (GitLab: Settings > CI/CD > Variables, NOT the CI file's `variables:` block)
# that are not marked `protected`. An unprotected variable is injected into
# pipelines running on ANY branch, including unprotected branches any
# developer can push to, so a malicious or careless branch can exfiltrate it.
# A protected variable is only exposed to pipelines on protected branches and
# tags.
#
# The collector (gitlab/dataCollectionGitlabVariables.go) projects the
# settings variables onto input.pipeline.settingsVariables carrying identity
# and flags only — never the value (per the #370 variable-sensitivity tiers).
# input.pipeline.settingsVariablesKnown is false when the settings API could
# not be read (a 401/403 from a token without variable-read scope); the rule
# abstains then, so the control reports not-evaluable rather than a false pass.
package cicd_variables_must_be_protected

import rego.v1

deny contains finding if {
	input.pipeline.provider == "gitlab"
	input.pipeline.settingsVariablesKnown
	some v in input.pipeline.settingsVariables
	not v.protected
	finding := {
		"code":         "ISSUE-201",
		"severity":     "medium",
		"message":      sprintf("CI/CD settings variable %q is not protected — it is exposed to pipelines on unprotected branches; mark it protected so it is only injected into pipelines on protected branches and tags", [v.name]),
		"variableName": v.name,
		"variableType": v.type,
		"environment":  v.environment,
	}
}
