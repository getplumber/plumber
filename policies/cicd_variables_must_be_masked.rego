# cicd-variables-must-be-masked — flag project CI/CD settings variables
# (GitLab: Settings > CI/CD > Variables, NOT the CI file's `variables:` block)
# that are not `masked`. An unmasked variable prints verbatim in every job log
# any project member can read, so a secret stored unmasked leaks to everyone
# with log access.
#
# GitLab refuses to mask a value shorter than 8 characters (or one with
# disallowed characters). Such variables are still flagged: the value is never
# projected onto the IR (per the #370 variable-sensitivity tiers), so the rule
# cannot special-case them by length, and the exposure is real regardless —
# the fix for an unmaskable secret is to restructure it, not to leave it in
# the clear. Shares its collector and identity with the protected-variable
# sibling; settingsVariablesKnown gates both so an unreadable settings API
# reports not-evaluable rather than a false pass.
#
# File-type variables (kubeconfigs, TLS keys, service-account JSON, ...) are
# excluded: GitLab does not offer the "Mask variable" option for file type, so
# it can never be masked and flagging it would be an unfixable, permanent false
# positive. Only env_var (the only maskable type) is checked.
package cicd_variables_must_be_masked

import rego.v1

deny contains finding if {
	input.pipeline.provider == "gitlab"
	input.pipeline.settingsVariablesKnown
	some v in input.pipeline.settingsVariables
	lower(v.type) != "file"
	not v.masked
	finding := {
		"code":         "ISSUE-202",
		"severity":     "medium",
		"message":      sprintf("CI/CD settings variable %q is not masked — its value prints in job logs; enable masking (GitLab requires a value of at least 8 characters)", [v.name]),
		"variableName": v.name,
		"variableType": v.type,
		"environment":  v.environment,
	}
}
