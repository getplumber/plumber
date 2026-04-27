# security-policy-missing — flag repositories that have workflows
# but no SECURITY.md disclosure policy. Without one, researchers
# who find an issue have no public contact channel beyond opening
# a GitHub issue, which defeats coordinated disclosure and trains
# them to dump vulnerabilities in the open. The file can be short:
# two lines naming the contact channel and the expected response
# window are enough to move reports off the public tracker.
#
# The collector probes the three locations GitHub itself recognises
# (repo root, `.github/`, `docs/`) and surfaces the path when it
# finds one. Empty path ⇒ finding.
package security_policy_missing

import rego.v1

deny contains finding if {
	input.pipeline.provider == "github"
	count(input.pipeline.jobs) > 0
	not input.pipeline.securityPolicyPath
	first_file := input.pipeline.jobs[0].originFile
	finding := {
		"code":     "ISSUE-610",
		"severity": "low",
		"message":  "repository has workflows but no SECURITY.md policy file — add one at the repo root or under .github/ to document the disclosure channel",
		"file":     first_file,
	}
}
