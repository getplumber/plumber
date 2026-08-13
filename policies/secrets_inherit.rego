# secrets-inherit — flag reusable-workflow calls that forward every
# caller-visible secret to the callee via `secrets: inherit`.
# The blast radius of a compromised reusable workflow then scales with
# the caller's full secret surface (repository + organisation +
# environment) rather than with the narrow set the callee actually
# needs. Explicit per-secret mappings are the safer pattern:
#
#   jobs:
#     call:
#       uses: owner/shared/.github/workflows/publish.yml@abc123…
#       secrets:
#         NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
#
# The collector surfaces ReusableWorkflowUses and SecretsInherit on
# the IR directly, so the rule reduces to checking those two fields.
package secrets_inherit

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	job.reusableWorkflowUses != ""
	job.secretsInherit == true
	finding := {
		"code":     "ISSUE-302",
		"severity": "high",
		"message":  sprintf("job %q calls reusable workflow %q with `secrets: inherit` — forward only the secrets the callee needs", [job.name, job.reusableWorkflowUses]),
		"job":      job.name,
		"uses":     job.reusableWorkflowUses,
	}
}
