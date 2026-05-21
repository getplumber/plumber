# dependabot-insecure-exec — flag repositories whose .github/
# dependabot.yml sets `insecure-external-code-execution: allow` on
# any update ecosystem. That toggle lets Dependabot run install /
# postinstall hooks from arbitrary candidate dependency versions
# during version resolution, giving any compromised upstream package
# a direct path into the privileged Dependabot runner.
#
# The collector surfaces the list of ecosystems with the toggle set
# to allow; if that slice is non-empty, we emit one finding per
# ecosystem so the remediation wording can name which one is wrong.
package dependabot_insecure_exec

import rego.v1

deny contains finding if {
	input.pipeline.dependabot
	some i
	ecosystem := input.pipeline.dependabot.insecureExecEcosystems[i]
	finding := {
		"code":     "ISSUE-901",
		"severity": "critical",
		"message":  sprintf("dependabot ecosystem %q re-enables insecure-external-code-execution — set it back to `deny` or remove the override", [ecosystem]),
		"file":     input.pipeline.dependabot.path,
	}
}
