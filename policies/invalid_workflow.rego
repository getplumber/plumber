# invalid-workflow - flag a GitHub Actions workflow file this scan
# fetched but could not parse as a workflow (an undefined YAML anchor, a
# tab-indented block, a duplicate key, a syntax error). GitHub itself
# refuses to run such a file and shows it as invalid on the Actions tab,
# so whatever that workflow was meant to do never happens. The file was
# fetched fine, so this is reported as a finding of its own rather than a
# collection failure (monorepo issue #517).
#
# One finding per entry of input.pipeline.invalidWorkflows.
package invalid_workflow

import rego.v1

deny contains finding if {
	input.pipeline.provider == "github"
	some w in input.pipeline.invalidWorkflows
	finding := {
		"code":     "ISSUE-423",
		"severity": "low",
		"message":  sprintf("workflow file %q is not a valid workflow: %s; GitHub will not run it", [w.path, w.error]),
		"file":     w.path,
	}
}
