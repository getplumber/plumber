# invalid-workflow - flag a GitHub Actions workflow file this scan
# fetched but Plumber's own parser could not read as a workflow (an
# undefined YAML anchor, a tab-indented block, a duplicate key, a syntax
# error). GitHub shows a file it cannot read as invalid on the Actions
# tab and does not run it; for these constructs the two agree. The file
# was fetched fine, so this is reported as a finding of its own rather
# than a collection failure (monorepo issue #517).
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
		"message":  sprintf("workflow file %q could not be parsed as a workflow: %s", [w.path, w.error]),
		"file":     w.path,
	}
}
