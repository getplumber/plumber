# workflow-misfeature — flag two supported-but-harmful patterns:
#
#   1. `actions/upload-artifact` with `path: .` (or the checkout
#      directory) uploads the entire repository, including `.git/`.
#      Paired with artipacked (ISSUE-307) this exfiltrates the
#      GITHUB_TOKEN to anyone who can download the artefact.
#   2. `actions/upload-artifact` with `path: ${{ github.workspace }}`
#      — same thing, just dressed up as an expression.
#
# Other misfeature patterns from the catalog — `shell: cmd`, inline
# pip install with a remote URL — are either covered by ISSUE-411
# (unverified scripts) or require step-level shell tracking the IR
# does not carry yet.
package workflow_misfeature

import rego.v1

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	startswith(action.uses, "actions/upload-artifact@")
	path := action.with.path
	is_string(path)
	_uploads_checkout_dir(path)
	finding := {
		"code":     "ISSUE-419",
		"severity": "medium",
		"message":  sprintf("job %q uploads the checkout directory as an artefact (path=%q) — `.git/` leaks with it, pair with ISSUE-307 to understand the risk", [job.name, path]),
		"job":      job.name,
	}
}

_uploads_checkout_dir(path) if {
	path == "."
}

_uploads_checkout_dir(path) if {
	path == "./"
}

_uploads_checkout_dir(path) if {
	regex.match(`\$\{\{\s*github\.workspace\s*\}\}\s*/?$`, path)
}
