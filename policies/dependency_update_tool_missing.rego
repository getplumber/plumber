# dependency-update-tool-missing — flag repositories with workflows
# but without any dependency-update tool configured. A project that
# pins its dependencies (which every sane workflow does via
# `actions/checkout@<sha>` etc.) then has no automation to refresh
# those pins as upstream ships patches, and every unpatched CVE
# stays in place until a human remembers to look.
#
# Satisfied by either `.github/dependabot.yml` (any shape) or a
# Renovate config at a conventional path. The collector populates
# `Dependabot` and `RenovateConfigPath` accordingly.
package dependency_update_tool_missing

import rego.v1

deny contains finding if {
	input.pipeline.provider == "github"
	count(input.pipeline.jobs) > 0
	not input.pipeline.dependabot
	not input.pipeline.renovateConfigPath
	first_file := input.pipeline.jobs[0].originFile
	finding := {
		"code":     "ISSUE-608",
		"severity": "medium",
		"message":  "repository has workflows but neither dependabot.yml nor renovate.json is configured — dependency pins will drift and stale CVEs will persist",
		"file":     first_file,
	}
}
