# sast-workflow-missing — flag repositories that ship workflows but
# do not run any recognised static application security testing
# scanner. SAST catches whole vulnerability classes (injection,
# unsafe deserialisation, crypto misuse) before they reach
# production; leaving it out of CI means the only gate is manual
# review, which misses regressions on large diffs.
#
# Repository-level rule — emits once per repo when the condition
# holds, identified by the first job's file. Projects that genuinely
# cannot run SAST in CI can disable the rule via
# `--skip-controls repositoriesMustRunSAST`.
package sast_workflow_missing

import rego.v1

sast_action_prefixes := {
	"github/codeql-action/init",
	"github/codeql-action/analyze",
	"returntocorp/semgrep-action",
	"semgrep/semgrep-action",
	"sonarsource/sonarqube-scan-action",
	"sonarsource/sonarcloud-github-action",
	"aquasecurity/trivy-action",
	"snyk/actions",
	"fossas/fossa-action",
	"trufflesecurity/trufflehog",
	"anchore/scan-action",
	"bearer/bearer-action",
	"checkmarx/ast-github-action",
	"microsoft/DevSkim-Action",
	"gitleaks/gitleaks-action",
	"shiftleftsecurity/scan-action",
	"zaproxy/action-baseline",
}

deny contains finding if {
	input.pipeline.provider == "github"
	count(input.pipeline.jobs) > 0
	not _any_workflow_runs_sast
	# Emit once, anchored on the first job's file so the renderer
	# has something to show in the `↳ at` hint.
	first_file := input.pipeline.jobs[0].originFile
	finding := {
		"code":     "ISSUE-904",
		"severity": "low",
		"message":  "repository ships workflows but none runs a recognised SAST scanner — add CodeQL / Semgrep / SonarQube / Trivy",
		"file":     first_file,
	}
}

_any_workflow_runs_sast if {
	some i, j
	action := input.pipeline.jobs[i].uses[j]
	some prefix in sast_action_prefixes
	startswith(action.uses, sprintf("%s@", [prefix]))
}

_any_workflow_runs_sast if {
	some i, j
	action := input.pipeline.jobs[i].uses[j]
	some prefix in sast_action_prefixes
	action.uses == prefix
}
