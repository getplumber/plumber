# superfluous-action — flag third-party actions that duplicate
# functionality already on the GitHub-hosted runner. Each such
# reference is an extra supply-chain dependency for zero capability
# gain — the sort of link an `impostor-commit`, a tag retag, or a
# maintainer account compromise can turn into a foothold without
# any functional reason to have accepted the risk.
#
# The curated list tracks the most common offenders: small wrappers
# over `gh`, shell retry loops, and action installers for tools
# `ubuntu-latest` already has on PATH (`yq`, `jq`, `python`). It is
# intentionally conservative — complex actions (`actions/cache`,
# `actions/artifact`, `actions/setup-<lang>`) do enough real work to
# stay off this list.
#
# Users who disagree with a specific entry can drop the rule on the
# workflow via `--skip-controls actionsMustNotDuplicateRunnerBuiltins`
# rather than fight the list.
package superfluous_action

import rego.v1

superfluous_prefixes := {
	"peter-evans/create-pull-request":    "gh pr create from the runner",
	"nick-invision/retry":                 "bash `for i in 1 2 3; do ... && break; done`",
	"nick-fields/retry":                   "bash `for i in 1 2 3; do ... && break; done`",
	"actions-ecosystem/action-regex-match": "bash `[[ $X =~ $re ]]` / `grep -E`",
	"mikefarah/yq-action":                  "`yq` is preinstalled on ubuntu-latest",
	"dcarbone/install-jq-action":           "`jq` is preinstalled on ubuntu-latest",
	"nicholasdille/run-with-retry":         "bash retry loop",
	"andymckay/labeler":                    "gh api gh pr edit --add-label",
	"actions-ecosystem/action-add-labels":  "gh api gh pr edit --add-label",
}

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	reason := _superfluous_reason(action.uses)
	finding := {
		"code":     "ISSUE-711",
		"severity": "low",
		"message":  sprintf("job %q uses %q — same effect as %q from the runner, drop the third-party dependency", [job.name, action.uses, reason]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

_superfluous_reason(uses) := reason if {
	some prefix, r in superfluous_prefixes
	startswith(uses, sprintf("%s@", [prefix]))
	reason := r
}

_superfluous_reason(uses) := reason if {
	some prefix, r in superfluous_prefixes
	uses == prefix
	reason := r
}
