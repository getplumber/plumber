# secrets-outside-env — flag deploy / publish / release jobs that
# consume production secrets without an `environment:` gate. GitHub's
# environment feature is the hook for required reviewers, wait
# timers, and deployment branch rules — without one, any caller on
# the trigger reaches the secret-bearing step with no human in the
# loop.
#
# The heuristic: a job that either
#
#   - runs on the `release` trigger, OR
#   - invokes a canonical publish action (PyPI, npm, Maven Central,
#     container-image push, k8s apply, …)
#
# AND references a secret (`secrets.*`) in its scripts / env / action
# inputs AND has no `environment:` set. Normal CI jobs that happen to
# read a secret (CODECOV_TOKEN, NPM_TOKEN for tests) stay silent — the
# deploy-like context is a prerequisite.
package secrets_outside_env

import rego.v1

publish_action_prefixes := {
	"pypa/gh-action-pypi-publish",
	"JS-DevTools/npm-publish",
	"gradle/publish-plugin",
	"softprops/action-gh-release",
	"ncipollo/release-action",
	"goreleaser/goreleaser-action",
	"docker/build-push-action",
	"azure/k8s-deploy",
	"google-github-actions/deploy-cloudrun",
	"google-github-actions/deploy-appengine",
	"aws-actions/amazon-ecs-deploy-task-definition",
}

secret_ref_pattern := `\$\{\{\s*secrets\.[A-Za-z_]`

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_is_deploy_context(job)
	_job_uses_secrets(job)
	not job.environment
	finding := {
		"code":     "ISSUE-305",
		"severity": "medium",
		"message":  sprintf("deploy/publish job %q consumes secrets without an `environment:` gate — no reviewer, wait timer or branch rule stands between the trigger and the secret", [job.name]),
		"job":      job.name,
	}
}

_is_deploy_context(job) if {
	some t in job.triggers
	t == "release"
}

_is_deploy_context(job) if {
	some k
	action := job.uses[k]
	_is_publish_action(action.uses)
}

_is_publish_action(uses) if {
	some prefix in publish_action_prefixes
	startswith(uses, sprintf("%s@", [prefix]))
}

_is_publish_action(uses) if {
	some prefix in publish_action_prefixes
	uses == prefix
}

_job_uses_secrets(job) if {
	some k
	regex.match(secret_ref_pattern, job.scripts[k])
}

_job_uses_secrets(job) if {
	some _, value in job.variables
	regex.match(secret_ref_pattern, value)
}

_job_uses_secrets(job) if {
	some k
	action := job.uses[k]
	some _, value in action.with
	is_string(value)
	regex.match(secret_ref_pattern, value)
}
