# use-trusted-publishing — flag PyPI / npm / Maven-Central publish
# steps that rely on a long-lived static token instead of OIDC
# trusted publishing. The explicit signal is a `password:` /
# `NODE_AUTH_TOKEN` / equivalent `with:` / `env:` input that points
# at a secrets.* value, paired with a known publish action.
#
# OIDC trusted publishing removes the standing secret: tokens are
# short-lived, scoped to a repository / workflow / environment, and
# minted only for the run that claims them. Projects migrating away
# from static tokens drop the `password:` input entirely.
package use_trusted_publishing

import rego.v1

# Publish actions we know about. The policy does not cover every
# obscure community action — Dependabot's own publish pipeline, for
# instance — but the big three ecosystems are here.
publish_actions := {
	"pypa/gh-action-pypi-publish":     "PyPI",
	"JS-DevTools/npm-publish":         "npm",
	"gradle/gradle-build-action":      "Gradle",
	"gradle/actions/publish":          "Gradle",
	"sonatype/central-publishing-gradle-plugin": "Maven Central",
}

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	ecosystem := _publish_action_ecosystem(action.uses)
	_step_uses_static_token(action)
	finding := {
		"code":     "ISSUE-421",
		"severity": "high",
		"message":  sprintf("job %q publishes to %s via %q with a static token — migrate to OIDC trusted publishing", [job.name, ecosystem, action.uses]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

_publish_action_ecosystem(uses) := eco if {
	some prefix, ecosystem in publish_actions
	startswith(uses, sprintf("%s@", [prefix]))
	eco := ecosystem
}

_publish_action_ecosystem(uses) := eco if {
	some prefix, ecosystem in publish_actions
	uses == prefix
	eco := ecosystem
}

_step_uses_static_token(action) if {
	# pypa/gh-action-pypi-publish keys its token on `password`.
	# When OIDC is used, the input is simply omitted.
	pw := action.with.password
	is_string(pw)
	regex.match(`\$\{\{\s*secrets\.`, pw)
}

_step_uses_static_token(action) if {
	# JS-DevTools/npm-publish: `token` input holds the static token.
	tok := action.with.token
	is_string(tok)
	regex.match(`\$\{\{\s*secrets\.`, tok)
}
