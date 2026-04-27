# cache-poisoning — flag release / publish jobs that prime a build
# cache via actions/cache (or the language-specific setup-* action's
# built-in cache) without an explicit release-scoped key. GitHub
# Actions caches are shared across branches with permissive fallback:
# a PR run on a feature branch can populate the same cache key that
# a later release-triggered job restores, silently injecting
# compromised artefacts into the published output.
#
# "Release context" here is any job whose workflow triggers include
# `release`, `push` with a tag filter (implicit via the `v*` pattern
# cache setups commonly key on), `workflow_dispatch` with a release
# intent, or that references `publish`, `release`, `build-release`
# semantics in scripts. The collector only surfaces the trigger
# names so the policy focuses on `release` + `push` triggers — the
# most common vectors.
package cache_poisoning

import rego.v1

cache_actions := {
	"actions/cache",
	"actions/cache/restore",
	"gradle/actions/setup-gradle",
	"actions/setup-node",
	"actions/setup-go",
	"actions/setup-python",
	"actions/setup-java",
	"pnpm/action-setup",
}

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	_is_release_context(job)
	action := job.uses[j]
	_uses_cache_action(action.uses)
	not _key_is_release_scoped(action)
	finding := {
		"code":     "ISSUE-106",
		"severity": "high",
		"message":  sprintf("job %q restores a cache via %q on a release-type trigger — scope the key to the release ref or disable caching on publish paths", [job.name, action.uses]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

_is_release_context(job) if {
	some t in job.triggers
	t == "release"
}

# Workflows that run a canonical publish action on a job — even under
# push/workflow_dispatch triggers — are still release-intent. Those
# actions lift the built artifact out of the runner; a poisoned cache
# restore before they execute lands straight on the registry.
_is_release_context(job) if {
	some k
	action := job.uses[k]
	_is_publish_action(action.uses)
}

publish_actions := {
	"pypa/gh-action-pypi-publish",
	"JS-DevTools/npm-publish",
	"gradle/publish-plugin",
	"softprops/action-gh-release",
	"ncipollo/release-action",
	"goreleaser/goreleaser-action",
	"crazy-max/ghaction-docker-buildx",
}

_is_publish_action(uses) if {
	some prefix in publish_actions
	startswith(uses, sprintf("%s@", [prefix]))
}

_is_publish_action(uses) if {
	some prefix in publish_actions
	uses == prefix
}

_uses_cache_action(uses) if {
	some prefix in cache_actions
	startswith(uses, sprintf("%s@", [prefix]))
}

_uses_cache_action(uses) if {
	some prefix in cache_actions
	uses == prefix
}

# A release-scoped key references the ref, tag, or release version.
# Looks for the canonical github.ref* / github.event.release.* /
# tag / version tokens inside the key string. The check is
# deliberately lenient — anything that weaves the ref into the key
# breaks the cross-branch fallback.
_key_is_release_scoped(action) if {
	key := action.with.key
	is_string(key)
	regex.match(`github\.(ref(_name)?|sha|event\.release|event\.pull_request\.head\.sha)`, key)
}

_key_is_release_scoped(action) if {
	key := action.with.key
	is_string(key)
	regex.match(`\$\{\{\s*github\.ref`, key)
}
