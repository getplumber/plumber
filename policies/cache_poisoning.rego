# cache-poisoning — flag release / publish jobs that restore a build
# cache without a release-ref-scoped key. GitHub Actions caches are
# shared across branches with permissive fallback: a PR run on a feature
# branch can populate the same cache key that a later release-triggered
# job restores, silently injecting compromised artefacts into the
# published output (the May 2026 TanStack vector).
#
# A job is release context when its workflow triggers include `release`,
# it runs a publish action, or it runs a publish command in a script. A
# restore is flagged unless BOTH the cache key and every restore-keys
# fallback weave the release ref.
#
# This rule is data-driven: the entire action/script inventory AND the
# per-action cache semantics come from input.config.cachePoisoning, so
# the yaml is the single source of truth and the rego hardcodes nothing
# about which actions exist. Config shape:
#
#   publishActions:        ["owner/repo", ...]
#   publishScriptPatterns: ["<regex>", ...]
#   cacheActions:
#     - { action: "actions/cache",       mode: "always" }
#     - { action: "actions/setup-go",    mode: "default", disableInput: "cache", disableValue: false }
#     - { action: "gradle/actions/setup-gradle", mode: "default", disableInput: "cache-disabled", disableValue: true }
#     - { action: "actions/setup-node",  mode: "opt-in",  enableInput: "cache" }
#
# mode:
#   always   restores whenever the action is present.
#   default  restores unless disableInput holds disableValue.
#   opt-in   restores only when enableInput names a manager (a non-empty,
#            non-"false" string).
#
# The only thing kept in code is the github.ref* scope-token regex — what
# counts as "weaving the release ref" is fixed GitHub expression syntax.
package cache_poisoning

import rego.v1

_publish_actions := object.get(input, ["config", "cachePoisoning", "publishActions"], [])

_publish_script_patterns := object.get(input, ["config", "cachePoisoning", "publishScriptPatterns"], [])

_cache_action_specs := object.get(input, ["config", "cachePoisoning", "cacheActions"], [])

# A release-scoped reference weaves the ref, tag, or release version into
# a string.
release_scope_pattern := `github\.(ref(_name)?|sha|event\.release|event\.pull_request\.head\.sha)`

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	not _job_allowed(job)
	_is_release_context(job)
	action := job.uses[j]
	_restores_cache(action)
	not _properly_scoped(action)
	finding := {
		"code":     "ISSUE-705",
		"severity": "high",
		"message":  sprintf("job %q restores a cache via %q on a release-type trigger — scope the key (and any restore-keys) to the release ref or disable caching on publish paths", [job.name, action.uses]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

# ── release context ──────────────────────────────────────────────────
_is_release_context(job) if {
	some t in job.triggers
	t == "release"
}

_is_release_context(job) if {
	some k
	_is_publish_action(job.uses[k].uses)
}

_is_release_context(job) if {
	some k
	some pat in _publish_script_patterns
	regex.match(pat, job.scripts[k])
}

_is_publish_action(uses) if {
	some p in _publish_actions
	_uses_prefix(uses, p)
}

# ── does the action restore a cache? (fully spec-driven) ─────────────
_restores_cache(action) if {
	some spec in _cache_action_specs
	_uses_prefix(action.uses, spec.action)
	_cache_active(action, spec)
}

_cache_active(_, spec) if spec.mode == "always"

_cache_active(action, spec) if {
	spec.mode == "default"
	not _cache_disabled(action, spec)
}

_cache_active(action, spec) if {
	spec.mode == "opt-in"
	_cache_enabled(action, spec)
}

# A default-on action is disabled when its disableInput holds disableValue
# (matched against the YAML boolean and the quoted-string form, any case).
_cache_disabled(action, spec) if {
	v := action.with[spec.disableInput]
	_as_bool(v) == spec.disableValue
}

# An opt-in action caches only when its enableInput names a manager.
_cache_enabled(action, spec) if {
	c := action.with[spec.enableInput]
	is_string(c)
	c != ""
	lower(c) != "false"
}

# Normalise a with-value to a bool: a real bool as-is, or a "true"/"false"
# string (any case) to its bool. Anything else is undefined (no match).
_as_bool(v) := v if is_boolean(v)

_as_bool(v) := true if {
	is_string(v)
	lower(v) == "true"
}

_as_bool(v) := false if {
	is_string(v)
	lower(v) == "false"
}

# ── key scoping ──────────────────────────────────────────────────────
# Properly scoped means the key weaves the ref AND no restore-keys entry
# falls back to an unscoped prefix.
_properly_scoped(action) if {
	_key_is_release_scoped(action)
	not _has_unscoped_restore_key(action)
}

_key_is_release_scoped(action) if {
	key := action.with.key
	is_string(key)
	regex.match(release_scope_pattern, key)
}

_has_unscoped_restore_key(action) if {
	some k in _restore_keys(action)
	trim_space(k) != ""
	not regex.match(release_scope_pattern, k)
}

# restore-keys is authored either as a `|` block scalar (one key per
# line) or a YAML list.
_restore_keys(action) := ks if {
	is_string(action.with["restore-keys"])
	ks := split(action.with["restore-keys"], "\n")
}

_restore_keys(action) := ks if {
	is_array(action.with["restore-keys"])
	ks := action.with["restore-keys"]
}

# ── allowlist: jobs the org has reviewed and accepted ────────────────
_job_allowed(job) if {
	some pattern in object.get(input, ["config", "cachePoisoning", "allowedJobs"], [])
	glob.match(pattern, null, job.name)
}

# ── helpers ──────────────────────────────────────────────────────────
_uses_prefix(uses, p) if uses == p

_uses_prefix(uses, p) if startswith(uses, sprintf("%s@", [p]))
