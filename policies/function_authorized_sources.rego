# function-authorized-sources (ISSUE-415) — flag `run:` step function
# references (docs.gitlab.com/ci/functions) pulled from a source that is
# not trusted by functionMustComeFromAuthorizedSources. Functions run
# arbitrary code with the job's full context, the same supply-chain
# exposure as CI/CD components. Trust is evaluated identically for every
# reference form — a deprecated form is NOT a free pass; deprecation is
# tracked separately (ir.Function.Deprecated, surfaced as a terminal stat)
# and carries no weight here.
#
# A reference is trusted when it matches an explicit trustedFunctions
# allowlist pattern, or (trustSameGroupFunctions, default true) the ref is
# hosted on the scanned GitLab instance (instanceHost) and its path starts
# with the project's own root namespace (top-level group) — a same-namespace
# check that only looks at the path after an unvalidated host segment would
# trust any registry that happens to name a top-level path after the
# victim's namespace (ISSUE-415 hardening).
#
# Allowlist patterns may themselves reference GitLab predefined CI/CD
# variables (e.g. the shipped defaults `$CI_TEMPLATE_REGISTRY_HOST/
# $CI_PROJECT_PATH/*` and its `${VAR}` equivalent — both notations are
# shipped since pipeline authors write either form, and _normalize_var
# treats them identically). GitLab predefined variables have the lowest
# precedence, so a pipeline that redefines one of them in its own
# `variables:` block could make Plumber trust pattern text that resolves to
# an attacker registry at runtime — _in_allowlist guards against this by
# rejecting a pattern match if any `$CI_*` variable referenced by that
# pattern is redefined in the pipeline's globalVariables/localGlobalVariables
# (ISSUE-415 hardening).
#
# "local" (relative/absolute filesystem path) references are same-repo
# and out of scope entirely, mirroring how `include: local` is out of
# scope for component-authorized-sources.
package function_authorized_sources

import rego.v1

deny contains finding if {
	input.config.functionAuthorizedSources
	some i, j
	job := input.pipeline.jobs[i]
	fn := job.functions[j]
	fn.kind != "local"
	not _is_authorized(fn)
	finding := {
		"code":     "ISSUE-415",
		"severity": "high",
		"message":  sprintf("job %q uses function %q from untrusted source: %s", [job.name, _fn_name(fn), fn.ref]),
		"job":      job.name,
		"link":     fn.ref,
		"status":   "unauthorized",
	}
}

# fn.name is omitted from the JSON payload entirely when empty
# (omitempty), so object.get's default only kicks in when the pipeline
# author didn't set a step `name:` — never compares against "".
_fn_name(fn) := object.get(fn, "name", fn.ref)

_is_authorized(fn) if _in_allowlist(fn.ref)

_is_authorized(fn) if _is_same_group(fn.ref)

_in_allowlist(ref) if {
	pattern := input.config.functionAuthorizedSources.trustedFunctions[_]
	glob.match(_normalize_var(pattern), null, _normalize_var(ref))
	not _pattern_redefined(pattern)
}

# _pattern_redefined guards trustedFunctions patterns that reference
# GitLab predefined CI/CD variables (e.g. $CI_PROJECT_PATH) — those
# variables have the lowest precedence, so a pipeline that redefines one
# in its own `variables:` block could make an otherwise-safe pattern
# match text that resolves to an attacker-controlled source at runtime.
# Every `/`-delimited segment of the pattern that starts with $CI is
# checked independently; if ANY of those variables is redefined, the
# pattern cannot authorize the ref (ISSUE-415 hardening).
_pattern_redefined(pattern) if {
	segment := split(_normalize_var(pattern), "/")[_]
	startswith(segment, "$CI")
	_pipeline_defines_var(_segment_var_name(segment))
}

# _segment_var_name extracts the bare variable name (no $) from a
# normalized "$CI_..." path segment, e.g. "$CI_PROJECT_PATH" ->
# "CI_PROJECT_PATH".
_segment_var_name(segment) := name if {
	m := regex.find_all_string_submatch_n(`^\$([A-Za-z_][A-Za-z0-9_]*)`, segment, 1)
	count(m) > 0
	name := m[0][1]
}

# _is_same_group trusts a function ref hosted on the scanned GitLab
# instance whose path starts with the project's own root namespace — see
# _matches_own_namespace.
_is_same_group(ref) if {
	object.get(input.config.functionAuthorizedSources, "trustSameGroupFunctions", true) == true
	_matches_own_namespace(ref)
}

# _matches_own_namespace mirrors component_authorized_sources.rego's
# _is_same_group — the ref must be hosted on the scanned GitLab instance
# AND its path (after the host) must start with the project's root
# namespace. Checking the path alone, with an unvalidated host segment
# dropped, let an attacker-controlled registry claim any path it wanted
# (ISSUE-415 hardening).
_matches_own_namespace(ref) if {
	instanceHost := object.get(input.config.functionAuthorizedSources, "instanceHost", "")
	instanceHost != ""
	startswith(ref, sprintf("%s/", [instanceHost]))
	root := _root_namespace(object.get(input.pipeline, "projectPath", ""))
	root != ""
	path := _path_after_host(ref)
	startswith(path, sprintf("%s/", [root]))
}

# _pipeline_defines_var reports whether the pipeline redefines a GitLab
# predefined CI/CD variable itself — checked both against the merged
# view (globalVariables) and the project-authored-only view
# (localGlobalVariables), since either could shadow the predefined value
# at runtime. Used by _pattern_redefined above.
_pipeline_defines_var(name) if object.get(input.pipeline, "globalVariables", {})[name]

_pipeline_defines_var(name) if object.get(input.pipeline, "localGlobalVariables", {})[name]

_root_namespace(projectPath) := parts[0] if {
	projectPath != ""
	parts := split(projectPath, "/")
	count(parts) > 0
	parts[0] != ""
} else := ""

# _path_after_host drops the first "/"-delimited segment of ref (the
# registry host, validated separately by the namespace branch above).
_path_after_host(ref) := path if {
	idx := indexof(ref, "/")
	idx >= 0
	path := substring(ref, idx+1, -1)
} else := ""

# _normalize_var rewrites `${VAR}` references to `$VAR` so trustedFunctions
# patterns and the actual ref compare equal regardless of notation.
# Mirrors image_authorized_sources.rego's helper of the same name.
_normalize_var(s) := regex.replace(s, `\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`, `$$$1`)
