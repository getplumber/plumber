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
# hosted on the scanned GitLab instance — its container registry host
# (input.pipeline.registryHost, the supported OCI form) or its web host
# (instanceHost, the deprecated git form) — and its path starts with the
# project's own root namespace (top-level group). The registry host is the
# one the GitLab API reports for the scanned project
# (container_registry_image_prefix), never a CI/CD variable: a variable such
# as CI_TEMPLATE_REGISTRY_HOST points at registry.gitlab.com on a
# self-managed instance, and any pipeline can redefine it to its own
# registry (ISSUE-415 hardening). A same-namespace check that only looks at
# the path after an unvalidated host segment would trust any registry that
# happens to name a top-level path after the victim's namespace (ISSUE-415
# hardening).
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
# or in the analyzed job's own `variables:` block (localVariables), since a
# job-level definition overrides the predefined value for that job just the
# same (ISSUE-415 hardening).
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
	not _is_authorized(fn, job)
	finding := {
		"code":     "ISSUE-415",
		"severity": "high",
		"message":  sprintf("Job `%s` uses the function `%s` from an untrusted source.", [job.name, fn.ref]),
		"job":      job.name,
		# step discriminates two `run:` steps in one job that reference the
		# same function (same code/file/job/link would otherwise collide to
		# one fingerprint). Empty when the author set no step `name:`, in
		# which case the identity recipe skips the segment (finding/identity).
		"step":     object.get(fn, "name", ""),
		"file":     object.get(job, "originFile", ""),
		"line":     object.get(job, "originLine", 0),
		"link":     fn.ref,
		"status":   "unauthorized",
	}
}

_is_authorized(fn, job) if _in_allowlist(fn.ref, job)

_is_authorized(fn, _) if _is_same_group(fn.ref)

_in_allowlist(ref, job) if {
	pattern := input.config.functionAuthorizedSources.trustedFunctions[_]
	glob.match(_normalize_var(pattern), null, _normalize_var(ref))
	not _pattern_redefined(pattern, job)
}

# _pattern_redefined guards trustedFunctions patterns that reference
# GitLab predefined CI/CD variables (e.g. $CI_PROJECT_PATH) — those
# variables have the lowest precedence, so a pipeline that redefines one
# in its own `variables:` block (global or the analyzed job's) could make
# an otherwise-safe pattern match text that resolves to an
# attacker-controlled source at runtime. Every `/`-delimited segment of the
# pattern that starts with $CI is checked independently; if ANY of those
# variables is redefined, the pattern cannot authorize the ref (ISSUE-415
# hardening).
_pattern_redefined(pattern, job) if {
	segment := split(_normalize_var(pattern), "/")[_]
	startswith(segment, "$CI")
	_var_redefined(_segment_var_name(segment), job)
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
	_on_own_host(ref)
	root := _root_namespace(object.get(input.pipeline, "projectPath", ""))
	root != ""
	path := _path_after_host(ref)
	startswith(path, sprintf("%s/", [root]))
}

# _on_own_host reports whether ref starts with one of the scanned
# instance's hosts: its container registry host (input.pipeline.registryHost,
# reported by the GitLab API), where GitLab Function OCI references live, or
# its web host (instanceHost), used by the deprecated git reference form.
_on_own_host(ref) if {
	host := object.get(input.pipeline, "registryHost", "")
	host != ""
	startswith(ref, sprintf("%s/", [host]))
}

_on_own_host(ref) if {
	host := object.get(input.config.functionAuthorizedSources, "instanceHost", "")
	host != ""
	startswith(ref, sprintf("%s/", [host]))
}

# _var_redefined reports whether a GitLab predefined CI/CD variable is
# redefined in a scope the function ref is resolved in: the pipeline's
# global `variables:` — both the merged view (globalVariables) and the
# project-authored-only view (localGlobalVariables) — or the analyzed
# job's own `variables:` block, which takes precedence over both. The job
# check reads the project-authored view (localVariables) rather than the
# merged one, so a value a trusted upstream template legitimately sets does
# not reject the pattern. Used by _pattern_redefined above.
_var_redefined(name, _) if object.get(input.pipeline, "globalVariables", {})[name]

_var_redefined(name, _) if object.get(input.pipeline, "localGlobalVariables", {})[name]

_var_redefined(name, job) if object.get(job, "localVariables", {})[name]

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
