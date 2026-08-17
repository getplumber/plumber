# component-authorized-sources (ISSUE-414) — flag `include: component:`
# references pulled from a source that is not trusted by
# componentMustComeFromAuthorizedSources. Components run arbitrary code
# with the job's full context (variables, secrets, CI_JOB_TOKEN) — the
# GitLab analogue of a GitHub Actions "pwn request".
#
# GitLab resolves $VAR server-side before
# Plumber ever fetches the merged CI config, so inc.source already
# carries the literal resolved host+path — trust here can safely compare
# against the real host.
#
# A source is trusted when it matches an explicit trustedComponents
# allowlist pattern, or (trustSameGroupComponents, default true) it lives
# under the scanned project's root namespace on the same instance, or
# (trustSameInstanceComponents, default false on gitlab.com / true on a
# self-hosted instance — see buildEngineConfig) it's hosted on the
# scanned GitLab instance at all, regardless of namespace — a self-hosted
# instance is already inside the org's trust boundary the way gitlab.com,
# a multi-tenant SaaS host, is not. Modeled on
# action_authorized_sources.rego's trustSameOrgActions.
package component_authorized_sources

import rego.v1

deny contains finding if {
	input.config.componentAuthorizedSources
	some i
	inc := input.pipeline.includes[i]
	inc.kind == "component"
	inc.source != ""
	not _is_authorized(inc.source)
	finding := {
		"code":     "ISSUE-414",
		"severity": "high",
		"message":  sprintf("component %q comes from untrusted source: %s", [object.get(inc, "componentName", inc.source), inc.source]),
		# No "job": an include is not a CI job, and the job field is a hashed
		# identity segment (finding/identity). componentPath names what this
		# finding is about and is the subject key the identity recipe selects,
		# matching the other component controls (ISSUE-408/409).
		"componentPath":         inc.source,
		"link":                  inc.source,
		"status":                "unauthorized",
		"file":                  object.get(inc, "originFile", ""),
		"line":                  object.get(inc, "originLine", 0),
		"componentName":         object.get(inc, "componentName", ""),
		"gitlabIncludeLocation": inc.source,
	}
}

_is_authorized(source) if _in_allowlist(source)

_is_authorized(source) if _is_same_group(source)

_is_authorized(source) if _is_same_instance(source)

_in_allowlist(source) if {
	pattern := input.config.componentAuthorizedSources.trustedComponents[_]
	glob.match(_normalize_var(pattern), null, _normalize_var(source))
}

_is_same_group(source) if {
	object.get(input.config.componentAuthorizedSources, "trustSameGroupComponents", true) == true
	instanceHost := object.get(input.config.componentAuthorizedSources, "instanceHost", "")
	instanceHost != ""
	startswith(source, sprintf("%s/", [instanceHost]))
	root := _root_namespace(object.get(input.pipeline, "projectPath", ""))
	root != ""
	path := _path_after_host(source)
	startswith(path, sprintf("%s/", [root]))
}

_is_same_instance(source) if {
	object.get(input.config.componentAuthorizedSources, "trustSameInstanceComponents", false) == true
	instanceHost := object.get(input.config.componentAuthorizedSources, "instanceHost", "")
	instanceHost != ""
	startswith(source, sprintf("%s/", [instanceHost]))
}

_root_namespace(projectPath) := parts[0] if {
	projectPath != ""
	parts := split(projectPath, "/")
	count(parts) > 0
	parts[0] != ""
} else := ""

# _path_after_host drops the first "/"-delimited segment of source
# (the registry/instance host).
_path_after_host(source) := path if {
	idx := indexof(source, "/")
	idx >= 0
	path := substring(source, idx+1, -1)
} else := ""

# _normalize_var rewrites `${VAR}` references to `$VAR` so trustedComponents
# patterns and the actual source compare equal regardless of notation.
# Mirrors image_authorized_sources.rego's helper of the same name.
_normalize_var(s) := regex.replace(s, `\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`, `$$$1`)
