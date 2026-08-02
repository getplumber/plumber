# component-authorized-sources (ISSUE-414) — flag `include: component:`
# references pulled from a source not listed in
# componentMustComeFromAuthorizedSources.trustedUrls. Components run
# arbitrary code with the job's full context (variables, secrets,
# CI_JOB_TOKEN) — the GitLab analogue of a GitHub Actions "pwn request".
#
# GitLab resolves $CI_SERVER_FQDN / $CI_PROJECT_PATH server-side before
# Plumber ever fetches the merged CI config, so inc.source already
# carries the literal resolved host+path. The Go side resolves the same
# variables in trustedUrls via os.Getenv (gitlab.ReplaceVariableFromEnv,
# control/task.go) before this policy ever runs — the notation
# normalization below is a defensive fallback for whatever `${VAR}` /
# `$VAR` text survives either side.
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
		"code":          "ISSUE-414",
		"severity":      "critical",
		"message":       sprintf("component %q comes from untrusted source: %s", [object.get(inc, "componentName", inc.source), inc.source]),
		"job":           inc.source,
		"link":          inc.source,
		"status":        "unauthorized",
		"file":          object.get(inc, "originFile", ""),
		"line":          object.get(inc, "originLine", 0),
		"componentName": object.get(inc, "componentName", ""),
	}
}

_is_authorized(source) if {
	pattern := input.config.componentAuthorizedSources.trustedUrls[_]
	glob.match(_normalize_var(pattern), null, _normalize_var(source))
}

# _normalize_var rewrites `${VAR}` references to `$VAR` so trustedUrls
# patterns and the actual source compare equal regardless of notation.
# Mirrors image_authorized_sources.rego's helper of the same name.
_normalize_var(s) := regex.replace(s, `\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`, `$$$1`)
