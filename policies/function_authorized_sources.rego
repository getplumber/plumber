# function-authorized-sources (ISSUE-415) — flag `run:` step function
# references (docs.gitlab.com/ci/functions) pulled from a source not
# listed in functionMustComeFromAuthorizedSources.trustedUrls. Functions
# run arbitrary code with the job's full context, the same supply-chain
# exposure as CI/CD components.
#
# Unlike `include:` (component-authorized-sources, ISSUE-414), GitLab
# does not resolve $CI_TEMPLATE_REGISTRY_HOST / $CI_PROJECT_PATH
# server-side for `run:`/`func:` — it's a runtime field, not something
# GitLab must resolve to merge the config. So neither side is
# Go-resolved here: trustedUrls patterns and fn.ref are compared as
# literal text, with only `${VAR}`/`$VAR` notation normalized — this
# matches when the pipeline author wrote the reference using the same
# variable text the default trustedUrls uses (the common idiom), or a
# literal value the user added themselves.
#
# References using the deprecated `step:` keyword (renamed to `func:`)
# or the deprecated git-repository loading format are reported as
# "deprecated" independently of trust — GitLab plans to remove support
# for both. "local" (relative/absolute filesystem path) references are
# same-repo and out of scope entirely, mirroring how `include: local` is
# out of scope for component-authorized-sources.
package function_authorized_sources

import rego.v1

deny contains finding if {
	input.config.functionAuthorizedSources
	some i, j
	job := input.pipeline.jobs[i]
	fn := job.functions[j]
	fn.kind != "local"
	fn.deprecated == true
	finding := {
		"code":     "ISSUE-415",
		"severity": "medium",
		"message":  sprintf("job %q uses function %q via a deprecated reference form: %s", [job.name, _fn_name(fn), fn.ref]),
		"job":      job.name,
		"link":     fn.ref,
		"status":   "deprecated",
	}
}

deny contains finding if {
	input.config.functionAuthorizedSources
	some i, j
	job := input.pipeline.jobs[i]
	fn := job.functions[j]
	fn.kind != "local"
	not fn.deprecated
	not _is_authorized(fn.ref)
	finding := {
		"code":     "ISSUE-415",
		"severity": "critical",
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

_is_authorized(ref) if {
	pattern := input.config.functionAuthorizedSources.trustedUrls[_]
	glob.match(_normalize_var(pattern), null, _normalize_var(ref))
}

# _normalize_var rewrites `${VAR}` references to `$VAR` so trustedUrls
# patterns and the actual ref compare equal regardless of notation.
# Mirrors image_authorized_sources.rego's helper of the same name.
_normalize_var(s) := regex.replace(s, `\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`, `$$$1`)
