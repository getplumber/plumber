package gitlab

import (
	"os"
	"strings"
)

// Image references in a CI configuration are routinely written with
// placeholders - `$CI_REGISTRY_IMAGE:$TAG`, `$SECURE_ANALYZERS_PREFIX/semgrep:5` -
// and a control cannot judge a registry or a tag it has not resolved. The
// CLI has resolved them by listing every CI/CD variable's VALUE over three
// GraphQL queries, which is the single most privileged thing it does.
//
// Inside a CI job that is unnecessary, and worse than unnecessary. GitLab
// exports into the job's own process environment exactly the variables that
// job is entitled to, already reduced across instance, group and project
// scope, already filtered by environment scope and by whether the ref is
// protected. That is not an approximation of what the API returns - it is
// the value the job will actually use, which the API listing cannot
// reproduce without re-implementing GitLab's own precedence rules.
//
// The platform never serves variable values, by design, and does not need
// to: it serves the NAMES, and the job supplies the values for them. The
// two halves are individually harmless and together sufficient.

// pipelineWidePredefined are the predefined variables an image reference is
// built from: registry hosts and image prefixes, the server host, the
// project coordinates, and the commit and pipeline coordinates image tags
// are routinely built from (`$CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG`). Their
// value is the same for every job of the pipeline, so the value this job
// reads is the value any job would use.
//
// The list is explicit rather than a prefix rule. A prefix admitted every
// predefined name GitLab exports, and most of them are not pipeline facts at
// all: `CI_JOB_*` and `CI_ENVIRONMENT_*` describe the job reading them, so
// substituting them into another job's reference produced a resolved-looking
// value that was confidently wrong, and names such as `CI_REPOSITORY_URL` or
// the `*_PASSWORD` ones are never a component of an image reference to begin
// with. A name absent from this list stays a placeholder, the reference is
// marked unresolved, and the image rules abstain on that job, which is the
// honest answer.
var pipelineWidePredefined = map[string]bool{
	"CI_REGISTRY":                                   true,
	"CI_REGISTRY_IMAGE":                             true,
	"CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX":        true,
	"CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX": true,
	"CI_TEMPLATE_REGISTRY_HOST":                     true,
	"CI_SERVER_HOST":                                true,
	"CI_SERVER_FQDN":                                true,
	"CI_SERVER_URL":                                 true,
	"CI_PROJECT_PATH":                               true,
	"CI_PROJECT_NAME":                               true,
	"CI_PROJECT_NAMESPACE":                          true,
	"CI_PROJECT_ROOT_NAMESPACE":                     true,
	"CI_DEFAULT_BRANCH":                             true,
	"CI_COMMIT_SHA":                                 true,
	"CI_COMMIT_SHORT_SHA":                           true,
	"CI_COMMIT_REF_NAME":                            true,
	"CI_COMMIT_REF_SLUG":                            true,
	"CI_COMMIT_BRANCH":                              true,
	"CI_COMMIT_TAG":                                 true,
	"CI_PIPELINE_ID":                                true,
	"CI_PIPELINE_IID":                               true,
}

// ciRefIsProtected reports whether the ref this job is running on is a
// protected branch or tag, from GitLab's own $CI_COMMIT_REF_PROTECTED.
//
// It decides whether a variable the snapshot marks PROTECTED can be read
// from this environment at all. On an unprotected ref GitLab withholds it,
// so any value found under that name came from somewhere else - most
// plausibly an ENV line in Plumber's own container image, where names like
// VERSION or LANG are common. Substituting that would invert the
// entitlement rule the whole approach rests on: the job would be judged
// against a value it is specifically not allowed to see.
func ciRefIsProtected() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("CI_COMMIT_REF_PROTECTED")), "true")
}

// JobEnvironmentVariables returns the values this job's environment holds
// for the CI/CD variables it is allowed to expand, keyed by name.
//
// Two sources, and the split is deliberate:
//
//   - The pipeline-wide predefined variables (pipelineWidePredefined). These
//     are the predefined names an image reference is built from, and their
//     names are not user-chosen, so reading them needs no permission from
//     anyone. `$CI_REGISTRY_IMAGE` is by far the most common placeholder in
//     a real image reference.
//   - Every name in declared, which is the variable metadata the platform
//     serves. Restricting the user-defined half to names the platform
//     vouched for is what keeps this from being "read the process
//     environment": an unrelated `$HOME` or `$PATH` in an image reference is
//     not a CI/CD variable and must not be substituted as though GitLab
//     would have substituted it.
//
// An empty value is skipped rather than recorded. GitLab exports a defined
// variable with an empty value, and substituting "" would silently turn
// `$REGISTRY/app` into `/app` - a resolved-looking reference that is not the
// one the job uses. Leaving the placeholder in place is what lets the caller
// see it did not resolve.
func JobEnvironmentVariables(declared []string) map[string]string {
	allowed := make(map[string]bool, len(declared))
	for _, name := range declared {
		if name = strings.TrimSpace(name); name != "" {
			allowed[name] = true
		}
	}

	out := map[string]string{}
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" {
			continue
		}
		if allowed[name] || pipelineWidePredefined[name] {
			out[name] = value
		}
	}
	return out
}
