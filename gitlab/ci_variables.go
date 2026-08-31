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

// gitLabReservedPrefixes are the variable-name prefixes GitLab reserves for
// its own predefined variables. A name under one of them is a CI variable by
// definition, so it can be read from the environment without an allowlist.
var gitLabReservedPrefixes = []string{"CI_", "GITLAB_"}

// jobScopedPredefined are predefined variables whose value describes the JOB
// reading them rather than the pipeline.
//
// The reserved prefixes above are a sound allowlist for pipeline-wide facts
// - `$CI_REGISTRY_IMAGE` is the same for every job. These are not. Plumber
// reads them from its OWN job and would substitute its own job name, id,
// stage or image into another job's reference, producing a resolved-looking
// value that is confidently wrong. Left out, they stay placeholders and the
// image rules abstain on that job, which is the honest answer.
var jobScopedPredefined = map[string]bool{
	"CI_JOB_ID":             true,
	"CI_JOB_NAME":           true,
	"CI_JOB_NAME_SLUG":      true,
	"CI_JOB_STAGE":          true,
	"CI_JOB_IMAGE":          true,
	"CI_JOB_URL":            true,
	"CI_JOB_TOKEN":          true,
	"CI_JOB_STARTED_AT":     true,
	"CI_JOB_MANUAL":         true,
	"CI_ENVIRONMENT_NAME":   true,
	"CI_ENVIRONMENT_SLUG":   true,
	"CI_ENVIRONMENT_URL":    true,
	"CI_ENVIRONMENT_ACTION": true,
	"CI_ENVIRONMENT_TIER":   true,
	"CI_NODE_INDEX":         true,
	"CI_NODE_TOTAL":         true,
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
//   - Every variable under a GitLab-reserved prefix. These are predefined
//     and their names are not user-chosen, so reading them needs no
//     permission from anyone. `$CI_REGISTRY_IMAGE` is by far the most common
//     placeholder in a real image reference.
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
		if allowed[name] || hasReservedPrefix(name) {
			out[name] = value
		}
	}
	return out
}

func hasReservedPrefix(name string) bool {
	if jobScopedPredefined[name] {
		return false
	}
	for _, prefix := range gitLabReservedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
