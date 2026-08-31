package gitlab

import (
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// DetectMergeRequestIID checks if we are running inside a GitLab CI
// merge request pipeline and returns the merge request IID.
// Returns 0 if not in a CI merge request context.
//
// GitLab CI sets CI_MERGE_REQUEST_IID only for merge request pipelines
// (pipelines triggered by `rules: - if: $CI_MERGE_REQUEST_IID` or
// `only: merge_requests`).
func DetectMergeRequestIID() int {
	l := logrus.WithField("action", "DetectMergeRequestIID")

	// Must be running in CI
	if !IsRunningInCI() {
		l.Debug("Not running in CI")
		return 0
	}

	// Must have a merge request IID
	mrIIDStr := os.Getenv("CI_MERGE_REQUEST_IID")
	if mrIIDStr == "" {
		l.Debug("CI_MERGE_REQUEST_IID not set, not a merge request pipeline")
		return 0
	}

	mrIID, err := strconv.Atoi(strings.TrimSpace(mrIIDStr))
	if err != nil {
		l.WithError(err).WithField("CI_MERGE_REQUEST_IID", mrIIDStr).Warn("Invalid CI_MERGE_REQUEST_IID value")
		return 0
	}

	l.WithField("mergeRequestIID", mrIID).Info("Detected merge request CI environment")
	return mrIID
}

// IsRunningInCI checks if the code is running inside a GitLab CI environment
// by checking if the CI environment variable is set to "true"
func IsRunningInCI() bool {
	ciEnv := os.Getenv("CI")
	return strings.ToLower(ciEnv) == "true"
}

// IsOnDefaultBranchCI checks if the current CI pipeline is running on the
// project's default branch by comparing CI_COMMIT_BRANCH to CI_DEFAULT_BRANCH.
// Only call this when IsRunningInCI() returns true.
func IsOnDefaultBranchCI() bool {
	commitBranch := os.Getenv("CI_COMMIT_BRANCH")
	defaultBranch := os.Getenv("CI_DEFAULT_BRANCH")

	if commitBranch == "" || defaultBranch == "" {
		return false
	}

	return commitBranch == defaultBranch
}

// CheckoutIsAtRef reports whether the working tree this job was given is the
// ref being analyzed.
//
// It exists so the analyzed project's own CI file can be read from disk
// instead of fetched over the API. That substitution is only sound when the
// tree holds the ref in question: reading one branch's file while reporting
// on another's is a wrong answer no downstream check would catch, because
// the file parses perfectly either way.
//
// An empty branch means "the run did not name one", which is the analyzed
// ref by definition. Otherwise it has to match the ref the job checked out.
func CheckoutIsAtRef(branch string) bool {
	if !IsRunningInCI() {
		return false
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return true
	}
	checkedOut := strings.TrimSpace(os.Getenv("CI_COMMIT_REF_NAME"))
	return checkedOut != "" && branch == checkedOut
}

// CIAnalyzedRef returns the ref this job checked out, or "" outside CI.
//
// A run that names no branch analyses whatever it is standing in, which in a
// CI job is $CI_COMMIT_REF_NAME - not the project's default branch. Without
// this the two come apart on every feature-branch pipeline: the run reads
// the branch's own CI file off disk and then labels the report with the
// default branch, so every source link points at a ref the finding is not
// on. The GitLab component always passes `branch:`, which hides it; the CLI
// should not need the template to be right.
func CIAnalyzedRef() string {
	if !IsRunningInCI() {
		return ""
	}
	return strings.TrimSpace(os.Getenv("CI_COMMIT_REF_NAME"))
}

// CIConfigPathIsExternal reports whether a ci_config_path points somewhere
// other than this repository.
//
// GitLab accepts three forms: a repo-relative path, `file.yml@group/project`
// (optionally `:ref`), and a bare URL. Only the first can be read from a
// checkout or from this project's file API, so the other two are a fetch
// that is certain to 404 - and $CI_CONFIG_PATH exports whichever form the
// project configured, verbatim.
//
// internal/cidigest already refuses the same shapes when computing a digest
// (ErrExternalRootConfig); this is the collection-side half of the same
// rule.
func CIConfigPathIsExternal(path string) bool {
	path = strings.TrimSpace(path)
	return strings.Contains(path, "@") ||
		strings.HasPrefix(path, "http://") ||
		strings.HasPrefix(path, "https://")
}
