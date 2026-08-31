package gitlab

import (
	"os"
	"strconv"
	"strings"
)

// The first thing an analysis does is look the project up over the API: two
// requests, for a numeric id, a path, a default branch, a CI config path and
// a head commit. Inside a CI job every one of those is already in the
// environment, put there by GitLab itself, and the API answers are in one
// case actively worse - see LatestHeadCommitSha below.
//
// This matters beyond the request count. `plumber analyze --platform` is
// meant to run with no personal access token at all, and that project
// lookup is the call that fails first: a 401 there is not a network error,
// so it aborts the whole run before a single control is evaluated.

// ciProjectPathDefault is the CI config path GitLab uses when a project has
// not configured one.
const ciProjectPathDefault = ".gitlab-ci.yml"

// ProjectFromCIEnvironment builds the analyzed project's identity from the
// predefined variables GitLab defines in every job, making no API call.
//
// analyzed is the project this run is REPORTING on, and the environment is
// only accepted when it describes that same project. The two are not always
// the same: `plumber analyze --project other/group/repo` is supported from
// inside a CI job, and there the environment describes the runner's project
// instead. Taking it anyway would collect branch protections, variables and
// a CI configuration from the runner's project and file them under the
// other one's name - a whole report about the wrong repository, with no
// field left inconsistent for anything downstream to catch.
//
// The second return is false whenever the environment cannot answer -
// outside CI, in a job missing the variables this needs, or for a different
// project - and the caller falls back to the API. It is never a partial
// answer: an identity assembled half from the environment and half from
// defaults would be wrong in a way nothing downstream could detect.
//
// ciConfigPath is what the platform's snapshot reported, and it wins over
// $CI_CONFIG_PATH when set. The platform anchored its own config digest
// against that value, so digesting against anything else can never match.
//
// Only call this in platform mode. GroupIdOnPlatform below is left zero
// because no predefined variable carries a namespace KIND, and the one
// reader of the ProjectInfo.IsGroup it feeds is a code path platform mode
// never reaches.
func ProjectFromCIEnvironment(analyzed, ciConfigPath string) (*Project, bool) {
	if !IsRunningInCI() {
		return nil, false
	}

	path := strings.TrimSpace(os.Getenv("CI_PROJECT_PATH"))
	sha := strings.TrimSpace(os.Getenv("CI_COMMIT_SHA"))
	id, idErr := strconv.Atoi(strings.TrimSpace(os.Getenv("CI_PROJECT_ID")))
	if path == "" || sha == "" || idErr != nil {
		return nil, false
	}
	if analyzed = strings.TrimSpace(analyzed); analyzed != "" && analyzed != path {
		return nil, false
	}

	project := &Project{
		IdOnPlatform:  id,
		Name:          strings.TrimSpace(os.Getenv("CI_PROJECT_NAME")),
		Path:          path,
		DefaultBranch: strings.TrimSpace(os.Getenv("CI_DEFAULT_BRANCH")),
		CiConfPath:    resolveCIConfigPath(ciConfigPath),

		// LatestHeadCommitSha is the commit this analysis is about, and
		// $CI_COMMIT_SHA is exactly that. The API answers a different
		// question - the head of the DEFAULT branch - which is why
		// RunAnalysis then spends a second request correcting it whenever
		// --branch names something else. Taking it from the environment is
		// both one request cheaper and right on the first attempt.
		LatestHeadCommitSha: sha,

		// GitLab does not START pipelines for archived projects, so a
		// running job is good evidence the project was not archived when
		// this pipeline began. It is not proof for the whole run - archiving
		// mid-pipeline does not cancel jobs already in flight - and there is
		// no predefined variable and no snapshot lane for it either.
		//
		// The exposure is small enough to accept: the only behavioural read
		// of Archived short-circuits the merged-config fetch, and platform
		// mode takes the merged config from the snapshot regardless. A
		// project archived mid-run is analysed as it was when the pipeline
		// started, which is the commit being reported on anyway.
		Archived: false,

		// GroupIdOnPlatform feeds ProjectInfo.IsGroup, whose only reader
		// gates the instance-wide CI/CD variable listing - an admin-only
		// query platform mode does not make, because image references are
		// expanded from the job's own environment instead. No predefined
		// variable carries a namespace KIND, so any value here would be
		// invented; zero at least matches the zero value of a Project that
		// was never fetched. See this function's own doc: platform mode
		// only.
		GroupIdOnPlatform: 0,
	}
	return project, true
}

// resolveCIConfigPath picks the CI config path, preferring what the platform
// reported over the job's own $CI_CONFIG_PATH.
//
// Both describe the same setting, and either would do for reading the file.
// The platform's copy wins because it is also what the platform's resolution
// anchor was digested against, and the digest can only ever match if both
// sides hashed the same root.
func resolveCIConfigPath(fromSnapshot string) string {
	if p := strings.TrimSpace(fromSnapshot); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("CI_CONFIG_PATH")); p != "" {
		return p
	}
	return ciProjectPathDefault
}
