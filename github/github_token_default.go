package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// defaultTokenRunsPerPage is the page size requested from
// /repos/{owner}/{repo}/actions/runs and /repos/{owner}/{repo}/releases
// when looking for the repository's real default GITHUB_TOKEN write:
// "the latest 20" per the collection contract, never paginated further
// (an answer worth reading is expected near the top, and this lane
// must stay cheap on a busy repository).
const defaultTokenRunsPerPage = 20

// maxJobLogBytes bounds how much of a job's log this reads: the
// "GITHUB_TOKEN Permissions" block GitHub Actions prints sits at the
// very top of the log, so 64 KB is ample while keeping a large log
// out of memory.
const maxJobLogBytes = 64 * 1024

// defaultTokenBotLogin is the identity a release the repository's own
// default token made is attributed to: a release this login authored
// is proof the token that published it could write, with no
// permissions block in sight.
const defaultTokenBotLogin = "github-actions[bot]"

// defaultTokenExcludedActor is an identity whose own runs are never
// read as evidence of the repository default: Dependabot runs with
// its own distinct token, scoped by the repository's Dependabot
// settings rather than the workflow's own permissions, so a run it
// triggered (as actor or as the identity GitHub re-runs it under)
// tells this lane nothing about the default any other run gets.
const defaultTokenExcludedActor = "dependabot[bot]"

// defaultTokenEligibleEvents are the run events this lane ever reads:
// events a run of the repository's own default branch, under the
// repository's own authority, actually fires on. A fork pull_request
// run, or any other event, is never read: its job may run with a
// different, narrower token than the one this lane is trying to
// characterize.
var defaultTokenEligibleEvents = map[string]bool{
	"push":              true,
	"schedule":          true,
	"workflow_dispatch": true,
}

// jobLogsAPIClient issues the initial GET to the API's job-logs
// endpoint without following its redirect automatically: the 302 it
// answers points off the API host, at an external log store this
// process's GitHub credentials must never reach bundled in the same
// request.
var jobLogsAPIClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// jobLogsStoreClient fetches the log store the API redirected to: a
// plain client, bounded to 15 seconds so a slow or unresponsive log
// store never hangs this lane, and never given an Authorization
// header (built fresh for every call, see fetchJobLogHead).
var jobLogsStoreClient = &http.Client{Timeout: 15 * time.Second}

// remoteRunsResponse is the slim subset of the workflow-runs listing
// endpoint response this reads.
type remoteRunsResponse struct {
	WorkflowRuns []remoteRun `json:"workflow_runs"`
}

// remoteRun is one entry of the workflow-runs listing, narrowed to
// what decides whether it is safe evidence of the repository's own
// default token: its id (to look up its first job), the repo-relative
// path of the workflow file that ran it (exactly as the runs and
// workflow-states endpoints both return it, matching the collector's
// Job.OriginFile once normalized by ir.WorkflowStateKey), the event
// that triggered it, the branch it ran on, the repository the run
// actually checked out (HeadRepository when set, the base Repository
// otherwise: a same-repository push run answers "repository" and
// leaves "head_repository" null or equal to it; a fork pull_request
// run answers a "head_repository" that differs), and who triggered it.
type remoteRun struct {
	ID              int64          `json:"id"`
	Path            string         `json:"path"`
	Event           string         `json:"event"`
	HeadBranch      string         `json:"head_branch"`
	Repository      *remoteRepoRef `json:"repository"`
	HeadRepository  *remoteRepoRef `json:"head_repository"`
	Actor           *remoteActor   `json:"actor"`
	TriggeringActor *remoteActor   `json:"triggering_actor"`
}

// remoteRepoRef is a repository reference, narrowed to the full name
// ("owner/repo") this reads.
type remoteRepoRef struct {
	FullName string `json:"full_name"`
}

// remoteJobsResponse is the slim subset of the run-jobs listing
// endpoint response this reads.
type remoteJobsResponse struct {
	Jobs []remoteJob `json:"jobs"`
}

// remoteJob is one entry of the run-jobs listing: its id, used to
// fetch its log.
type remoteJob struct {
	ID int64 `json:"id"`
}

// remoteRelease is the slim subset of the releases listing endpoint
// response this reads: who authored it.
type remoteRelease struct {
	Author *remoteActor `json:"author"`
}

// remoteActor is a GitHub user/bot reference, narrowed to the login
// this reads.
type remoteActor struct {
	Login string `json:"login"`
}

// logTimestampRe strips the ISO-8601 timestamp GitHub Actions prefixes
// to every line of a raw job log ("2026-10-15T12:34:56.1234567Z ")
// before any of the block-shape regexes below see the line.
var logTimestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T[\d:.]+Z `)

// tokenPermissionsHeaderRe matches the line that opens the block
// GitHub Actions prints at the top of a job's log when it issues the
// job's GITHUB_TOKEN, after logTimestampRe has already stripped the
// line's timestamp: "GITHUB_TOKEN Permissions" on its own, or wrapped
// in the log's own group marker ("##[group]GITHUB_TOKEN Permissions").
var tokenPermissionsHeaderRe = regexp.MustCompile(`^\s*(##\[group\])?\s*GITHUB_TOKEN Permissions\s*$`)

// tokenPermissionsEndGroupRe matches the line that closes the group
// marker the header line opened ("##[endgroup]"), one of the three
// ways the block ends (the others: a blank line, or a line that is
// not a scope line at all).
var tokenPermissionsEndGroupRe = regexp.MustCompile(`^\s*##\[endgroup\]\s*$`)

// tokenPermissionsScopeRe matches one scope line of that block: a
// scope name (e.g. "Contents"), a colon, and its access level ("read"
// or "write").
var tokenPermissionsScopeRe = regexp.MustCompile(`^\s*(\w[\w-]*): (read|write)\s*$`)

// FetchGitHubDefaultTokenWrite resolves whether the repository's real
// default GITHUB_TOKEN (the one a job with no permissions block at
// all, its own or its workflow's, actually runs with) can write, and
// how that was decided.
//
// eligible reports whether a workflow (by its repo-relative path, the
// form the runs listing's own "path" field and the workflow-states
// listing share) is one where EVERY job declares no permissions of
// its own and calls no reusable workflow: the only workflows whose
// run can safely stand in for the repository default, since GitHub
// answers a run's first job (per_page=1) whichever job that happens
// to be. defaultBranch is the repository's own default branch
// (pipeline.DefaultBranch); empty means no run is ever read (nothing
// to compare a run's own branch against). declaresContentsWrite is
// true when some job elsewhere in the pipeline already declares a
// contents write or write-all: in that case a bot-authored release
// proves only that SOME token in this repository can write, not that
// the undeclared default one can, so the effect route is skipped
// outright. The lane tries, in order:
//
//  1. the log route: the latest defaultTokenRunsPerPage completed runs,
//     kept to the ones that ran on a push, a schedule or a manual
//     dispatch of the repository's own default branch, in the
//     repository itself (never a fork), triggered by neither actor nor
//     triggering actor as defaultTokenExcludedActor, and whose
//     workflow is eligible; for the first such run with a fetchable
//     first job, that job's own log is read for the "GITHUB_TOKEN
//     Permissions" block GitHub Actions prints at the top. A job
//     fetch failure moves on to the next eligible run; a log fetch or
//     parse failure (or an absent block) abandons the log route
//     entirely rather than trying another run, and falls through to
//     the effect route below.
//  2. the effect route (skipped when declaresContentsWrite): a
//     release authored by github-actions[bot], a write the bot
//     demonstrably made, proof enough that its token could write,
//     with no permissions block in sight either.
//
// Neither route ever returns an error: every failure (network, auth,
// an unparsable response) degrades to the next route, and finally to
// write="unknown", source="unknown" when nothing settled it. Nothing
// here ever logs the job's log body or an Authorization header value.
func FetchGitHubDefaultTokenWrite(host, owner, repo, defaultBranch string, declaresContentsWrite bool, eligible func(workflowPath string) bool) (write, source string) {
	if owner == "" || repo == "" || eligible == nil {
		return "unknown", "unknown"
	}
	if w, ok := defaultTokenFromLog(host, owner, repo, defaultBranch, eligible); ok {
		return w, "log"
	}
	if !declaresContentsWrite && defaultTokenFromEffect(host, owner, repo) {
		return "true", "effect"
	}
	return "unknown", "unknown"
}

// defaultTokenFromLog implements the log route described on
// FetchGitHubDefaultTokenWrite. ok is false whenever the route could
// not settle a write/no-write answer at all (no default branch to
// compare against, no reachable run listing, no eligible run with a
// fetchable job, or a log fetch/parse failure on the one eligible run
// it did commit to).
func defaultTokenFromLog(host, owner, repo, defaultBranch string, eligible func(workflowPath string) bool) (write string, ok bool) {
	if defaultBranch == "" {
		return "", false
	}
	rest, err := newGitHubRESTClient(host)
	if err != nil {
		return "", false
	}
	runs, err := listCompletedRuns(rest, owner, repo)
	if err != nil {
		logRefusedLane("default token runs", err)
		return "", false
	}
	jobsCalls := 0
	for _, run := range runs {
		if !runSafeForDefaultToken(run, owner, repo, defaultBranch) {
			continue
		}
		if !eligible(run.Path) {
			continue
		}
		if jobsCalls == maxDefaultTokenJobsCalls {
			// Three eligible runs answered no job: the route stops
			// here rather than walk the whole listing.
			return "", false
		}
		jobsCalls++
		job, found := firstRunJob(rest, owner, repo, run.ID)
		if !found {
			// The job fetch itself failed (network, 404, an empty
			// jobs list): this run tells us nothing, try the next
			// eligible one.
			continue
		}
		scopes, ok := fetchJobLogPermissions(host, owner, repo, job.ID)
		if !ok {
			// A job was fetched, but its log could not be read or
			// parsed, or carried no permissions block at all: the
			// log route is abandoned here, not retried on another
			// run (a different run of the same workflow would answer
			// the same thing).
			return "", false
		}
		return scopeWrite(scopes), true
	}
	return "", false
}

// runSafeForDefaultToken reports whether run is safe evidence of the
// repository's own default token: triggered by push, schedule or a
// manual dispatch (never a fork pull_request or any other event whose
// job might run with a different token entirely), on the repository's
// own default branch, checked out from the repository itself (never a
// fork's), and triggered by neither actor nor triggering actor as
// defaultTokenExcludedActor (Dependabot's own token is scoped by the
// repository's Dependabot settings, not by this workflow).
func runSafeForDefaultToken(run remoteRun, owner, repo, defaultBranch string) bool {
	if !defaultTokenEligibleEvents[run.Event] {
		return false
	}
	if run.HeadBranch != defaultBranch {
		return false
	}
	if !strings.EqualFold(runHeadRepoFullName(run), owner+"/"+repo) {
		return false
	}
	if isDefaultTokenExcludedActor(run.Actor) || isDefaultTokenExcludedActor(run.TriggeringActor) {
		return false
	}
	return true
}

// runHeadRepoFullName is the repository a run actually checked out:
// HeadRepository's full name when the run carries one (set on every
// run, a fork's own full name on a fork pull_request run), the base
// Repository's otherwise.
func runHeadRepoFullName(run remoteRun) string {
	if run.HeadRepository != nil && run.HeadRepository.FullName != "" {
		return run.HeadRepository.FullName
	}
	if run.Repository != nil {
		return run.Repository.FullName
	}
	return ""
}

// isDefaultTokenExcludedActor reports whether actor (possibly nil,
// when the API omits it) is the excluded identity.
func isDefaultTokenExcludedActor(actor *remoteActor) bool {
	return actor != nil && actor.Login == defaultTokenExcludedActor
}

// listCompletedRuns lists the repository's latest defaultTokenRunsPerPage
// completed workflow runs, newest first (GitHub's own default order).
func listCompletedRuns(rest restClient, owner, repo string) ([]remoteRun, error) {
	resp, err := rest.Request(http.MethodGet, fmt.Sprintf(
		"repos/%s/%s/actions/runs?per_page=%d&status=completed", owner, repo, defaultTokenRunsPerPage,
	), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var page remoteRunsResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, err
	}
	return page.WorkflowRuns, nil
}

// firstRunJob fetches a run's first job (per_page=1, the shape the
// collection contract asks for). found is false on any fetch, decode
// or empty-list failure.
func firstRunJob(rest restClient, owner, repo string, runID int64) (job remoteJob, found bool) {
	resp, err := rest.Request(http.MethodGet, fmt.Sprintf(
		"repos/%s/%s/actions/runs/%d/jobs?per_page=1", owner, repo, runID,
	), nil)
	if err != nil {
		logRefusedLane("default token jobs", err)
		return remoteJob{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	var page remoteJobsResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || len(page.Jobs) == 0 {
		return remoteJob{}, false
	}
	return page.Jobs[0], true
}

// fetchJobLogPermissions fetches jobID's log (bounded to maxJobLogBytes)
// and parses the "GITHUB_TOKEN Permissions" block from it. ok is false
// when the log could not be fetched at all, or carried no such block.
func fetchJobLogPermissions(host, owner, repo string, jobID int64) (map[string]string, bool) {
	body, ok := fetchJobLogHead(host, owner, repo, jobID)
	if !ok {
		return nil, false
	}
	return parseTokenPermissionsBlock(body)
}

// fetchJobLogHead fetches at most maxJobLogBytes of owner/repo/jobID's
// log through the GitHub REST API: GET
// /repos/{owner}/{repo}/actions/jobs/{job_id}/logs, which answers a
// redirect to an external log store GitHub does not operate. That
// redirect is followed by hand, with a plain, unauthenticated client:
// the log store is never the API host, and this process's GitHub
// credentials must never reach it. resp.Location() (rather than
// reading the Location header directly) resolves a relative target
// against the request URL, the same rule browsers and other HTTP
// clients follow. ok is false on any network, auth, or
// unexpected-status failure. The log body is never logged by any
// caller: it may carry build output.
func fetchJobLogHead(host, owner, repo string, jobID int64) (string, bool) {
	logsURL := apiBaseURLForHost(host) + fmt.Sprintf("/repos/%s/%s/actions/jobs/%d/logs", owner, repo, jobID)
	req, err := http.NewRequest(http.MethodGet, logsURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := rawFetchToken(); tok != "" {
		req.Header.Set("Authorization", "token "+tok)
	}
	resp, err := jobLogsAPIClient.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// Some hosts (GHES configurations without a separate log
		// store) answer the log directly.
		return readLogHead(resp.Body)
	case http.StatusFound, http.StatusTemporaryRedirect, http.StatusMovedPermanently:
		// fall through to the redirect handling below.
	default:
		return "", false
	}

	location, err := resp.Location()
	if err != nil {
		return "", false
	}
	redirectReq, err := http.NewRequest(http.MethodGet, location.String(), nil)
	if err != nil {
		return "", false
	}
	redirectResp, err := jobLogsStoreClient.Do(redirectReq)
	if err != nil {
		return "", false
	}
	defer func() { _ = redirectResp.Body.Close() }()
	if redirectResp.StatusCode != http.StatusOK {
		return "", false
	}
	return readLogHead(redirectResp.Body)
}

// readLogHead reads at most maxJobLogBytes from r.
func readLogHead(r io.Reader) (string, bool) {
	data, err := io.ReadAll(io.LimitReader(r, maxJobLogBytes))
	if err != nil {
		return "", false
	}
	return string(data), true
}

// parseTokenPermissionsBlock finds the "GITHUB_TOKEN Permissions" line
// in body (after stripping each line's leading log timestamp) and
// reads the scope: level lines that immediately follow it, stopping
// at the group marker that closes it, the first blank line, or a line
// that is not a scope line at all. ok is false when the header is
// never found, or when it is found but no scope line follows it (an
// empty or malformed block).
func parseTokenPermissionsBlock(body string) (map[string]string, bool) {
	rawLines := strings.Split(body, "\n")
	lines := make([]string, len(rawLines))
	for i, l := range rawLines {
		lines[i] = logTimestampRe.ReplaceAllString(strings.TrimRight(l, "\r"), "")
	}
	for i, line := range lines {
		if !tokenPermissionsHeaderRe.MatchString(line) {
			continue
		}
		scopes := map[string]string{}
		for _, next := range lines[i+1:] {
			if tokenPermissionsEndGroupRe.MatchString(next) {
				break
			}
			if strings.TrimSpace(next) == "" {
				break
			}
			m := tokenPermissionsScopeRe.FindStringSubmatch(next)
			if m == nil {
				break
			}
			scopes[m[1]] = m[2]
		}
		if len(scopes) == 0 {
			return nil, false
		}
		return scopes, true
	}
	return nil, false
}

// scopeWrite folds a parsed GITHUB_TOKEN Permissions block to "true"
// when any scope other than Metadata is "write", "false" when every
// scope is "read".
func scopeWrite(scopes map[string]string) string {
	for scope, level := range scopes {
		if scope == "Metadata" {
			continue
		}
		if level == "write" {
			return "true"
		}
	}
	return "false"
}

// defaultTokenFromEffect implements the effect route described on
// FetchGitHubDefaultTokenWrite: a release authored by
// github-actions[bot]. The commits fallback this route once also
// tried is gone: anyone with push access can author a commit under
// any identity's name (the git author/committer fields are
// unauthenticated metadata), so a commit "by" github-actions[bot]
// proves nothing about which token ran; a release's author is the
// identity GitHub actually authenticated when it was published.
func defaultTokenFromEffect(host, owner, repo string) bool {
	rest, err := newGitHubRESTClient(host)
	if err != nil {
		return false
	}
	return releaseAuthoredByBot(rest, owner, repo)
}

// releaseAuthoredByBot reports whether any of the repository's latest
// defaultTokenRunsPerPage releases was authored by
// defaultTokenBotLogin.
func releaseAuthoredByBot(rest restClient, owner, repo string) bool {
	resp, err := rest.Request(http.MethodGet, fmt.Sprintf(
		"repos/%s/%s/releases?per_page=%d", owner, repo, defaultTokenRunsPerPage,
	), nil)
	if err != nil {
		logRefusedLane("default token releases", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	var releases []remoteRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return false
	}
	for _, r := range releases {
		if r.Author != nil && r.Author.Login == defaultTokenBotLogin {
			return true
		}
	}
	return false
}

// restClient is the slim subset of *api.RESTClient this file calls
// through: narrowing the parameter type to just what listCompletedRuns,
// firstRunJob and releaseAuthoredByBot need keeps this file free of a
// direct dependency on the go-gh api package.
type restClient interface {
	Request(method string, path string, body io.Reader) (*http.Response, error)
}
