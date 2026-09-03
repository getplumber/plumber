package cmd

import (
	"os"
	"regexp"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	providerPkg "github.com/getplumber/plumber/provider"
	"github.com/getplumber/plumber/utils"
)

// gitCommitSHAPattern matches a git commit SHA (a 7-to-40 char lowercase hex
// string, covering both abbreviated and full forms). It is what tells a real
// commit apart from the literal "HEAD" placeholder a --project run leaves in
// result.HeadCommitSha when no commit was resolved.
var gitCommitSHAPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// detectGitHeadSHA reads the local checkout's HEAD commit. It is a package
// var so the last-resort SHA source can be exercised without a git checkout.
var detectGitHeadSHA = utils.DetectGitHeadSHA

// resolveArtifactRef returns the analyzed commit for this run: a resolved
// SHA and the symbolic branch or tag (#443). It is the single source every
// artifact writer reads, so the same commit is reported the same way in the
// JSON report, the PBOM, SARIF and OCSF.
//
// The key question is whether the CI job is building the very project that was
// analyzed. For a self-analysis it is, so the job's own $CI_COMMIT_SHA /
// $CI_COMMIT_REF_NAME are the analyzed commit and ref and are preferred. When
// the analysis points elsewhere - a cross-project --project scan, or an
// explicit --branch on a different ref - only the analyzed target's own head
// and branch (which control.task resolves into the result) may be used, so the
// artifact names the analyzed project and never the scanner that ran it. In
// that case the job's env commit and the local checkout are NOT fallbacks
// (they describe the scanner): when the target head did not resolve - a remote
// scan may not resolve it - the commit is omitted rather than mis-attributed.
// For a self-analysis the local git checkout is the last-resort SHA source.
// The literal "HEAD" placeholder is never a commit, so it is filtered out and
// an unresolvable SHA comes back empty rather than as "HEAD" - callers omit the
// field instead of emitting a non-commit value. "HEAD" is filtered from the
// ref too.
func resolveArtifactRef(p providerPkg.Provider, result *control.AnalysisResult, conf *configuration.Configuration) (sha, ref string) {
	var head, envSHA, envRef, envRepo, branch, projectPath, confBranch, defaultBranch, repoRoot string
	if result != nil {
		head, branch, defaultBranch, projectPath = result.HeadCommitSha, result.AnalyzeBranch, result.DefaultBranch, result.ProjectPath
	}
	if p != nil {
		env := p.CIEnvVars()
		envSHA = strings.TrimSpace(os.Getenv(env.CommitSHA))
		if env.RefName != "" {
			envRef = strings.TrimSpace(os.Getenv(env.RefName))
		}
		if env.RepoPath != "" {
			envRepo = strings.TrimSpace(os.Getenv(env.RepoPath))
		}
	}
	localProject := false
	if conf != nil {
		confBranch, repoRoot, localProject = conf.Branch, conf.GitRepoRoot, conf.IsLocalProject
	}

	// When the CI job is building the very project we analyzed, its own commit
	// and ref env vars ARE the analyzed commit and ref, so they are preferred.
	// Otherwise the analysis points elsewhere than the job's checkout - a
	// cross-project --project scan, or an explicit --branch on a different ref -
	// and control.task has already resolved the analyzed target's own head and
	// branch into the result; those win, so the artifact names the analyzed
	// project rather than the scanner. (This is the same self-vs-elsewhere test
	// ProjectFromCIEnvironment makes when it decides whether $CI_COMMIT_SHA is
	// the analyzed head at all.)
	crossProject := envRepo != "" && projectPath != "" && !strings.EqualFold(projectPath, envRepo)
	branchElsewhere := confBranch != "" && confBranch != envRef
	preferResult := crossProject || branchElsewhere

	if preferResult {
		// The analysis points elsewhere than the job's checkout, so ONLY the
		// resolved target head is a valid commit. The job's own env commit and
		// the local checkout both describe the scanner, not the analyzed target
		// (a remote scan may not resolve the target head at all), so when the
		// head does not resolve the commit is omitted rather than mis-attributed.
		sha = realCommitSHA(head)
		// The result's resolved branch is authoritative; the job's ambient ref
		// describes the scanner and is not used. An explicit --branch wins.
		ref = firstNonEmptyRef(confBranch, branch, defaultBranch)
		return sha, ref
	}

	// Self-analysis: the CI job is building the analyzed project, so its own
	// commit and ref env vars are the analyzed commit and ref and win; the
	// result's head and the local checkout only stand in when the env is absent.
	for _, candidate := range []string{envSHA, head} {
		if s := realCommitSHA(candidate); s != "" {
			sha = s
			break
		}
	}
	// The local checkout is a valid commit source only when it IS the analyzed
	// project (IsLocalProject). For a --project scan of a different or remote
	// project the checkout is some unrelated repo, so stamping its HEAD would be
	// false provenance; leave the commit omitted instead.
	if sha == "" && localProject && repoRoot != "" {
		sha = realCommitSHA(detectGitHeadSHA(repoRoot))
	}
	ref = firstNonEmptyRef(confBranch, envRef, branch, defaultBranch)
	return sha, ref
}

// artifactRepoURI is the analyzed project's web URL, reusing the location
// linker's server resolution so SARIF's versionControlProvenance and OCSF's
// resource point at the right repository (#443). The repository path is the
// analyzed project (result.ProjectPath) rather than the linker's, so a
// cross-project scan names the analyzed target and not the scanner's own
// project - keeping the URI coherent with the resolved commit and ref. For a
// self-analysis the two are identical. Empty when it cannot be derived.
func artifactRepoURI(conf *configuration.Configuration, result *control.AnalysisResult, provider string) string {
	l := newLocationLinker(conf, result, provider)
	repo := l.repo
	if result != nil && result.ProjectPath != "" {
		repo = result.ProjectPath
	}
	if l.serverURL == "" || repo == "" {
		return ""
	}
	return l.serverURL + "/" + repo
}

// realCommitSHA returns s when it is a git commit SHA, or "" otherwise. It
// rejects the "HEAD" placeholder and any non-hex value, so a resolved commit
// is never confused with a symbolic default.
func realCommitSHA(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if gitCommitSHAPattern.MatchString(s) {
		return s
	}
	return ""
}

// firstNonEmptyRef returns the first branch/tag that is neither empty nor the
// "HEAD" placeholder.
func firstNonEmptyRef(candidates ...string) string {
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c != "" && c != "HEAD" {
			return c
		}
	}
	return ""
}
