package cmd

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	providerPkg "github.com/getplumber/plumber/provider"
)

// resolveArtifactRef is the single source of the analyzed commit (#443): a
// resolved SHA plus the symbolic branch/tag, sourced the same way for every
// artifact writer. The literal "HEAD" placeholder (the --project run with no
// resolved commit) must never leave as a SHA; it is omitted instead.
func TestResolveArtifactRef(t *testing.T) {
	gl := &providerPkg.GitLabProvider{}
	realSHA := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"

	t.Run("real sha and branch pass through", func(t *testing.T) {
		t.Setenv("CI_COMMIT_SHA", "")
		res := &control.AnalysisResult{HeadCommitSha: realSHA, AnalyzeBranch: "release/2.0"}
		sha, ref := resolveArtifactRef(gl, res, &configuration.Configuration{})
		if sha != realSHA {
			t.Fatalf("sha = %q, want the resolved head", sha)
		}
		if ref != "release/2.0" {
			t.Fatalf("ref = %q, want the analyzed branch", ref)
		}
	})

	t.Run("literal HEAD is replaced by the CI env commit, never emitted as a sha", func(t *testing.T) {
		t.Setenv("CI_COMMIT_SHA", realSHA)
		res := &control.AnalysisResult{HeadCommitSha: "HEAD", AnalyzeBranch: "main"}
		sha, _ := resolveArtifactRef(gl, res, &configuration.Configuration{})
		if sha != realSHA {
			t.Fatalf("sha = %q, want the CI env commit, never the literal HEAD", sha)
		}
	})

	t.Run("no resolvable commit yields an empty sha, not HEAD", func(t *testing.T) {
		t.Setenv("CI_COMMIT_SHA", "")
		res := &control.AnalysisResult{HeadCommitSha: "HEAD", AnalyzeBranch: "main"}
		sha, ref := resolveArtifactRef(gl, res, &configuration.Configuration{})
		if sha != "" {
			t.Fatalf("sha = %q, want empty when nothing real resolves (never the literal HEAD)", sha)
		}
		if ref != "main" {
			t.Fatalf("ref = %q, want the branch even when the sha is unresolved", ref)
		}
	})

	t.Run("the CI ref-name env is authoritative over the resolved default branch", func(t *testing.T) {
		t.Setenv("CI_COMMIT_SHA", realSHA)
		t.Setenv("CI_COMMIT_REF_NAME", "release/2.0")
		// The run analyzed the default branch (AnalyzeBranch defaulted to
		// main), but the job is building release/2.0: the env wins.
		res := &control.AnalysisResult{HeadCommitSha: realSHA, AnalyzeBranch: "main", DefaultBranch: "main"}
		_, ref := resolveArtifactRef(gl, res, &configuration.Configuration{})
		if ref != "release/2.0" {
			t.Fatalf("ref = %q, want the CI ref-name env over the default branch", ref)
		}
	})

	t.Run("ref falls back through conf.Branch to the default branch, HEAD filtered", func(t *testing.T) {
		t.Setenv("CI_COMMIT_REF_NAME", "")
		t.Setenv("CI_COMMIT_SHA", "")
		res := &control.AnalysisResult{HeadCommitSha: realSHA, AnalyzeBranch: "HEAD", DefaultBranch: "main"}
		_, ref := resolveArtifactRef(gl, res, &configuration.Configuration{Branch: ""})
		if ref != "main" {
			t.Fatalf("ref = %q, want the default branch once HEAD is filtered out", ref)
		}
	})

	t.Run("an explicit --branch on a ref other than the job's prefers the analyzed target over the ambient job commit", func(t *testing.T) {
		jobSHA := "0000000000000000000000000000000000000000"
		targetSHA := realSHA
		t.Setenv("CI_COMMIT_SHA", jobSHA)
		t.Setenv("CI_COMMIT_REF_NAME", "main")
		// The job built main, but --branch analyzed release/2.0: control.task
		// fetched release/2.0's own head into HeadCommitSha. That target, not
		// the job's own checkout, is what the artifact must name.
		res := &control.AnalysisResult{HeadCommitSha: targetSHA, AnalyzeBranch: "release/2.0"}
		sha, ref := resolveArtifactRef(gl, res, &configuration.Configuration{Branch: "release/2.0"})
		if sha != targetSHA {
			t.Fatalf("sha = %q, want the analyzed target head, not the job's own commit", sha)
		}
		if ref != "release/2.0" {
			t.Fatalf("ref = %q, want the explicitly analyzed branch over the job's ref", ref)
		}
	})

	t.Run("without an explicit --branch the job's own commit stays authoritative", func(t *testing.T) {
		jobSHA := realSHA
		apiDefaultHead := "0000000000000000000000000000000000000000"
		t.Setenv("CI_COMMIT_SHA", jobSHA)
		t.Setenv("CI_COMMIT_REF_NAME", "feature/x")
		// No --branch: the job built feature/x at jobSHA. HeadCommitSha may hold
		// the API's default-branch head, but the analyzed commit is the job's.
		res := &control.AnalysisResult{HeadCommitSha: apiDefaultHead, AnalyzeBranch: "feature/x"}
		sha, ref := resolveArtifactRef(gl, res, &configuration.Configuration{Branch: ""})
		if sha != jobSHA {
			t.Fatalf("sha = %q, want the CI job commit for a self-analysis", sha)
		}
		if ref != "feature/x" {
			t.Fatalf("ref = %q, want the job's analyzed ref", ref)
		}
	})

	t.Run("a cross-project scan names the analyzed target, not the scanner job's own commit", func(t *testing.T) {
		scannerSHA := "0000000000000000000000000000000000000000"
		targetSHA := realSHA
		t.Setenv("CI_COMMIT_SHA", scannerSHA)
		t.Setenv("CI_COMMIT_REF_NAME", "main")
		t.Setenv("CI_PROJECT_PATH", "scanner/fleet") // the job builds its own repo
		// control.task resolved a *different* analyzed project's head and branch
		// (ProjectFromCIEnvironment declined because the target != the job repo).
		res := &control.AnalysisResult{
			ProjectPath:   "acme/target",
			HeadCommitSha: targetSHA,
			AnalyzeBranch: "develop",
			DefaultBranch: "develop",
		}
		sha, ref := resolveArtifactRef(gl, res, &configuration.Configuration{})
		if sha != targetSHA {
			t.Fatalf("sha = %q, want the analyzed target's head, not the scanner job's commit", sha)
		}
		if ref != "develop" {
			t.Fatalf("ref = %q, want the analyzed target's branch, not the scanner job's ref", ref)
		}
	})

	t.Run("an explicit --branch equal to the job's own ref stays a self-analysis and keeps the env commit", func(t *testing.T) {
		jobSHA := realSHA
		otherHead := "0000000000000000000000000000000000000000"
		t.Setenv("CI_COMMIT_SHA", jobSHA)
		t.Setenv("CI_COMMIT_REF_NAME", "main")
		// --branch main names the very ref the job built, so branchElsewhere is
		// false: this is still a self-analysis and the job's own commit wins
		// over the result head (pins the confBranch != envRef clause).
		res := &control.AnalysisResult{HeadCommitSha: otherHead, AnalyzeBranch: "main"}
		sha, ref := resolveArtifactRef(gl, res, &configuration.Configuration{Branch: "main"})
		if sha != jobSHA {
			t.Fatalf("sha = %q, want the CI job commit when --branch equals the job's own ref", sha)
		}
		if ref != "main" {
			t.Fatalf("ref = %q, want the analyzed ref", ref)
		}
	})

	t.Run("resolves through the GitHub provider's own env mapping", func(t *testing.T) {
		gh := &providerPkg.GitHubProvider{}
		t.Setenv("CI_COMMIT_SHA", "")
		t.Setenv("CI_COMMIT_REF_NAME", "")
		t.Setenv("GITHUB_SHA", realSHA)
		t.Setenv("GITHUB_REF_NAME", "release/2.0")
		res := &control.AnalysisResult{HeadCommitSha: "HEAD", AnalyzeBranch: "main", DefaultBranch: "main"}
		sha, ref := resolveArtifactRef(gh, res, &configuration.Configuration{})
		if sha != realSHA {
			t.Fatalf("sha = %q, want the GITHUB_SHA env commit", sha)
		}
		if ref != "release/2.0" {
			t.Fatalf("ref = %q, want the GITHUB_REF_NAME env ref", ref)
		}
	})

	t.Run("an explicit --branch whose target head is unresolved omits the commit rather than naming the job's own", func(t *testing.T) {
		jobSHA := realSHA
		t.Setenv("CI_COMMIT_SHA", jobSHA)
		t.Setenv("CI_COMMIT_REF_NAME", "main")
		// --branch release/2.0 but the target head could not be fetched. The
		// job's own commit belongs to main, not release/2.0, so stamping it
		// would be false provenance: the commit is omitted, the ref kept.
		res := &control.AnalysisResult{HeadCommitSha: "HEAD", AnalyzeBranch: "release/2.0"}
		sha, ref := resolveArtifactRef(gl, res, &configuration.Configuration{Branch: "release/2.0"})
		if sha != "" {
			t.Fatalf("sha = %q, want empty (omitted) when the analyzed branch's head is unresolved, never the job's own commit", sha)
		}
		if ref != "release/2.0" {
			t.Fatalf("ref = %q, want the explicitly analyzed branch", ref)
		}
	})

	t.Run("a cross-project scan whose target head is unresolved omits the commit, never the scanner's", func(t *testing.T) {
		// A remote GitHub scan does not resolve the target repo's head, so
		// result.HeadCommitSha is empty. The scanner job's own GITHUB_SHA must
		// not be stamped as the target's revision: omit the commit, keep the
		// target's repo and ref.
		gh := &providerPkg.GitHubProvider{}
		t.Setenv("GITHUB_SHA", realSHA)     // the scanner job's own commit
		t.Setenv("GITHUB_REF_NAME", "main") // the scanner job's own ref
		t.Setenv("GITHUB_REPOSITORY", "scanner/fleet")
		res := &control.AnalysisResult{ProjectPath: "acme/target", HeadCommitSha: "", AnalyzeBranch: "develop", DefaultBranch: "develop"}
		sha, ref := resolveArtifactRef(gh, res, &configuration.Configuration{})
		if sha != "" {
			t.Fatalf("sha = %q, want empty (omitted) for a remote cross-project scan, never the scanner's own commit", sha)
		}
		if ref != "develop" {
			t.Fatalf("ref = %q, want the analyzed target's branch, not the scanner's ref", ref)
		}
	})

	t.Run("a local --branch with no CI ref-name env uses the resolved head, skipping env and checkout fallbacks", func(t *testing.T) {
		t.Setenv("CI_COMMIT_SHA", "")
		t.Setenv("CI_COMMIT_REF_NAME", "")
		restore := detectGitHeadSHA
		defer func() { detectGitHeadSHA = restore }()
		// If the checkout fallback were (wrongly) reached, it would return this.
		detectGitHeadSHA = func(string) string { return "ffffffffffffffffffffffffffffffffffffffff" }

		// --branch set with no job ref-name env: branchElsewhere is true, so only
		// the resolved head is used; the (empty) env commit and the local
		// checkout are skipped even though GitRepoRoot/IsLocalProject are set.
		res := &control.AnalysisResult{HeadCommitSha: realSHA, AnalyzeBranch: "feature"}
		sha, ref := resolveArtifactRef(gl, res, &configuration.Configuration{Branch: "feature", GitRepoRoot: "/repo", IsLocalProject: true})
		if sha != realSHA {
			t.Fatalf("sha = %q, want the resolved head, not the checkout fallback", sha)
		}
		if ref != "feature" {
			t.Fatalf("ref = %q, want the --branch value", ref)
		}
	})

	t.Run("the local git checkout is the last-resort sha source", func(t *testing.T) {
		t.Setenv("CI_COMMIT_SHA", "")
		restore := detectGitHeadSHA
		defer func() { detectGitHeadSHA = restore }()

		detectGitHeadSHA = func(string) string { return realSHA }
		res := &control.AnalysisResult{HeadCommitSha: "HEAD", AnalyzeBranch: "main"}
		conf := &configuration.Configuration{GitRepoRoot: "/repo", IsLocalProject: true}
		sha, _ := resolveArtifactRef(gl, res, conf)
		if sha != realSHA {
			t.Fatalf("sha = %q, want the local checkout head when it is the analyzed project", sha)
		}

		// A non-commit from the checkout is filtered like any other source.
		detectGitHeadSHA = func(string) string { return "HEAD" }
		sha, _ = resolveArtifactRef(gl, res, conf)
		if sha != "" {
			t.Fatalf("sha = %q, want empty when the checkout yields no real commit", sha)
		}
	})

	t.Run("the local checkout is not used when it is not the analyzed project", func(t *testing.T) {
		t.Setenv("CI_COMMIT_SHA", "")
		restore := detectGitHeadSHA
		defer func() { detectGitHeadSHA = restore }()
		detectGitHeadSHA = func(string) string { return realSHA } // some unrelated repo's HEAD

		// A local --project scan of a different repo: IsLocalProject is false, so
		// the checkout must not be stamped as the analyzed project's commit.
		res := &control.AnalysisResult{ProjectPath: "acme/other", HeadCommitSha: "HEAD", AnalyzeBranch: "main"}
		sha, _ := resolveArtifactRef(gl, res, &configuration.Configuration{GitRepoRoot: "/repo", IsLocalProject: false})
		if sha != "" {
			t.Fatalf("sha = %q, want empty (omitted) when the local checkout is not the analyzed project", sha)
		}
	})
}

// writeOutputsWithProvider is the single place that resolves the commit and
// stamps it onto the result before any artifact writer runs (#443). With no
// output files requested it does only that, so this locks the wiring: dropping
// the two stamping lines would ship empty provenance in every artifact.
func TestWriteOutputsStampsProvenance(t *testing.T) {
	// Zero the package-global output paths so no files are written; restore
	// them afterwards to keep other tests isolated.
	saved := []*string{&outputFile, &pbomFile, &pbomCycloneDXFile, &sarifFile, &glsastFile, &csvFile, &ocsfFile}
	old := make([]string, len(saved))
	for i, p := range saved {
		old[i] = *p
		*p = ""
	}
	defer func() {
		for i, p := range saved {
			*p = old[i]
		}
	}()

	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	t.Setenv("CI_COMMIT_SHA", sha)
	t.Setenv("CI_COMMIT_REF_NAME", "release/2.0")
	t.Setenv("CI_SERVER_URL", "")
	t.Setenv("CI_PROJECT_PATH", "")

	result := &control.AnalysisResult{ProjectPath: "acme/target"}
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example"}
	if err := writeOutputsWithProvider(&providerPkg.GitLabProvider{}, result, conf, complianceSummary{}); err != nil {
		t.Fatalf("writeOutputsWithProvider: %v", err)
	}
	if result.ArtifactCommitSHA != sha {
		t.Errorf("ArtifactCommitSHA = %q, want the resolved commit stamped onto the result", result.ArtifactCommitSHA)
	}
	if result.ArtifactRef != "release/2.0" {
		t.Errorf("ArtifactRef = %q, want the resolved ref stamped onto the result", result.ArtifactRef)
	}
	if result.ArtifactRepoURI != "https://gitlab.example/acme/target" {
		t.Errorf("ArtifactRepoURI = %q, want the derived repo URI stamped onto the result", result.ArtifactRepoURI)
	}
}

// artifactRepoURI feeds SARIF's versionControlProvenance and OCSF's resource
// the analyzed repository URL, reusing the location linker (#443). It must be
// empty, not a partial URL, when the repository cannot be derived so callers
// omit the provenance rather than emit a dangling host.
func TestArtifactRepoURI(t *testing.T) {
	t.Setenv("CI_SERVER_URL", "")
	t.Setenv("CI_PROJECT_PATH", "")

	t.Run("derives server + repo for a resolved gitlab project", func(t *testing.T) {
		conf := &configuration.Configuration{GitlabURL: "https://gitlab.example"}
		res := &control.AnalysisResult{ProjectPath: "acme/target"}
		if got := artifactRepoURI(conf, res, "gitlab"); got != "https://gitlab.example/acme/target" {
			t.Fatalf("uri = %q, want the server joined to the repo path", got)
		}
	})

	t.Run("empty when the repository cannot be derived", func(t *testing.T) {
		conf := &configuration.Configuration{GitlabURL: "https://gitlab.example"}
		res := &control.AnalysisResult{ProjectPath: ""}
		if got := artifactRepoURI(conf, res, "gitlab"); got != "" {
			t.Fatalf("uri = %q, want empty when no repo path resolves", got)
		}
	})

	t.Run("names the analyzed target, not the CI job's own project, on a cross-project scan", func(t *testing.T) {
		t.Setenv("CI_SERVER_URL", "https://gitlab.example")
		t.Setenv("CI_PROJECT_PATH", "scanner/fleet") // the job's own project
		conf := &configuration.Configuration{GitlabURL: "https://gitlab.example"}
		res := &control.AnalysisResult{ProjectPath: "acme/target"}
		if got := artifactRepoURI(conf, res, "gitlab"); got != "https://gitlab.example/acme/target" {
			t.Fatalf("uri = %q, want the analyzed target repo, not the scanner's CI_PROJECT_PATH", got)
		}
	})

	t.Run("derives the GitHub web URL from the default host", func(t *testing.T) {
		t.Setenv("GITHUB_SERVER_URL", "")
		t.Setenv("GITHUB_REPOSITORY", "")
		conf := &configuration.Configuration{}
		res := &control.AnalysisResult{ProjectPath: "acme/target"}
		if got := artifactRepoURI(conf, res, "github"); got != "https://github.com/acme/target" {
			t.Fatalf("uri = %q, want the github.com web URL for the analyzed repo", got)
		}
	})

	t.Run("derives the GitHub web URL from a GHES API host", func(t *testing.T) {
		t.Setenv("GITHUB_SERVER_URL", "")
		t.Setenv("GITHUB_REPOSITORY", "")
		conf := &configuration.Configuration{GithubAPIHost: "https://ghes.example.com/api/v3"}
		res := &control.AnalysisResult{ProjectPath: "acme/target"}
		if got := artifactRepoURI(conf, res, "github"); got != "https://ghes.example.com/acme/target" {
			t.Fatalf("uri = %q, want the GHES web host (api path stripped) for the analyzed repo", got)
		}
	})
}
