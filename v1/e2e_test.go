//go:build cli

package v1

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// e2eCases are the rows that call GitHub or GitLab, run against the fixture
// repositories. A row costs about 80 GitHub API requests (5,000 an hour per
// token), so rows combine flags where they do not interfere.
var e2eCases = []cliCase{
	// analyze on GitHub.
	onGitHub("clean-score", 0, "analyze", githubTarget, "--branch", "clean", "--score"),
	onGitHub("clean-url-target", 0, "analyze", "https://"+githubTarget, "--branch", "clean"),
	onGitHub("clean-project-flags", 0, "analyze", "--provider", "github", "--project", githubRepo, "--branch", "clean", "--github-url", "api.github.com"),
	onGitHub("clean-local-clone", 0, "analyze", "--score").in("clean"),
	onGitHub("findings", 1, "analyze", githubTarget, "--branch", "findings"),
	onGitHub("findings-outputs", 1, "analyze", githubTarget, "--branch", "findings", "--print=false",
		"-o", "report.json", "--csv", "report.csv", "--ocsf", "report.ocsf.json", "--sarif", "report.sarif",
		"--pbom", "pbom.json", "--pbom-cyclonedx", "pbom.cdx.json").
		writes("report.json", "report.csv", "report.ocsf.json", "report.sarif", "pbom.json", "pbom.cdx.json"),
	onGitHub("findings-min-score-pass-score-point", 0, "analyze", githubTarget, "--branch", "findings", "--min-score", "E", "--score-point"),
	onGitHub("findings-min-points-pass-profile-v3", 0, "analyze", githubTarget, "--branch", "findings", "--min-points", "0", "--score-profile", "v3", "--score"),
	onGitHub("findings-threshold-deprecated", 0, "analyze", githubTarget, "--branch", "findings", "--threshold", "0"),
	onGitHub("findings-controls", 1, "analyze", githubTarget, "--branch", "findings", "--controls", "workflowMustNotGrantPermissionsWriteAll", "--print=false", "--output", "report.json").writes("report.json"),
	onGitHub("findings-no-controls", 0, "analyze", githubTarget, "--branch", "findings", "--no-controls", "--pbom", "pbom.json").writes("pbom.json"),
	onGitHub("findings-config-overlay-skip-controls", 1, "analyze", githubTarget, "--branch", "findings", "--config", "overlay.plumber.yaml", "--skip-controls", "workflowMustNotGrantPermissionsWriteAll").with("overlay.plumber.yaml"),
	onGitHub("findings-fail-warnings", 2, "analyze", githubTarget, "--branch", "findings", "--config", "warning.plumber.yaml", "--fail-warnings").with("warning.plumber.yaml"),
	onGitHub("explain-attack-cached-project", 0, "explain", "-a", "all", "--project", githubRepo, "--provider", "github").after("analyze", githubTarget, "--branch", "findings", "--print=false"),
	onGitHub("invalid-yaml", 1, "analyze", githubTarget, "--branch", "invalid-yaml"),
	onGitHub("reusable-local", 1, "analyze", githubTarget, "--branch", "reusable-local"),
	onGitHub("no-workflows", 0, "analyze", githubTarget, "--branch", "no-workflows"),
	onGitHub("unknown-branch", 2, "analyze", githubTarget, "--branch", "does-not-exist"),
	onGitHub("unknown-project", 2, "analyze", "github.com/getplumber-examples/does-not-exist"),
	onGitHub("bad-token", 2, "analyze", githubTarget, "--branch", "clean").withEnv("GITHUB_TOKEN=not-a-token"),

	// analyze on GitLab.
	onGitLab("clean-score", 0, "analyze", gitlabTarget, "--branch", "clean", "--score"),
	onGitLab("clean-url-target", 0, "analyze", "https://"+gitlabTarget, "--branch", "clean"),
	onGitLab("clean-project-flags", 0, "analyze", "--provider", "gitlab", "--gitlab-url", "https://gitlab.com", "--project", gitlabRepo, "--branch", "clean"),
	onGitLab("clean-local-clone", 0, "analyze", "--score").in("clean"),
	onGitLab("findings", 1, "analyze", gitlabTarget, "--branch", "findings"),
	onGitLab("findings-outputs", 1, "analyze", gitlabTarget, "--branch", "findings", "--print=false",
		"-o", "report.json", "--csv", "report.csv", "--ocsf", "report.ocsf.json", "--sarif", "report.sarif",
		"--glsast", "gl-sast-report.json", "--pbom", "pbom.json", "--pbom-cyclonedx", "pbom.cdx.json").
		writes("report.json", "report.csv", "report.ocsf.json", "report.sarif", "gl-sast-report.json", "pbom.json", "pbom.cdx.json"),
	onGitLab("findings-min-score-pass-score-point", 0, "analyze", gitlabTarget, "--branch", "findings", "--min-score", "E", "--score-point"),
	onGitLab("findings-min-points-pass-profile-v3", 0, "analyze", gitlabTarget, "--branch", "findings", "--min-points", "0", "--score-profile", "v3", "--score"),
	onGitLab("findings-threshold-deprecated", 0, "analyze", gitlabTarget, "--branch", "findings", "--threshold", "0"),
	onGitLab("findings-controls", 1, "analyze", gitlabTarget, "--branch", "findings", "--controls", "pipelineMustNotEnableDebugTrace", "--print=false", "-o", "report.json").writes("report.json"),
	onGitLab("findings-no-controls", 0, "analyze", gitlabTarget, "--branch", "findings", "--no-controls", "--pbom", "pbom.json").writes("pbom.json"),
	onGitLab("findings-config-overlay-skip-controls", 1, "analyze", gitlabTarget, "--branch", "findings", "--config", "overlay.plumber.yaml", "--skip-controls", "pipelineMustNotEnableDebugTrace").with("overlay.plumber.yaml"),
	onGitLab("explain-attack-cached-project", 0, "explain", "-a", "all", "--project", gitlabRepo, "--provider", "gitlab").after("analyze", gitlabTarget, "--branch", "findings", "--print=false"),
	onGitLab("includes-local", 1, "analyze", gitlabTarget, "--branch", "includes-local"),
	onGitLab("ci-config-path", 1, "analyze", gitlabTarget, "--branch", "includes-local", "--ci-config-path", "ci/build.yml"),
	onGitLab("invalid-yaml", 1, "analyze", gitlabTarget, "--branch", "invalid-yaml"),
	// No CI file: no control can run, and that fails the gate.
	onGitLab("no-ci", 1, "analyze", gitlabTarget, "--branch", "no-ci"),
	onGitLab("unknown-branch", 2, "analyze", gitlabTarget, "--branch", "does-not-exist"),
	onGitLab("unknown-project", 2, "analyze", "gitlab.com/getplumber/examples/does-not-exist"),
	onGitLab("bad-token", 2, "analyze", gitlabTarget, "--branch", "clean").withEnv("GITLAB_TOKEN=glpat-not-a-token"),
}

// providerSlots caps concurrent e2e rows per provider: gitlab.com throttles
// (429) as soon as two analyses run at once.
var providerSlots = map[string]chan struct{}{
	"github": make(chan struct{}, 2),
	"gitlab": make(chan struct{}, 1),
}

// tokenVars lists, per provider, the variables a token is read from, in
// order of preference.
var tokenVars = map[string][]string{
	"github": {"PLUMBER_E2E_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"},
	"gitlab": {"PLUMBER_E2E_GITLAB_TOKEN", "GITLAB_TOKEN"},
}

// cloneURLs maps each provider to the fixture repository that in() rows clone.
var cloneURLs = map[string]string{
	"github": "https://" + githubTarget + ".git",
	"gitlab": "https://" + gitlabTarget + ".git",
}

// throttled matches a provider refusing a request for rate reasons. Such a run
// says nothing about the CLI, so it fails the row instead of reaching a golden.
var throttled = regexp.MustCompile(`429 Too Many Requests|API rate limit exceeded`)

func TestE2E(t *testing.T) {
	runCases(t, e2eCases)
}

// e2eToken returns the first token set for provider, or "".
func e2eToken(provider string) string {
	for _, name := range tokenVars[provider] {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

// e2eEnv returns the token variable of an e2e row. It skips the row when no
// token is set (fails it with PLUMBER_E2E_REQUIRED), and clones the fixture
// branch for a row built with in(), moving sb.work into the clone.
func e2eEnv(t *testing.T, c cliCase, sb *sandbox) []string {
	t.Helper()
	token := e2eToken(c.provider)
	if token == "" {
		msg := fmt.Sprintf("no %s token: set PLUMBER_E2E_%s_TOKEN", c.provider, strings.ToUpper(c.provider))
		if os.Getenv("PLUMBER_E2E_REQUIRED") != "" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	if c.clone != "" {
		repo := cloneURLs[c.provider]
		dir := filepath.Join(sb.work, "repo")
		clone := exec.Command("git", "clone", "--quiet", "--depth", "1", "--branch", c.clone, repo, dir)
		if out, err := clone.CombinedOutput(); err != nil {
			t.Fatalf("clone %s@%s: %v\n%s", repo, c.clone, err, out)
		}
		sb.work = dir
	}
	return []string{strings.ToUpper(c.provider) + "_TOKEN=" + token}
}

// runRetrying runs the call under test, and runs it again up to 3 times, a
// minute apart, while the provider throttles it.
func runRetrying(t *testing.T, c cliCase, dir string, env []string) (stdout, stderr string, code int) {
	t.Helper()
	stdout, stderr, code = runPlumber(dir, env, c.args)
	for attempt := 1; throttled.MatchString(stdout + stderr); attempt++ {
		if attempt > 3 {
			t.Fatalf("%s kept throttling the run (rate limit): rerun later, nothing was compared\n%s", c.provider, throttled.FindString(stdout+stderr))
		}
		t.Logf("%s throttled the run, retrying in a minute (%d/3)", c.provider, attempt)
		time.Sleep(time.Minute)
		stdout, stderr, code = runPlumber(dir, env, c.args)
	}
	return stdout, stderr, code
}
