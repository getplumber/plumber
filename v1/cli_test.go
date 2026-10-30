//go:build cli

// Package v1 holds the CLI test suite of the refactoring (getplumber/monorepo#640).
//
// This file is the whole suite: one table row per CLI input, run against the
// built binary as a subprocess and compared with a golden file.
//
//   - local rows cover every input that makes no backend request. They run
//     with no token and with every proxy pointed at a closed port, so a row
//     that tries the network fails. `make test-integration` (#641).
//   - e2e rows cover every input that calls GitHub or GitLab. They run against
//     the fixture repositories, one branch per case (testdata/e2e, pushed by
//     testdata/e2e/sync.sh). `make test-e2e` (#651).
//
// TestCLICoverage walks the command tree of the binary and fails when a
// command or a flag has no row, so a new input coming from main needs a case.
//
// Refresh the golden files on purpose with UPDATE=1 and review the diff.
package v1

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const (
	githubRepo   = "getplumber-examples/plumber-cli-e2e"
	gitlabRepo   = "getplumber/examples/plumber-cli-e2e"
	githubTarget = "github.com/" + githubRepo
	gitlabTarget = "gitlab.com/" + gitlabRepo

	// closedPort refuses every connection: local rows send all their
	// traffic there, so any request fails instead of reaching a backend.
	closedPort = "http://127.0.0.1:9"
)

type mode string

const (
	local mode = "local"
	e2e   mode = "e2e"
)

type cliCase struct {
	name     string // golden file: testdata/golden/<mode>/<name>.golden
	mode     mode
	provider string     // e2e: "github" or "gitlab", decides which token the row gets
	args     []string   // arguments of the plumber call under test
	setup    [][]string // plumber calls run first, in the same work dir and home (not compared)
	inputs   []string   // paths under testdata/inputs copied into the work dir
	clone    string     // e2e: branch of the provider's fixture repo to clone; the row runs inside it
	env      []string   // extra environment, e.g. a bad token
	wantExit int
	files    []string // files the call writes, compared with the golden
	sorted   bool     // output lines are compared sorted: the CLI prints them in random order (a bug)
}

func run(name string, exit int, args ...string) cliCase {
	return cliCase{name: name, mode: local, args: args, wantExit: exit}
}

func onGitHub(name string, exit int, args ...string) cliCase {
	return cliCase{name: "github-" + name, mode: e2e, provider: "github", args: args, wantExit: exit}
}

func onGitLab(name string, exit int, args ...string) cliCase {
	return cliCase{name: "gitlab-" + name, mode: e2e, provider: "gitlab", args: args, wantExit: exit}
}

func (c cliCase) with(inputs ...string) cliCase  { c.inputs = append(c.inputs, inputs...); return c }
func (c cliCase) writes(files ...string) cliCase { c.files = append(c.files, files...); return c }
func (c cliCase) withEnv(kv ...string) cliCase   { c.env = append(c.env, kv...); return c }
func (c cliCase) in(branch string) cliCase       { c.clone = branch; return c }
func (c cliCase) after(args ...string) cliCase   { c.setup = append(c.setup, args); return c }
func (c cliCase) unordered() cliCase             { c.sorted = true; return c }

// cases is the table: one row per CLI input. An e2e row costs about 80
// GitHub API requests (5000/hour per token), so e2e rows combine flags where
// they do not interfere.
//
// cases is the table: one row per CLI input. --help rows for every command
// are added by helpCases from the command tree.
var cases = []cliCase{
	// Root.
	run("help", 0, "help"),
	run("help-analyze", 0, "help", "analyze"),
	run("unknown-command", 2, "bogus"),
	run("unknown-flag", 2, "analyze", "--nope"),
	run("version-flag-unsupported", 2, "--version"),

	run("version", 0, "version"),
	run("version-verbose", 0, "-v", "version"),
	run("completion", 0, "completion"),
	run("completion-bash", 0, "completion", "bash"),
	run("completion-zsh", 0, "completion", "zsh"),
	run("completion-fish", 0, "completion", "fish"),
	run("completion-powershell", 0, "completion", "powershell"),
	run("completion-bash-no-descriptions", 0, "completion", "bash", "--no-descriptions"),
	run("completion-zsh-no-descriptions", 0, "completion", "zsh", "--no-descriptions"),
	run("completion-fish-no-descriptions", 0, "completion", "fish", "--no-descriptions"),
	run("completion-powershell-no-descriptions", 0, "completion", "powershell", "--no-descriptions"),

	run("catalog", 0, "catalog"),
	run("capabilities", 0, "capabilities"),
	run("capabilities-defaults", 0, "capabilities", "defaults"),

	// explain.
	run("explain-code", 0, "explain", "ISSUE-101"),
	run("explain-code-json", 0, "explain", "ISSUE-101", "--json"),
	run("explain-unknown-code", 2, "explain", "BOGUS"),
	run("explain-list", 0, "explain", "--list"),
	run("explain-list-json", 0, "explain", "--list", "--json"),
	run("explain-all", 0, "explain", "--all"),
	run("explain-all-json", 0, "explain", "--all", "--json"),
	run("explain-attack-from-run", 0, "explain", "-a", "1", "--run", "score-compare/plumber-example-critical.v4.json").with("score-compare"),
	run("explain-attack-all-from-run", 0, "explain", "--attack", "all", "--run", "score-compare/plumber-example-critical.v4.json").with("score-compare"),
	run("explain-attack-no-cache", 2, "explain", "-a", "1"),
	run("explain-attack-project-no-cache", 2, "explain", "-a", "1", "--project", "a/b", "--provider", "github"),

	// config.
	run("config", 0, "config"),
	run("config-generate", 0, "config", "generate").writes(".plumber.yaml"),
	run("config-generate-overlay", 0, "config", "generate", "--overlay", "-o", "overlay.yaml").writes("overlay.yaml"),
	run("config-generate-exists", 2, "config", "generate").after("config", "generate"),
	run("config-generate-force", 0, "config", "generate", "--force", "--output", "custom.yaml").after("config", "generate", "-o", "custom.yaml"),
	run("config-generate-force-short", 0, "config", "generate", "-f").after("config", "generate"),
	run("config-init-no-terminal", 2, "config", "init"),
	run("config-init-force-output", 2, "config", "init", "--force", "--output", "x.yaml"),
	run("config-init-short-flags", 2, "config", "init", "-f", "-o", "x.yaml"),
	run("config-view-default-file", 0, "config", "view").after("config", "generate"),
	run("config-view-no-file", 0, "config", "view"),
	run("config-view-overlay", 0, "config", "view", "-c", "overlay.plumber.yaml").with("overlay.plumber.yaml"),
	// Provenance lines come out of a map in random order (cmd/config_explain.go).
	run("config-view-explain", 0, "config", "view", "--config", "overlay.plumber.yaml", "--explain").with("overlay.plumber.yaml").unordered(),
	run("config-view-no-color", 0, "config", "view", "-c", "overlay.plumber.yaml", "--no-color").with("overlay.plumber.yaml"),
	run("config-validate-ok", 0, "config", "validate", "-c", "overlay.plumber.yaml").with("overlay.plumber.yaml"),
	run("config-validate-warning", 0, "config", "validate", "--config", "warning.plumber.yaml").with("warning.plumber.yaml"),
	run("config-validate-fail-warnings", 2, "config", "validate", "-c", "warning.plumber.yaml", "--fail-warnings").with("warning.plumber.yaml"),
	run("config-validate-legacy", 0, "config", "validate", "-c", "legacy.plumber.yaml").with("legacy.plumber.yaml"),
	run("config-validate-invalid-yaml", 2, "config", "validate", "-c", "invalid.plumber.yaml").with("invalid.plumber.yaml"),
	run("config-validate-missing", 2, "config", "validate", "-c", "missing.yaml"),
	run("config-resolve", 0, "config", "resolve", "-c", "overlay.plumber.yaml").with("overlay.plumber.yaml"),
	run("config-resolve-to-file", 0, "config", "resolve", "--config", "overlay.plumber.yaml", "--output", "resolved.yaml").with("overlay.plumber.yaml").writes("resolved.yaml"),
	run("config-resolve-short-output", 0, "config", "resolve", "-c", "overlay.plumber.yaml", "-o", "resolved.yaml").with("overlay.plumber.yaml").writes("resolved.yaml"),
	run("config-diff", 0, "config", "diff", "-c", "overlay.plumber.yaml").with("overlay.plumber.yaml"),
	run("config-diff-no-color", 0, "config", "diff", "--config", "overlay.plumber.yaml", "--no-color").with("overlay.plumber.yaml"),
	run("config-slim", 0, "config", "slim", "-c", "full.yaml").after("config", "generate", "-o", "full.yaml"),
	run("config-slim-to-file", 0, "config", "slim", "--config", "full.yaml", "--output", "slim.yaml").after("config", "generate", "-o", "full.yaml").writes("slim.yaml"),
	run("config-slim-short-output", 0, "config", "slim", "-c", "full.yaml", "-o", "slim.yaml").after("config", "generate", "-o", "full.yaml").writes("slim.yaml"),
	run("config-migrate", 0, "config", "migrate", "--input", "legacy.plumber.yaml").with("legacy.plumber.yaml").writes("legacy.plumber.yaml.v2"),
	run("config-migrate-output", 0, "config", "migrate", "--input", "legacy.plumber.yaml", "--output", "migrated.yaml").with("legacy.plumber.yaml").writes("migrated.yaml"),
	run("config-migrate-in-place", 0, "config", "migrate", "--input", "legacy.plumber.yaml", "--in-place").with("legacy.plumber.yaml").writes("legacy.plumber.yaml", "legacy.plumber.yaml.bak"),
	run("config-migrate-up-to-date", 0, "config", "migrate", "--input", "overlay.plumber.yaml").with("overlay.plumber.yaml"),

	// score-compare (hidden).
	run("score-compare", 0, "score-compare", "--input", "score-compare").with("score-compare"),
	run("score-compare-to-file", 0, "score-compare", "--input", "score-compare", "--output", "report.md").with("score-compare").writes("report.md"),
	run("score-compare-missing-input", 2, "score-compare"),

	// analyze inputs rejected before any request.
	run("analyze-no-provider", 2, "analyze"),
	run("analyze-bad-provider", 2, "analyze", "--provider", "bogus", "--project", "a/b"),
	run("analyze-bad-target", 2, "analyze", "notaurl::x"),
	run("analyze-github-no-token", 2, "analyze", "--provider", "github", "--project", "a/b"),
	run("analyze-gitlab-no-token", 2, "analyze", "--provider", "gitlab", "--project", "a/b", "--gitlab-url", "https://gitlab.com"),
	run("analyze-bad-min-score", 2, "analyze", "--provider", "github", "--project", "a/b", "--min-score", "Z"),
	run("analyze-bad-min-points", 2, "analyze", "--provider", "github", "--project", "a/b", "--min-points", "150"),
	run("analyze-bad-threshold", 2, "analyze", "--provider", "github", "--project", "a/b", "--threshold", "150"),
	run("analyze-bad-score-profile", 2, "analyze", "--provider", "github", "--project", "a/b", "--score-profile", "v9"),
	run("analyze-unknown-control", 2, "analyze", "--provider", "github", "--project", "a/b", "--controls", "bogusControl"),
	run("analyze-unknown-skip-control", 2, "analyze", "--provider", "github", "--project", "a/b", "--skip-controls", "bogusControl"),
	run("analyze-no-controls-with-controls", 2, "analyze", "--provider", "github", "--project", "a/b", "--no-controls", "--controls", "x"),
	run("analyze-missing-config", 2, "analyze", "--provider", "github", "--project", "a/b", "--config", "missing.yaml"),
	run("analyze-platform-plain-http", 2, "analyze", "--provider", "github", "--project", "a/b", "--platform", "http://example.com"),

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

// untested lists the inputs no row can cover, with the reason. Keep it short:
// each entry is a gap in the safety net.
var untested = map[string]string{
	"analyze --badge":               "writes a badge on the analyzed project (needs a token with api scope)",
	"analyze --mr-comment":          "posts on a merge request; only runs in a merge request pipeline",
	"analyze --score-push":          "needs a CI OIDC id-token; a local run is a no-op",
	"analyze --score-endpoint":      "only used with --score-push",
	"analyze --platform-allow-http": "needs a running Plumber platform",
}

// hiddenCommands are commands the help output does not list.
var hiddenCommands = [][]string{{"score-compare"}}

// providerSlots caps concurrent e2e rows per provider: gitlab.com throttles
// (429) as soon as two analyses run at once.
var providerSlots = map[string]chan struct{}{"github": make(chan struct{}, 2), "gitlab": make(chan struct{}, 1)}

// throttled matches a provider refusing a request for rate reasons. Such a run
// says nothing about the CLI: it fails the row instead of reaching a golden.
var throttled = regexp.MustCompile(`429 Too Many Requests|API rate limit exceeded`)

var (
	plumberBin string
	tree       []command
)

// command is one node of the binary's command tree, read from --help.
type command struct {
	path  []string
	flags map[string]string // long name -> shorthand ("" if none)
}

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "plumber-v1-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	plumberBin = filepath.Join(dir, "plumber")
	// -buildvcs=false keeps the version "dev": stable outputs, and the
	// update check (cmd/update_check.go) skips dev builds.
	build := exec.Command("go", "build", "-buildvcs=false", "-o", plumberBin, "github.com/getplumber/plumber")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build plumber:", err)
		os.Exit(1)
	}
	tree, err = readTree()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read the command tree:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestCLI(t *testing.T) {
	for _, c := range allCases() {
		t.Run(string(c.mode)+"/"+c.name, func(t *testing.T) {
			t.Parallel() // each row has its own work dir and home
			if c.mode == e2e {
				providerSlots[c.provider] <- struct{}{}
				defer func() { <-providerSlots[c.provider] }()
			}
			got := runCase(t, c)
			compareGolden(t, filepath.Join("testdata", "golden", string(c.mode), c.name+".golden"), got)
		})
	}
}

// TestCLICoverage fails when a command or a flag of the binary has no row,
// and when a golden file has no row anymore.
func TestCLICoverage(t *testing.T) {
	// Commands count only from the table: every command has a --help row.
	covered, commands := map[string]bool{}, map[string]bool{}
	for _, c := range allCases() {
		for _, k := range inputsOf(c.args) {
			covered[k] = true
		}
	}
	for _, c := range cases {
		commands[inputsOf(c.args)[0]] = true
	}
	for _, cmd := range tree {
		name := strings.Join(cmd.path, " ")
		key := strings.TrimSpace("plumber " + name)
		if len(cmd.path) > 0 && !commands[name] {
			t.Errorf("no row runs `%s`: add one to cases in v1/cli_test.go", key)
		}
		for long := range cmd.flags {
			k := strings.TrimSpace(name + " --" + long)
			if !covered[k] && untested[k] == "" {
				t.Errorf("no row uses `%s --%s`: add one to cases in v1/cli_test.go", key, long)
			}
		}
	}
	for k := range untested {
		if covered[k] {
			t.Errorf("%q is covered by a row now: remove it from untested", k)
		}
	}

	want := map[string]bool{}
	for _, c := range allCases() {
		want[filepath.Join(string(c.mode), c.name+".golden")] = true
	}
	_ = filepath.Walk(filepath.Join("testdata", "golden"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join("testdata", "golden"), p)
		if !want[rel] {
			if *update {
				return os.Remove(p)
			}
			t.Errorf("%s has no row anymore: delete it or run with UPDATE=1", p)
		}
		return nil
	})
}

// allCases is the table plus a --help row for every command of the tree.
func allCases() []cliCase {
	out := append([]cliCase(nil), cases...)
	for _, cmd := range tree {
		name := "help-flag"
		if len(cmd.path) > 0 {
			name += "-" + strings.Join(cmd.path, "-")
		}
		out = append(out, run(name, 0, append(append([]string(nil), cmd.path...), "--help")...))
	}
	return out
}

// inputsOf returns the inputs a call exercises: its command path ("config
// view") and each flag ("config view --explain"), shorthands resolved.
func inputsOf(args []string) []string {
	var path []string
	byPath := map[string]command{}
	for _, c := range tree {
		byPath[strings.Join(c.path, " ")] = c
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		next := strings.TrimSpace(strings.Join(append(append([]string(nil), path...), a), " "))
		if _, ok := byPath[next]; !ok {
			break
		}
		path = append(path, a)
	}
	name := strings.Join(path, " ")
	if len(path) > 0 && path[0] == "help" { // `plumber help analyze` runs help, not analyze
		name = "help"
	}
	cmd, root := byPath[name], byPath[""]
	out := []string{name}
	for _, a := range args {
		var long string
		switch {
		case strings.HasPrefix(a, "--"):
			long = strings.SplitN(strings.TrimPrefix(a, "--"), "=", 2)[0]
		case strings.HasPrefix(a, "-") && len(a) == 2:
			for l, s := range cmd.flags {
				if s == a[1:] {
					long = l
				}
			}
			for l, s := range root.flags {
				if s == a[1:] && long == "" {
					long = l
				}
			}
		}
		if long == "" {
			continue
		}
		if _, ok := cmd.flags[long]; !ok {
			if _, global := root.flags[long]; global {
				out = append(out, "--"+long)
				continue
			}
		}
		out = append(out, strings.TrimSpace(name+" --"+long))
	}
	return out
}

var (
	commandLine = regexp.MustCompile(`^  (\S+)\s{2,}`)
	flagLine    = regexp.MustCompile(`^\s+(?:-(\w), )?--([\w-]+)`)
)

// readTree reads the command tree from the --help output of every command.
func readTree() ([]command, error) {
	var out []command
	queue := append([][]string{{}}, hiddenCommands...)
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		help, err := exec.Command(plumberBin, append(append([]string(nil), path...), "--help")...).Output()
		if err != nil {
			return nil, fmt.Errorf("plumber %s --help: %w", strings.Join(path, " "), err)
		}
		cmd := command{path: path, flags: map[string]string{}}
		section := ""
		for _, line := range strings.Split(string(help), "\n") {
			switch {
			case strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " "):
				section = line
			case section == "Available Commands:":
				if m := commandLine.FindStringSubmatch(line); m != nil {
					queue = append(queue, append(append([]string(nil), path...), m[1]))
				}
			case section == "Flags:":
				if m := flagLine.FindStringSubmatch(line); m != nil {
					cmd.flags[m[2]] = m[1]
				}
			}
		}
		out = append(out, cmd)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Join(out[i].path, " ") < strings.Join(out[j].path, " ") })
	return out, nil
}

// runCase runs the setup calls and the call under test in a fresh work dir
// and home, and returns the normalized transcript: exit code, stdout, stderr
// and the files the call wrote.
func runCase(t *testing.T, c cliCase) string {
	t.Helper()
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	work, home := filepath.Join(root, "work"), filepath.Join(root, "home")
	for _, d := range []string{work, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, in := range c.inputs {
		copyPath(t, filepath.Join("testdata", "inputs", in), filepath.Join(work, in))
	}

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"GH_CONFIG_DIR=" + filepath.Join(home, "gh"), // no `gh auth token` fallback
		"TMPDIR=" + root,
		"TERM=dumb",
	}
	switch c.mode {
	case local:
		env = append(env, "HTTPS_PROXY="+closedPort, "HTTP_PROXY="+closedPort, "ALL_PROXY="+closedPort, "NO_PROXY=")
	case e2e:
		token := e2eToken(c.provider)
		if token == "" {
			msg := fmt.Sprintf("no %s token: set PLUMBER_E2E_%s_TOKEN", c.provider, strings.ToUpper(c.provider))
			if os.Getenv("PLUMBER_E2E_REQUIRED") != "" {
				t.Fatal(msg)
			}
			t.Skip(msg)
		}
		env = append(env, strings.ToUpper(c.provider)+"_TOKEN="+token)
		if c.clone != "" {
			repo := map[string]string{"github": "https://" + githubTarget + ".git", "gitlab": "https://" + gitlabTarget + ".git"}[c.provider]
			clone := exec.Command("git", "clone", "--quiet", "--depth", "1", "--branch", c.clone, repo, filepath.Join(work, "repo"))
			if out, err := clone.CombinedOutput(); err != nil {
				t.Fatalf("clone %s@%s: %v\n%s", repo, c.clone, err, out)
			}
			work = filepath.Join(work, "repo")
		}
	}
	env = append(env, c.env...)

	for _, args := range c.setup {
		if _, _, code := plumber(work, env, args); code != 0 && c.mode == local {
			t.Fatalf("setup `plumber %s` exited %d", strings.Join(args, " "), code)
		}
	}
	stdout, stderr, code := plumber(work, env, c.args)
	for attempt := 1; throttled.MatchString(stdout + stderr); attempt++ {
		if attempt > 3 {
			t.Fatalf("%s kept throttling the run (rate limit): rerun later, nothing was compared\n%s", c.provider, throttled.FindString(stdout+stderr))
		}
		t.Logf("%s throttled the run, retrying in a minute (%d/3)", c.provider, attempt)
		time.Sleep(time.Minute)
		stdout, stderr, code = plumber(work, env, c.args)
	}
	if c.sorted {
		stdout, stderr = sortLines(stdout), sortLines(stderr)
	}
	if code != c.wantExit {
		t.Errorf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", code, c.wantExit, stdout, stderr)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "$ plumber %s\nexit: %d\n--- stdout\n%s\n--- stderr\n%s\n", strings.Join(c.args, " "), code, stdout, stderr)
	for _, f := range c.files {
		data, err := os.ReadFile(filepath.Join(work, f))
		if err != nil {
			t.Errorf("expected file %s: %v", f, err)
			continue
		}
		fmt.Fprintf(&b, "--- file %s\n%s\n", f, data)
	}
	return normalize(b.String(), work, home, root)
}

func sortLines(s string) string {
	lines := strings.Split(s, "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func plumber(dir string, env, args []string) (stdout, stderr string, code int) {
	cmd := exec.Command(plumberBin, args...)
	cmd.Dir, cmd.Env = dir, env
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return o.String(), e.String(), ee.ExitCode()
		}
		return o.String(), e.String() + err.Error(), -1
	}
	return o.String(), e.String(), 0
}

func e2eToken(provider string) string {
	names := map[string][]string{
		"github": {"PLUMBER_E2E_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"},
		"gitlab": {"PLUMBER_E2E_GITLAB_TOKEN", "GITLAB_TOKEN"},
	}[provider]
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

var (
	timestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?`)
	urnUUID   = regexp.MustCompile(`urn:uuid:[0-9a-f-]{36}`) // CycloneDX serialNumber, random per run
	epochMs   = regexp.MustCompile(`\b1[78]\d{11}\b`)        // epoch milliseconds, 2023-2033 (OCSF time, correlation_uid)
	// A provider throttling a request (429) and the CLI retrying it is
	// transport noise, not CLI behavior.
	retryLine = regexp.MustCompile(`(?m)^time=\S+ level=warning msg="Retrying GitLab API request due to rate limit or error".*\n`)
)

// normalize replaces what changes from one run to the next: temp paths,
// timestamps and retried requests.
func normalize(s, work, home, root string) string {
	cache := filepath.Join(home, ".cache")
	if runtime.GOOS == "darwin" {
		cache = filepath.Join(home, "Library", "Caches")
	}
	s = strings.NewReplacer(cache, "<CACHE>", work, "<WORK>", home, "<HOME>", root, "<TMP>").Replace(s)
	s = timestamp.ReplaceAllString(s, "<TIME>")
	s = epochMs.ReplaceAllString(s, "<EPOCH>")
	s = urnUUID.ReplaceAllString(s, "urn:uuid:<UUID>")
	return retryLine.ReplaceAllString(s, "")
}

func compareGolden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no golden file %s: run `make test-integration UPDATE=1` (or test-e2e) and review it", path)
	}
	if string(want) == got {
		return
	}
	wl, gl := strings.Split(string(want), "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			t.Errorf("output differs from %s at line %d:\n  want: %q\n  got:  %q\nrefresh on purpose with UPDATE=1 and review the diff", path, i+1, w, g)
			return
		}
	}
}

func copyPath(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
