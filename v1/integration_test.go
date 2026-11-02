//go:build cli

package v1

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// localCases are the rows that make no backend request: one row per CLI
// input. TestIntegration adds a --help row for every command of the tree.
var localCases = []cliCase{
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
}

// untested lists the inputs no row can cover, with the reason. No test covers
// these inputs, so add one only when a row cannot be written.
var untested = map[string]string{
	"analyze --badge":               "writes a badge on the analyzed project (needs a token with api scope)",
	"analyze --mr-comment":          "posts on a merge request; only runs in a merge request pipeline",
	"analyze --score-push":          "needs a CI OIDC id-token; a local run is a no-op",
	"analyze --score-endpoint":      "only used with --score-push",
	"analyze --platform-allow-http": "needs a running Plumber platform",

	// Only an analysis that reaches a provider uses these flags. The e2e
	// suite (monorepo#651) covers them.
	"analyze --branch":         needsProvider,
	"analyze --ci-config-path": needsProvider,
	"analyze --csv":            needsProvider,
	"analyze --fail-warnings":  needsProvider,
	"analyze --github-url":     needsProvider,
	"analyze --glsast":         needsProvider,
	"analyze --ocsf":           needsProvider,
	"analyze --output":         needsProvider,
	"analyze --pbom":           needsProvider,
	"analyze --pbom-cyclonedx": needsProvider,
	"analyze --print":          needsProvider,
	"analyze --sarif":          needsProvider,
	"analyze --score":          needsProvider,
	"analyze --score-point":    needsProvider,
}

// needsProvider is the untested reason of a flag only an analysis that
// reaches GitHub or GitLab uses.
const needsProvider = "needs a provider: covered by the e2e suite (monorepo#651)"

// hiddenCommands are commands the help output does not list.
var hiddenCommands = [][]string{{"score-compare"}}

func TestIntegration(t *testing.T) {
	runCases(t, append(append([]cliCase(nil), localCases...), helpCases()...))
}

// TestCoverage fails when a command or a flag of the binary has no row, and
// when a golden file has no row anymore.
func TestCoverage(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range allCases() {
		for _, k := range inputsOf(c.args) {
			covered[k] = true
		}
	}
	// Commands count only from localCases, since every command has a
	// generated --help row.
	commands := map[string]bool{}
	for _, c := range localCases {
		commands[inputsOf(c.args)[0]] = true
	}
	for _, cmd := range tree {
		name := strings.Join(cmd.path, " ")
		key := strings.TrimSpace("plumber " + name)
		if len(cmd.path) > 0 && !commands[name] {
			t.Errorf("no row runs `%s`: add one to localCases in v1/integration_test.go", key)
		}
		for long := range cmd.flags {
			k := strings.TrimSpace(name + " --" + long)
			if !covered[k] && untested[k] == "" {
				t.Errorf("no row uses `%s --%s`: add one to localCases in v1/integration_test.go", key, long)
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
	goldenDir := filepath.Join("testdata", "golden")
	err := filepath.WalkDir(goldenDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(goldenDir, p)
		if err != nil {
			return err
		}
		if want[rel] {
			return nil
		}
		if *update {
			return os.Remove(p)
		}
		t.Errorf("%s has no row anymore: delete it or run with UPDATE=1", p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", goldenDir, err)
	}
}
