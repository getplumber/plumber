package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/spf13/cobra"
)

// loadConfigOrOffer — non-interactive paths (no TTY in CI or test runner).
//
// The interactive survey branch cannot be unit-tested without mocking the
// survey library; the paths below cover the three deterministic code paths:
//  1. Config file exists → loaded successfully, no prompt.
//  2. Config file missing, non-interactive → error with actionable hint.
//  3. Config file present but invalid YAML → configuration error (not a
//     "file not found" variant, so the offer logic is bypassed).

// ---------------------------------------------------------------------------
// validateProviderFlags
// ---------------------------------------------------------------------------

func TestValidateProviderFlags_MutuallyExclusiveURLs(t *testing.T) {
	err := validateProviderFlags(analyzeFlags{gitlabURLFromFlag: true, githubURLFromFlag: true})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

func TestValidateProviderFlags_InvalidProvider(t *testing.T) {
	orig := providerFlag
	providerFlag = "bitbucket"
	defer func() { providerFlag = orig }()

	err := validateProviderFlags(analyzeFlags{})
	if err == nil || !strings.Contains(err.Error(), "--provider must be") {
		t.Fatalf("expected invalid provider error, got %v", err)
	}
}

func TestValidateProviderFlags_GitlabProviderWithGithubURL(t *testing.T) {
	orig := providerFlag
	providerFlag = "gitlab"
	defer func() { providerFlag = orig }()

	err := validateProviderFlags(analyzeFlags{githubURLFromFlag: true})
	if err == nil || !strings.Contains(err.Error(), "conflicts with --github-url") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestValidateProviderFlags_GithubProviderWithGitlabURL(t *testing.T) {
	orig := providerFlag
	providerFlag = "github"
	defer func() { providerFlag = orig }()

	err := validateProviderFlags(analyzeFlags{gitlabURLFromFlag: true})
	if err == nil || !strings.Contains(err.Error(), "conflicts with --gitlab-url") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestValidateProviderFlags_Valid(t *testing.T) {
	orig := providerFlag
	defer func() { providerFlag = orig }()

	for _, pf := range []string{"", "github", "gitlab"} {
		providerFlag = pf
		if err := validateProviderFlags(analyzeFlags{}); err != nil {
			t.Errorf("provider=%q: unexpected error: %v", pf, err)
		}
	}
}

// ---------------------------------------------------------------------------
// parseControlsFilters
// ---------------------------------------------------------------------------

func TestParseControlsFilters_BothSet(t *testing.T) {
	origInclude, origSkip := controlsFilter, skipControls
	controlsFilter, skipControls = "a", "b"
	defer func() { controlsFilter, skipControls = origInclude, origSkip }()

	_, _, err := parseControlsFilters()
	if err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestParseControlsFilters_IncludeOnly(t *testing.T) {
	origInclude, origSkip := controlsFilter, skipControls
	controlsFilter = "pipelineMustNotEnableDebugTrace,containerImageMustNotUseForbiddenTags"
	skipControls = ""
	defer func() { controlsFilter, skipControls = origInclude, origSkip }()

	include, skip, err := parseControlsFilters()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(include) != 2 {
		t.Fatalf("include: got %v", include)
	}
	if len(skip) != 0 {
		t.Fatalf("skip: expected empty, got %v", skip)
	}
}

func TestParseControlsFilters_SkipOnly(t *testing.T) {
	origInclude, origSkip := controlsFilter, skipControls
	controlsFilter = ""
	skipControls = "pipelineMustNotEnableDebugTrace"
	defer func() { controlsFilter, skipControls = origInclude, origSkip }()

	include, skip, err := parseControlsFilters()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(include) != 0 {
		t.Fatalf("include: expected empty, got %v", include)
	}
	if len(skip) != 1 || skip[0] != "pipelineMustNotEnableDebugTrace" {
		t.Fatalf("skip: got %v", skip)
	}
}

// ---------------------------------------------------------------------------
// issueTableCells
// ---------------------------------------------------------------------------

func TestIssueTableCells_Skipped(t *testing.T) {
	ctrl := controlSummary{skipped: true, issues: 3, codes: []string{"ISSUE-101"}}
	codes, sev, issue := issueTableCells(ctrl)
	if codes != "-" {
		t.Fatalf("skipped codes: want '-', got %q", codes)
	}
	if issue != "-" {
		t.Fatalf("skipped issue count: want '-', got %q", issue)
	}
	_ = sev
}

func TestIssueTableCells_WithIssues(t *testing.T) {
	ctrl := controlSummary{
		skipped:    false,
		issues:     2,
		codes:      []string{"ISSUE-101", "ISSUE-102"},
		bySeverity: control.SeverityCounts{High: 2},
	}
	codes, _, issue := issueTableCells(ctrl)
	if codes != "ISSUE-101, ISSUE-102" {
		t.Fatalf("codes: got %q", codes)
	}
	if issue != "2" {
		t.Fatalf("issue count: got %q", issue)
	}
}

func TestIssueTableCells_NoSeverity(t *testing.T) {
	ctrl := controlSummary{
		skipped:    false,
		issues:     1,
		codes:      []string{"ISSUE-101"},
		bySeverity: control.SeverityCounts{},
	}
	_, sev, _ := issueTableCells(ctrl)
	// Empty severity counts produce a placeholder; just assert it doesn't panic.
	_ = sev
}

// ---------------------------------------------------------------------------
// writeLegacyJSONValue
// ---------------------------------------------------------------------------

func TestWriteLegacyJSONValue_Scalar(t *testing.T) {
	var buf bytes.Buffer
	if err := writeLegacyJSONValue(&buf, "k", 42, "  "); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "42" {
		t.Fatalf("scalar: got %q", buf.String())
	}
}

func TestWriteLegacyJSONValue_String(t *testing.T) {
	var buf bytes.Buffer
	if err := writeLegacyJSONValue(&buf, "k", "hello", "  "); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != `"hello"` {
		t.Fatalf("string: got %q", buf.String())
	}
}

func TestWriteLegacyJSONValue_SingleLineObject(t *testing.T) {
	var buf bytes.Buffer
	if err := writeLegacyJSONValue(&buf, "k", map[string]any{"a": 1}, "  "); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "{") {
		t.Fatalf("object: expected leading '{', got %q", out)
	}
}

func TestWriteLegacyJSONValue_MultiLineObject(t *testing.T) {
	var buf bytes.Buffer
	obj := map[string]any{"alpha": 1, "beta": 2}
	if err := writeLegacyJSONValue(&buf, "k", obj, "  "); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "{") || !strings.HasSuffix(out, "}") {
		t.Fatalf("object: want {…}, got %q", out)
	}
}

func TestWriteLegacyJSONValue_Array(t *testing.T) {
	var buf bytes.Buffer
	if err := writeLegacyJSONValue(&buf, "k", []int{1, 2, 3}, "  "); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "[") {
		t.Fatalf("array: expected leading '[', got %q", out)
	}
}

// ---------------------------------------------------------------------------
// LoadConfigOrOffer
// ---------------------------------------------------------------------------

func TestLoadConfigOrOffer_FileExists(t *testing.T) {
	// Write a minimal valid .plumber.yaml to a temp dir.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".plumber.yaml")
	content := "version: \"2.0\"\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	pc, path, warnings, err := loadConfigOrOffer(cfgPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil PlumberConfig")
	}
	if path != cfgPath {
		t.Fatalf("path: got %q, want %q", path, cfgPath)
	}
	_ = warnings // may be non-empty for a minimal config, that's fine
}

func TestLoadConfigOrOffer_ExplicitMissingFile_Errors(t *testing.T) {
	// A --config path the user named explicitly (configExplicit=true) must
	// still fail when absent — we don't silently swap in the default for a
	// file they asked for.
	t.Setenv("CI", "true")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nonexistent.yaml")

	_, _, _, err := loadConfigOrOffer(cfgPath, true)
	if err == nil {
		t.Fatal("expected an error for an explicitly-requested missing config file")
	}
	msg := err.Error()
	if !strings.Contains(msg, "configuration file not found") {
		t.Errorf("error should mention 'configuration file not found', got: %s", msg)
	}
	if !strings.Contains(msg, "plumber config generate") || !strings.Contains(msg, "plumber config init") {
		t.Errorf("error should include generation hint, got: %s", msg)
	}
}

func TestLoadConfigOrOffer_MissingDefault_FallsBackToEmbedded(t *testing.T) {
	// No local file and no explicit --config (configExplicit=false), non-
	// interactive: instead of failing, fall back to the binary's embedded
	// default so a zero-config scan still runs (getplumber/plumber#326).
	t.Setenv("CI", "true")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".plumber.yaml") // does not exist

	pc, path, _, err := loadConfigOrOffer(cfgPath, false)
	if err != nil {
		t.Fatalf("expected fallback to the embedded default, got error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil PlumberConfig from the embedded default")
	}
	if path != builtinDefaultConfigSource {
		t.Errorf("path: got %q, want %q", path, builtinDefaultConfigSource)
	}
	// The embedded default is a real config: it should carry provider sections.
	if pc.GitHub == nil && pc.GitLab == nil {
		t.Error("embedded default should populate at least one provider section")
	}
}

// The GitLab CI component passes the config path via PLUMBER_ANALYZE_CONFIG,
// not a --config flag. That env value must count as an EXPLICIT config, so a
// missing path hard-fails instead of silently falling back to the embedded
// default. This drives the exact wiring runAnalyze uses — apply the env
// fallback, then derive configExplicitlySet from cmd.Flags().Changed("config")
// — so a refactor that drops the Flags().Set side effect in envStringFallback
// (or reorders the assignment) is caught here rather than shipping a
// misconfigured CI job that scans with default rules.
func TestConfigExplicit_FromEnvVar_MissingPathHardFails(t *testing.T) {
	origFile, origExplicit := configFile, configExplicitlySet
	defer func() { configFile, configExplicitlySet = origFile, origExplicit }()

	missing := filepath.Join(t.TempDir(), "from-env.yaml")
	t.Setenv(envKeys["config"], missing) // PLUMBER_ANALYZE_CONFIG=<missing>

	cmd := &cobra.Command{Use: "analyze"}
	cmd.Flags().StringVar(&configFile, "config", ".plumber.yaml", "")

	if err := envStringFallback(cmd, "config", envKeys["config"], &configFile); err != nil {
		t.Fatalf("envStringFallback: %v", err)
	}
	configExplicitlySet = cmd.Flags().Changed("config")
	if !configExplicitlySet {
		t.Fatal("PLUMBER_ANALYZE_CONFIG must make --config count as explicit")
	}
	if configFile != missing {
		t.Fatalf("configFile = %q, want %q", configFile, missing)
	}

	_, _, _, err := loadConfigOrOffer(configFile, configExplicitlySet)
	if err == nil {
		t.Fatal("an env-provided missing config must hard-fail, not fall back to the default")
	}
	if !strings.Contains(err.Error(), "configuration file not found") {
		t.Errorf("want 'configuration file not found', got: %v", err)
	}
}

func TestLoadConfigOrOffer_InvalidYAML_NonInteractive(t *testing.T) {
	t.Setenv("CI", "true")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".plumber.yaml")
	if err := os.WriteFile(cfgPath, []byte(":\tinvalid: yaml: [\n"), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	_, _, _, err := loadConfigOrOffer(cfgPath, false)
	if err == nil {
		t.Fatal("expected an error for invalid YAML")
	}
	// Must be a configuration error, not a "file not found" hint.
	msg := err.Error()
	if !strings.Contains(msg, "configuration error") {
		t.Errorf("error should mention 'configuration error', got: %s", msg)
	}
}
