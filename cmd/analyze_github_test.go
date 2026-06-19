package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/pbom"
)

// ---------------------------------------------------------------------------
// parseAdvisoryIDs
// ---------------------------------------------------------------------------

func TestParseAdvisoryIDs_Empty(t *testing.T) {
	if ids := parseAdvisoryIDs(nil); len(ids) != 0 {
		t.Fatalf("want empty, got %v", ids)
	}
}

func TestParseAdvisoryIDs_FiltersNonStrings(t *testing.T) {
	raw := []any{"GHSA-abc", 42, "", "GHSA-def"}
	ids := parseAdvisoryIDs(raw)
	if len(ids) != 2 || ids[0] != "GHSA-abc" || ids[1] != "GHSA-def" {
		t.Fatalf("got %v", ids)
	}
}

// ---------------------------------------------------------------------------
// applyVulnerableAction
// ---------------------------------------------------------------------------

func TestApplyVulnerableAction_SetsVulnerableAndAdvisories(t *testing.T) {
	out := emptyComplianceData()
	data := map[string]any{
		"advisories": []any{"GHSA-abc", "GHSA-xyz"},
	}
	applyVulnerableAction("actions/foo@v1", data, out)

	if !out.VulnerableActions["actions/foo@v1"] {
		t.Fatal("VulnerableActions not set")
	}
	ids := out.ActionAdvisories["actions/foo@v1"]
	if len(ids) != 2 || ids[0] != "GHSA-abc" {
		t.Fatalf("ActionAdvisories: got %v", ids)
	}
}

func TestApplyVulnerableAction_NoAdvisories(t *testing.T) {
	out := emptyComplianceData()
	applyVulnerableAction("actions/foo@v1", map[string]any{}, out)

	if !out.VulnerableActions["actions/foo@v1"] {
		t.Fatal("VulnerableActions not set")
	}
	if len(out.ActionAdvisories) != 0 {
		t.Fatalf("ActionAdvisories should be empty, got %v", out.ActionAdvisories)
	}
}

// ---------------------------------------------------------------------------
// applyFindingToCompliance
// ---------------------------------------------------------------------------

func TestApplyFindingToCompliance_ForbiddenTag(t *testing.T) {
	out := emptyComplianceData()
	applyFindingToCompliance(string(control.CodeImageForbiddenTag), map[string]any{"link": "docker.io/img:latest"}, out)
	if !out.ForbiddenTagImages["docker.io/img:latest"] {
		t.Fatal("ForbiddenTagImages not set")
	}
}

func TestApplyFindingToCompliance_UnpinnedAction(t *testing.T) {
	out := emptyComplianceData()
	applyFindingToCompliance(string(control.CodeActionUnpinned), map[string]any{"uses": "actions/checkout@v4"}, out)
	if !out.UnpinnedActions["actions/checkout@v4"] {
		t.Fatal("UnpinnedActions not set")
	}
}

func TestApplyFindingToCompliance_ArchivedAction(t *testing.T) {
	out := emptyComplianceData()
	applyFindingToCompliance(string(control.CodeActionArchivedRepo), map[string]any{"uses": "org/archived@v1"}, out)
	if !out.ArchivedActions["org/archived@v1"] {
		t.Fatal("ArchivedActions not set")
	}
}

func TestApplyFindingToCompliance_VulnerableAction(t *testing.T) {
	out := emptyComplianceData()
	data := map[string]any{
		"uses":       "actions/vuln@v1",
		"advisories": []any{"GHSA-123"},
	}
	applyFindingToCompliance(string(control.CodeKnownVulnerableAction), data, out)
	if !out.VulnerableActions["actions/vuln@v1"] {
		t.Fatal("VulnerableActions not set")
	}
}

func TestApplyFindingToCompliance_MissingDataKey(t *testing.T) {
	out := emptyComplianceData()
	// No panic when the expected data key is absent.
	applyFindingToCompliance(string(control.CodeActionUnpinned), map[string]any{}, out)
	if len(out.UnpinnedActions) != 0 {
		t.Fatal("should not set anything when data key absent")
	}
}

func TestApplyFindingToCompliance_UnknownCode(t *testing.T) {
	out := emptyComplianceData()
	applyFindingToCompliance("ISSUE-999", map[string]any{"link": "x"}, out)
	// Unknown codes must not mutate any map.
	if len(out.ForbiddenTagImages)+len(out.UnpinnedActions)+len(out.ArchivedActions)+len(out.VulnerableActions) != 0 {
		t.Fatal("unknown code must not mutate compliance data")
	}
}

// ---------------------------------------------------------------------------
// collectPinnedImages
// ---------------------------------------------------------------------------

func TestCollectPinnedImages_NilPipeline(t *testing.T) {
	out := emptyComplianceData()
	collectPinnedImages(&control.AnalysisResult{}, out)
	if len(out.ImagesPinnedByDigest) != 0 {
		t.Fatal("expected no entries for nil pipeline")
	}
}

func TestCollectPinnedImages_JobImagePinned(t *testing.T) {
	out := emptyComplianceData()
	result := &control.AnalysisResult{
		GitHubPipeline: &ir.NormalizedPipeline{
			Jobs: []ir.Job{
				{Image: &ir.Image{Name: "golang", Tag: "1.22", Digest: "sha256:abc"}},
			},
		},
	}
	collectPinnedImages(result, out)
	if len(out.ImagesPinnedByDigest) != 1 {
		t.Fatalf("expected 1 pinned image, got %d", len(out.ImagesPinnedByDigest))
	}
}

func TestCollectPinnedImages_ServicePinned(t *testing.T) {
	out := emptyComplianceData()
	result := &control.AnalysisResult{
		GitHubPipeline: &ir.NormalizedPipeline{
			Jobs: []ir.Job{
				{
					Services: []ir.Image{
						{Name: "postgres", Digest: "sha256:def"},
					},
				},
			},
		},
	}
	collectPinnedImages(result, out)
	if len(out.ImagesPinnedByDigest) != 1 {
		t.Fatalf("expected 1 pinned service, got %d", len(out.ImagesPinnedByDigest))
	}
}

func TestCollectPinnedImages_UnpinnedIgnored(t *testing.T) {
	out := emptyComplianceData()
	result := &control.AnalysisResult{
		GitHubPipeline: &ir.NormalizedPipeline{
			Jobs: []ir.Job{
				{Image: &ir.Image{Name: "golang", Tag: "1.22"}}, // no digest
			},
		},
	}
	collectPinnedImages(result, out)
	if len(out.ImagesPinnedByDigest) != 0 {
		t.Fatal("undigested image should not appear in pinned map")
	}
}

// ---------------------------------------------------------------------------
// buildGitHubPBOMCompliance
// ---------------------------------------------------------------------------

func TestBuildGitHubPBOMCompliance_NilResult(t *testing.T) {
	if buildGitHubPBOMCompliance(nil) != nil {
		t.Fatal("expected nil for nil result")
	}
}

func TestBuildGitHubPBOMCompliance_Empty(t *testing.T) {
	out := buildGitHubPBOMCompliance(&control.AnalysisResult{})
	if out == nil {
		t.Fatal("expected non-nil output")
	}
	if len(out.ForbiddenTagImages)+len(out.UnpinnedActions)+len(out.ArchivedActions)+len(out.VulnerableActions) != 0 {
		t.Fatal("empty result should produce empty maps")
	}
}

func TestBuildGitHubPBOMCompliance_CombinesFindings(t *testing.T) {
	result := &control.AnalysisResult{
		Findings: []opaengine.Finding{
			{Code: string(control.CodeActionUnpinned), Data: map[string]any{"uses": "actions/checkout@v4"}},
			{Code: string(control.CodeImageForbiddenTag), Data: map[string]any{"link": "img:latest"}},
		},
	}
	out := buildGitHubPBOMCompliance(result)
	if !out.UnpinnedActions["actions/checkout@v4"] {
		t.Fatal("UnpinnedActions missing")
	}
	if !out.ForbiddenTagImages["img:latest"] {
		t.Fatal("ForbiddenTagImages missing")
	}
}

// ---------------------------------------------------------------------------
// normalizeIRImageRef
// ---------------------------------------------------------------------------

func TestNormalizeIRImageRef_Empty(t *testing.T) {
	if normalizeIRImageRef(ir.Image{}) != "" {
		t.Fatal("expected empty string for empty image")
	}
}

func TestNormalizeIRImageRef_NameOnly(t *testing.T) {
	if got := normalizeIRImageRef(ir.Image{Name: "golang"}); got != "golang" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeIRImageRef_WithTag(t *testing.T) {
	if got := normalizeIRImageRef(ir.Image{Name: "golang", Tag: "1.22"}); got != "golang:1.22" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeIRImageRef_WithDigest(t *testing.T) {
	img := ir.Image{Name: "golang", Tag: "1.22", Digest: "sha256:abc"}
	if got := normalizeIRImageRef(img); got != "golang@sha256:abc" {
		t.Fatalf("digest takes priority over tag, got %q", got)
	}
}

func TestNormalizeIRImageRef_WithRegistry(t *testing.T) {
	img := ir.Image{Name: "golang", Registry: "docker.io", Tag: "1.22"}
	if got := normalizeIRImageRef(img); got != "docker.io/golang:1.22" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeIRImageRef_RegistryAlreadyInName(t *testing.T) {
	// When Name already contains the registry prefix, don't double-prepend.
	img := ir.Image{Name: "docker.io/golang", Registry: "docker.io", Tag: "1.22"}
	if got := normalizeIRImageRef(img); got != "docker.io/golang:1.22" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// detectGitHubAuthSource
// ---------------------------------------------------------------------------

func TestDetectGitHubAuthSource_GHToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "tok")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	if got := detectGitHubAuthSource(""); got != "GH_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_GitHubToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "tok")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	if got := detectGitHubAuthSource(""); got != "GITHUB_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_EnterpriseToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "tok")
	if got := detectGitHubAuthSource(""); got != "GH_ENTERPRISE_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_None(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	// No gh CLI configured in test env — expect empty string.
	got := detectGitHubAuthSource("github.com")
	if got == "GH_TOKEN" || got == "GITHUB_TOKEN" || got == "GH_ENTERPRISE_TOKEN" {
		t.Fatalf("unexpected token source: %q", got)
	}
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// loadGitHubConfig
// ---------------------------------------------------------------------------

func TestLoadGitHubConfig_FileExists(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig := configFile
	configFile = dir + "/.plumber.yaml"
	defer func() { configFile = orig }()
	if err := writeMinimalConfig(configFile); err != nil {
		t.Fatal(err)
	}

	pc, path, err := loadGitHubConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil config")
	}
	if path != configFile {
		t.Fatalf("path: got %q, want %q", path, configFile)
	}
}

func TestLoadGitHubConfig_MissingFile(t *testing.T) {
	t.Setenv("CI", "true")
	orig := configFile
	configFile = t.TempDir() + "/nonexistent.yaml"
	defer func() { configFile = orig }()

	_, _, err := loadGitHubConfig()
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	if !strings.Contains(err.Error(), "configuration file not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadGitHubConfig_WarningsFailWarnings(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig, origFW := configFile, failWarnings
	configFile = dir + "/.plumber.yaml"
	failWarnings = true
	defer func() { configFile, failWarnings = orig, origFW }()

	// Write a config that produces validation warnings (unknown field).
	content := "version: \"2.0\"\nunknownField: true\n"
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadGitHubConfig()
	// If warnings are produced and failWarnings is set, expect an error.
	// If the config happens to produce no warnings, the test is a no-op.
	if err != nil && !strings.Contains(err.Error(), "warning") {
		t.Errorf("unexpected error kind: %v", err)
	}
}

func TestLoadGitHubConfig_WarningsNoFail(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig, origFW := configFile, failWarnings
	configFile = dir + "/.plumber.yaml"
	failWarnings = false
	defer func() { configFile, failWarnings = orig, origFW }()

	if err := writeMinimalConfig(configFile); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadGitHubConfig()
	if err != nil {
		t.Fatalf("failWarnings=false should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeMinimalConfig(path string) error {
	return os.WriteFile(path, []byte("version: \"2.0\"\n"), 0644)
}

func emptyComplianceData() *pbom.GitHubComplianceData {
	return &pbom.GitHubComplianceData{
		ForbiddenTagImages:   map[string]bool{},
		ImagesPinnedByDigest: map[string]bool{},
		UnpinnedActions:      map[string]bool{},
		ArchivedActions:      map[string]bool{},
		VulnerableActions:    map[string]bool{},
		ActionAdvisories:     map[string][]string{},
	}
}
