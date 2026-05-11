package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func TestFilterFindingsByEnabledControls_dropsDisabledControlFindings(t *testing.T) {
	disabled := false
	enabled := true
	pc := &configuration.PlumberConfig{
		Controls: configuration.ControlsConfig{
			ContainerImageMustNotUseForbiddenTags: &configuration.ImageForbiddenTagsControlConfig{
				Enabled: &disabled,
			},
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{
				Enabled: &enabled,
			},
		},
	}

	findings := []opaengine.Finding{
		{Code: string(CodeImageNotPinnedByDigest), Severity: "high"},
		{Code: string(CodeImageForbiddenTag), Severity: "medium"},
		{Code: string(CodeBranchUnprotected), Severity: "critical"},
		{Code: "ISSUE-9999", Severity: "low"}, // unknown, must be kept
	}

	out := FilterFindingsByEnabledControls(findings, "gitlab", &pc.Controls, nil, nil)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(out), out)
	}
	for _, f := range out {
		if f.Code == string(CodeImageNotPinnedByDigest) || f.Code == string(CodeImageForbiddenTag) {
			t.Fatalf("disabled control finding leaked through: %+v", f)
		}
	}
}

func TestFilterFindingsByEnabledControls_noConfigKeepsAll(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: string(CodeImageNotPinnedByDigest), Severity: "high"},
		{Code: string(CodeBranchUnprotected), Severity: "critical"},
	}
	out := FilterFindingsByEnabledControls(findings, "gitlab", nil, nil, nil)
	if len(out) != len(findings) {
		t.Fatalf("expected all findings preserved when pc is nil, got %d", len(out))
	}
}

func TestFilterFindingsByEnabledControls_appliesIncludeOnlyAndSkip(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: string(CodeImageNotPinnedByDigest), Severity: "high"},   // containerImageMustNotUseForbiddenTags
		{Code: string(CodeBranchUnprotected), Severity: "critical"},    // branchMustBeProtected
		{Code: string(CodeDockerInDockerUsage), Severity: "high"},      // pipelineMustNotUseDockerInDocker
	}

	// include-only: only branchMustBeProtected survives.
	out := FilterFindingsByEnabledControls(findings, "gitlab", nil, []string{"branchMustBeProtected"}, nil)
	if len(out) != 1 || out[0].Code != string(CodeBranchUnprotected) {
		t.Fatalf("include-only should keep only branchMustBeProtected, got %+v", out)
	}

	// skip: branchMustBeProtected dropped, others survive.
	out = FilterFindingsByEnabledControls(findings, "gitlab", nil, nil, []string{"branchMustBeProtected"})
	if len(out) != 2 {
		t.Fatalf("skip should drop only branchMustBeProtected, got %d", len(out))
	}
	for _, f := range out {
		if f.Code == string(CodeBranchUnprotected) {
			t.Fatalf("skipped control finding leaked through: %+v", f)
		}
	}
}

func TestControlPassesFilter(t *testing.T) {
	cases := []struct {
		name        string
		includeOnly []string
		skip        []string
		want        bool
	}{
		{"branchMustBeProtected", nil, nil, true},
		{"branchMustBeProtected", []string{"branchMustBeProtected"}, nil, true},
		{"branchMustBeProtected", []string{"otherControl"}, nil, false},
		{"branchMustBeProtected", nil, []string{"branchMustBeProtected"}, false},
		{"branchMustBeProtected", []string{"branchMustBeProtected"}, []string{"branchMustBeProtected"}, false},
	}
	for _, tc := range cases {
		got := ControlPassesFilter(tc.name, tc.includeOnly, tc.skip)
		if got != tc.want {
			t.Errorf("ControlPassesFilter(%q, includeOnly=%v, skip=%v) = %v, want %v",
				tc.name, tc.includeOnly, tc.skip, got, tc.want)
		}
	}
}

func TestMarkSkippedByFilter(t *testing.T) {
	entries := []ControlEntry{
		{ControlName: "branchMustBeProtected"},
		{ControlName: "containerImageMustNotUseForbiddenTags"},
		{ControlName: "pipelineMustNotUseDockerInDocker", Skipped: true}, // already skipped (disabled in config)
	}

	MarkSkippedByFilter(entries, nil, []string{"branchMustBeProtected"})

	if !entries[0].Skipped {
		t.Errorf("expected branchMustBeProtected to be marked skipped")
	}
	if entries[1].Skipped {
		t.Errorf("expected containerImageMustNotUseForbiddenTags to remain unskipped")
	}
	if !entries[2].Skipped {
		t.Errorf("expected already-skipped entry to remain skipped")
	}
}
