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

	out := FilterFindingsByEnabledControls(findings, "gitlab", &pc.Controls)
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
	out := FilterFindingsByEnabledControls(findings, "gitlab", nil)
	if len(out) != len(findings) {
		t.Fatalf("expected all findings preserved when pc is nil, got %d", len(out))
	}
}
