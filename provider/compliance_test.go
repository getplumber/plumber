package provider

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func boolPtr(b bool) *bool { return &b }

// gitLabPC builds a PlumberConfig whose GitLab provider enables exactly
// the two controls exercised below (image-forbidden-tags and
// branch-must-be-protected) so the considered-control count is
// predictable regardless of catalog growth.
func gitLabPC(t *testing.T) *configuration.PlumberConfig {
	t.Helper()
	return &configuration.PlumberConfig{
		GitLab: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				ContainerImageMustNotUseForbiddenTags: &configuration.ImageForbiddenTagsControlConfig{Enabled: boolPtr(true)},
				BranchMustBeProtected:                 &configuration.BranchProtectionControlConfig{Enabled: boolPtr(true)},
			},
		},
	}
}

// gitHubPC enables two GitHub controls (forbidden-tags and
// actions-must-be-pinned) under the github provider block.
func gitHubPC(t *testing.T) *configuration.PlumberConfig {
	t.Helper()
	return &configuration.PlumberConfig{
		GitHub: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				ContainerImageMustNotUseForbiddenTags: &configuration.ImageForbiddenTagsControlConfig{Enabled: boolPtr(true)},
				ActionsMustBePinnedByCommitSha:        &configuration.ActionsPinnedByShaControlConfig{Enabled: boolPtr(true)},
			},
		},
	}
}

func TestGitLabProvider_ComputeCompliance(t *testing.T) {
	p := &GitLabProvider{}

	t.Run("CI missing yields zero", func(t *testing.T) {
		result := &control.AnalysisResult{CiMissing: true, CiValid: true}
		conf := &configuration.Configuration{PlumberConfig: gitLabPC(t)}
		pct, n := p.ComputeCompliance(result, conf)
		if pct != 0.0 || n != 0 {
			t.Fatalf("CiMissing: got (%v, %d), want (0, 0)", pct, n)
		}
	})

	t.Run("CI invalid yields zero", func(t *testing.T) {
		result := &control.AnalysisResult{CiValid: false}
		conf := &configuration.Configuration{PlumberConfig: gitLabPC(t)}
		pct, n := p.ComputeCompliance(result, conf)
		if pct != 0.0 || n != 0 {
			t.Fatalf("CiValid=false: got (%v, %d), want (0, 0)", pct, n)
		}
	})

	t.Run("all controls pass", func(t *testing.T) {
		result := &control.AnalysisResult{CiValid: true}
		conf := &configuration.Configuration{PlumberConfig: gitLabPC(t)}
		pct, n := p.ComputeCompliance(result, conf)
		if pct != 100.0 || n != 2 {
			t.Fatalf("no findings: got (%v, %d), want (100, 2)", pct, n)
		}
	})

	t.Run("one of two controls fails", func(t *testing.T) {
		result := &control.AnalysisResult{
			CiValid: true,
			Findings: []opaengine.Finding{
				{Code: string(control.CodeImageForbiddenTag)},
			},
		}
		conf := &configuration.Configuration{PlumberConfig: gitLabPC(t)}
		pct, n := p.ComputeCompliance(result, conf)
		// Binary per-control: 1 passed of 2 considered -> 50%.
		if pct != 50.0 || n != 2 {
			t.Fatalf("one finding: got (%v, %d), want (50, 2)", pct, n)
		}
	})

	t.Run("multiple findings on same control count once", func(t *testing.T) {
		result := &control.AnalysisResult{
			CiValid: true,
			Findings: []opaengine.Finding{
				{Code: string(control.CodeImageForbiddenTag)},
				{Code: string(control.CodeImageForbiddenTag)},
			},
		}
		conf := &configuration.Configuration{PlumberConfig: gitLabPC(t)}
		pct, n := p.ComputeCompliance(result, conf)
		// Still 1 failing control of 2 -> 50%.
		if pct != 50.0 || n != 2 {
			t.Fatalf("two findings same control: got (%v, %d), want (50, 2)", pct, n)
		}
	})

	t.Run("no controls considered yields zero", func(t *testing.T) {
		// Empty config: ControlsFor("gitlab") returns a zero ControlsConfig,
		// so every control is skipped (absent) -> controlCount == 0.
		result := &control.AnalysisResult{CiValid: true}
		conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
		pct, n := p.ComputeCompliance(result, conf)
		if pct != 0.0 || n != 0 {
			t.Fatalf("no controls: got (%v, %d), want (0, 0)", pct, n)
		}
	})
}

func TestGitHubProvider_ComputeCompliance(t *testing.T) {
	p := &GitHubProvider{}

	t.Run("all controls pass", func(t *testing.T) {
		result := &control.AnalysisResult{}
		conf := &configuration.Configuration{PlumberConfig: gitHubPC(t)}
		pct, n := p.ComputeCompliance(result, conf)
		if pct != 100.0 || n != 2 {
			t.Fatalf("no findings: got (%v, %d), want (100, 2)", pct, n)
		}
	})

	t.Run("one of two controls fails", func(t *testing.T) {
		result := &control.AnalysisResult{
			Findings: []opaengine.Finding{
				{Code: string(control.CodeActionUnpinned)},
			},
		}
		conf := &configuration.Configuration{PlumberConfig: gitHubPC(t)}
		pct, n := p.ComputeCompliance(result, conf)
		// Average of per-control compliance: (0 + 100) / 2 = 50.
		if pct != 50.0 || n != 2 {
			t.Fatalf("one finding: got (%v, %d), want (50, 2)", pct, n)
		}
	})

	t.Run("no controls considered yields full compliance", func(t *testing.T) {
		// Key divergence from GitLab: when no control is considered the
		// GitHub path returns 100, not 0.
		result := &control.AnalysisResult{}
		conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
		pct, n := p.ComputeCompliance(result, conf)
		if pct != 100.0 || n != 0 {
			t.Fatalf("no controls: got (%v, %d), want (100, 0)", pct, n)
		}
	})

	t.Run("GitHub ignores CiMissing", func(t *testing.T) {
		// Unlike GitLab, the GitHub path has no CI-missing short-circuit.
		result := &control.AnalysisResult{CiMissing: true}
		conf := &configuration.Configuration{PlumberConfig: gitHubPC(t)}
		pct, n := p.ComputeCompliance(result, conf)
		if pct != 100.0 || n != 2 {
			t.Fatalf("CiMissing ignored: got (%v, %d), want (100, 2)", pct, n)
		}
	})
}
