package control

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

func spBoolPtr(b bool) *bool    { return &b }
func spIntPtr(i int) *int       { return &i }
func spStrPtr(s string) *string { return &s }

func spConf(c *configuration.SecurityPolicyControlConfig) *configuration.Configuration {
	return &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
		GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			ProjectMustHaveSecurityPolicySource: c,
		}},
	}}
}

// securityPolicyControlEnabled gates the protection collection for a
// security-policy-only run: wrongly false means the linkage is never fetched
// and ISSUE-601 silently reports not-evaluable on every run.
func TestSecurityPolicyControlEnabled(t *testing.T) {
	if securityPolicyControlEnabled(&configuration.Configuration{}) {
		t.Fatal("expected false when PlumberConfig is nil")
	}
	if securityPolicyControlEnabled(spConf(nil)) {
		t.Fatal("expected false when the control is not configured")
	}
	if securityPolicyControlEnabled(spConf(&configuration.SecurityPolicyControlConfig{Enabled: spBoolPtr(false)})) {
		t.Fatal("expected false when disabled")
	}
	if !securityPolicyControlEnabled(spConf(&configuration.SecurityPolicyControlConfig{Enabled: spBoolPtr(true)})) {
		t.Fatal("expected true when enabled")
	}
	skipped := spConf(&configuration.SecurityPolicyControlConfig{Enabled: spBoolPtr(true)})
	skipped.SkipControlsFilter = []string{controlSecurityPolicy}
	if securityPolicyControlEnabled(skipped) {
		t.Fatal("expected false when in --skip-controls")
	}

	// protectionDataNeeded must be true for a security-policy-only run so the
	// protection collection (which carries the linkage) actually runs.
	if !protectionDataNeeded(spConf(&configuration.SecurityPolicyControlConfig{Enabled: spBoolPtr(true)})) {
		t.Fatal("expected protectionDataNeeded true when only the security-policy control is enabled")
	}
}

// securityPolicyTierCaveatApplies composes the enabled gate with the
// linkage-read state: it fires only when the linkage was read and nothing is
// linked. A wrong-project read (a real misconfig on a paid tier) and a
// not-read state must not trigger it.
func TestSecurityPolicyTierCaveatApplies(t *testing.T) {
	enabled := spConf(&configuration.SecurityPolicyControlConfig{Enabled: spBoolPtr(true)})
	disabled := spConf(&configuration.SecurityPolicyControlConfig{Enabled: spBoolPtr(false)})

	noneLinked := &gitlab.GitlabProtectionAnalysisData{SecurityPolicyKnown: true, SecurityPolicyProject: nil}
	linked := &gitlab.GitlabProtectionAnalysisData{SecurityPolicyKnown: true, SecurityPolicyProject: &gitlab.SecurityPolicyProjectLink{ID: 5}}
	notRead := &gitlab.GitlabProtectionAnalysisData{SecurityPolicyKnown: false}

	if securityPolicyTierCaveatApplies(disabled, noneLinked) {
		t.Fatal("caveat must NOT fire when the control is disabled")
	}
	if !securityPolicyTierCaveatApplies(enabled, noneLinked) {
		t.Fatal("caveat must fire when enabled, read, and nothing linked")
	}
	if securityPolicyTierCaveatApplies(enabled, linked) {
		t.Fatal("caveat must NOT fire when a project is linked (paid tier, real misconfig)")
	}
	if securityPolicyTierCaveatApplies(enabled, notRead) {
		t.Fatal("caveat must NOT fire when the linkage was not read (not-evaluable)")
	}
	if securityPolicyTierCaveatApplies(enabled, nil) {
		t.Fatal("caveat must NOT fire when there is no protection data")
	}
}

// TestSecurityPolicyConfigContract pins the struct -> map -> rego chain for
// ISSUE-601: buildEngineConfig emits expectedProjectId only when set, and the
// rego reads exactly that key, so a rename on either side would silently make
// the control assert only "any linkage" forever.
func TestSecurityPolicyConfigContract(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	fires := func(linkedID int, cfg map[string]any) bool {
		p := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, SecurityPolicyProject: &ir.SecurityPolicyProjectState{Known: true, LinkedProjectID: linkedID}}
		findings, err := engine.Evaluate(context.Background(), p, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-601" {
				return true
			}
		}
		return false
	}

	// expectedProjectId set via the REAL projection: a mismatch fires, a match does not.
	cfgExpect := buildEngineConfig(&configuration.ControlsConfig{
		ProjectMustHaveSecurityPolicySource: &configuration.SecurityPolicyControlConfig{
			Enabled: spBoolPtr(true), ExpectedProjectId: spIntPtr(9),
		},
	})
	if _, ok := cfgExpect["projectMustHaveSecurityPolicySource"]; !ok {
		t.Fatal("buildEngineConfig did not project a projectMustHaveSecurityPolicySource block")
	}
	if !fires(5, cfgExpect) {
		t.Fatal("expected id 9, linked 5: expected ISSUE-601 to fire")
	}
	if fires(9, cfgExpect) {
		t.Fatal("expected id 9, linked 9: expected no ISSUE-601")
	}

	// expectedProjectId unset -> require any linkage: nothing linked fires, a linked project passes.
	cfgAny := buildEngineConfig(&configuration.ControlsConfig{
		ProjectMustHaveSecurityPolicySource: &configuration.SecurityPolicyControlConfig{Enabled: spBoolPtr(true)},
	})
	if !fires(0, cfgAny) {
		t.Fatal("require-any, nothing linked: expected ISSUE-601 to fire")
	}
	if fires(7, cfgAny) {
		t.Fatal("require-any, a project linked: expected no ISSUE-601")
	}

	// expectedProjectPath via the REAL projection: case-insensitive path match.
	firesPath := func(linkedPath string, cfg map[string]any) bool {
		p := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, SecurityPolicyProject: &ir.SecurityPolicyProjectState{Known: true, LinkedProjectID: 5, LinkedProjectPath: linkedPath}}
		findings, err := engine.Evaluate(context.Background(), p, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-601" {
				return true
			}
		}
		return false
	}
	cfgPath := buildEngineConfig(&configuration.ControlsConfig{
		ProjectMustHaveSecurityPolicySource: &configuration.SecurityPolicyControlConfig{
			Enabled: spBoolPtr(true), ExpectedProjectPath: spStrPtr("Grp/Policies"),
		},
	})
	if firesPath("grp/policies", cfgPath) {
		t.Fatal("path match (case-insensitive): expected no ISSUE-601")
	}
	if !firesPath("grp/other", cfgPath) {
		t.Fatal("path mismatch: expected ISSUE-601 to fire")
	}
}
