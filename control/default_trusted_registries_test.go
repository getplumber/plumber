package control

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestDefaultConfig_TrustsMicrosoftArtifactRegistry pins the shipped
// baseline's authorized-sources behavior end to end (embedded default ->
// engine config -> the ISSUE-101 policy): ANY image from
// mcr.microsoft.com is trusted, because only Microsoft can publish
// there (operator ruling 2026-09-28), while an unknown registry in the
// same run is still flagged, proving the control was active. The image
// is deliberately outside the product scopes the list used to carry
// (dotnet, playwright, powershell), so this fails on the old
// product-scoped entries and passes only with the host-wide one.
func TestDefaultConfig_TrustsMicrosoftArtifactRegistry(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "built-in default")
	if err != nil {
		t.Fatalf("load embedded default: %v", err)
	}
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "azcli", Image: &ir.Image{Registry: "mcr.microsoft.com", Name: "azure-cli", Tag: "2.64.0"}},
			{Name: "evil", Image: &ir.Image{Registry: "evil.example.com", Name: "x", Tag: "1"}},
		},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, buildEngineConfig(pc.ControlsFor("gitlab")))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	var flagged []string
	for _, f := range findings {
		if f.Code == "ISSUE-101" {
			flagged = append(flagged, f.Job)
		}
	}
	if len(flagged) != 1 || flagged[0] != "evil" {
		t.Fatalf("want exactly the unknown registry flagged (evil), got %v", flagged)
	}
}
