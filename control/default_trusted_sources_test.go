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

// The shipped baseline trusts the Dependabot and Plumber action owners for
// ISSUE-713 (actions must come from authorized sources): a SHA-pinned
// dependabot/fetch-metadata (the most common Dependabot auto-merge step) or
// getplumber/plumber is never flagged, while a third owner pinned the same
// way in the same run still is, proving the control was active.
func TestDefaultConfig_TrustsDependabotAndPlumberActionOwners(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "built-in default")
	if err != nil {
		t.Fatalf("load embedded default: %v", err)
	}
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	const sha = "@dbb049abf0d677abbd7f7eee0375145b417fdd34"
	trusted := map[string]bool{"dependabot/fetch-metadata" + sha: true, "getplumber/plumber" + sha: true}
	third := "some-owner/some-action" + sha
	var uses []ir.Action
	for u := range trusted {
		uses = append(uses, ir.Action{Uses: u})
	}
	uses = append(uses, ir.Action{Uses: third})
	pipeline := &ir.NormalizedPipeline{
		Provider:    ir.ProviderGitHub,
		ProjectPath: "example-org/example-repo",
		Jobs:        []ir.Job{{Name: "auto-merge", Permissions: map[string]any{"contents": "write"}, Uses: uses}},
	}
	cfg := buildEngineConfig(pc.ControlsFor("github"))
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	var flagged []string
	for _, f := range findings {
		if f.Code == "ISSUE-713" {
			flagged = append(flagged, f.Data["uses"].(string))
		}
	}
	if len(flagged) != 1 || flagged[0] != third {
		t.Fatalf("want only the third owner flagged by ISSUE-713, got %v", flagged)
	}
}
