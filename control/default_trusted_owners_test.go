package control

import (
	"context"
	"sort"
	"testing"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestDefaultConfig_PinBySHATrustsOnlyGitHubOwnedActions pins the shipped
// baseline's pin-by-SHA trust boundary end to end (embedded default ->
// engine config -> the ISSUE-701 policy). The exemption list is a
// security-sensitive default: trustedOwners may hold only owners already
// inside the workflow's trust boundary, which is GitHub itself (actions,
// github, dependabot), because the runner already trusts GitHub. Every
// third-party publisher, however widely used, stays subject to the SHA
// pin: docker stands in for that class (operator ruling 2026-10-08, the
// signal-based alternative is getplumber/plumber#421). A lookalike org
// sharing a trusted prefix must not slip through the `owner/` boundary.
func TestDefaultConfig_PinBySHATrustsOnlyGitHubOwnedActions(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "built-in default")
	if err != nil {
		t.Fatalf("load embedded default: %v", err)
	}
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "actions", Uses: []ir.Action{{Uses: "actions/checkout@v5"}}},
			{Name: "github", Uses: []ir.Action{{Uses: "github/codeql-action/init@v4"}}},
			{Name: "dependabot", Uses: []ir.Action{{Uses: "dependabot/fetch-metadata@v2"}}},
			{Name: "lookalike", Uses: []ir.Action{{Uses: "dependabot-evil/fetch-metadata@v2"}}},
			{Name: "docker", Uses: []ir.Action{{Uses: "docker/login-action@v4"}}},
		},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, buildEngineConfig(pc.ControlsFor("github")))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	var flagged []string
	for _, f := range findings {
		if f.Code == "ISSUE-701" {
			flagged = append(flagged, f.Job)
		}
	}
	sort.Strings(flagged)
	want := []string{"docker", "lookalike"}
	if len(flagged) != len(want) {
		t.Fatalf("want exactly the third-party and lookalike refs flagged %v, got %v", want, flagged)
	}
	for i := range want {
		if flagged[i] != want[i] {
			t.Fatalf("want exactly the third-party and lookalike refs flagged %v, got %v", want, flagged)
		}
	}
}
