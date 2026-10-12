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

// The shipped baseline trusts Plumber's own GitLab CI/CD component for
// ISSUE-414 (components must come from authorized sources), the same way
// it already trusts Plumber's own container image: on gitlab.com, where
// the same-instance trust is always off, including
// gitlab.com/getplumber/plumber/plumber (the recommended way to run
// Plumber on GitLab) is never flagged, while a component from another
// namespace in the same run still is, proving the control was active.
func TestDefaultConfig_TrustsPlumberOwnComponent(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "built-in default")
	if err != nil {
		t.Fatalf("load embedded default: %v", err)
	}
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	const (
		plumber = "gitlab.com/getplumber/plumber/plumber@v0.6.0"
		other   = "gitlab.com/someone-else/tool/x@1.0.0"
	)
	pipeline := &ir.NormalizedPipeline{
		Provider:    ir.ProviderGitLab,
		ProjectPath: "example-group/example-project",
		Includes: []ir.Include{
			{Kind: "component", Source: plumber},
			{Kind: "component", Source: other},
		},
	}
	cfg := buildEngineConfig(pc.ControlsFor("gitlab"), "https://gitlab.com")
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	var flagged []string
	for _, f := range findings {
		if f.Code == "ISSUE-414" {
			flagged = append(flagged, f.Data["componentPath"].(string))
		}
	}
	for _, src := range flagged {
		if src == plumber {
			t.Fatalf("Plumber's own component %q is flagged by ISSUE-414 with the default configuration; flagged: %v", plumber, flagged)
		}
	}
	if len(flagged) != 1 || flagged[0] != other {
		t.Fatalf("want only %q flagged by ISSUE-414, got %v", other, flagged)
	}
}
