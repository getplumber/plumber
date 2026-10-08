package policies_test

import (
	"context"
	"reflect"
	"sort"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestOwnRegistryImageIsAuthorized pins that an image under the
// repository owner's own GitHub container registry namespace
// (ghcr.io/<owner>/..., the owner compared case-insensitively) is the
// repository's own image, never an image from an unauthorized source
// (ISSUE-101), the same rule as the repository's own actions. Another
// owner's image under ghcr.io stays judged.
func TestOwnRegistryImageIsAuthorized(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{"imageAuthorizedSources": map[string]any{"trustedUrls": []any{"docker.io/library/*"}}}
	pipeline := &ir.NormalizedPipeline{
		Provider:    ir.ProviderGitLab,
		ProjectPath: "Electron/electron",
		Jobs: []ir.Job{
			{Name: "own", Image: &ir.Image{Registry: "ghcr.io", Name: "electron/build", Tag: "abc"}},
			{Name: "own-lower-owner", Image: &ir.Image{Registry: "ghcr.io", Name: "ELECTRON/test", Tag: "1"}},
			{Name: "other", Image: &ir.Image{Registry: "ghcr.io", Name: "someone/build", Tag: "1"}},
			{Name: "prefix-owner", Image: &ir.Image{Registry: "ghcr.io", Name: "electronics/build", Tag: "1"}},
		},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, f := range findings {
		if f.Code == "ISSUE-101" {
			hits = append(hits, f.Job)
		}
	}
	sort.Strings(hits)
	if want := []string{"other", "prefix-owner"}; !reflect.DeepEqual(hits, want) {
		t.Errorf("ISSUE-101 on %v, want %v", hits, want)
	}
}
