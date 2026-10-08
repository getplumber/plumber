package policies_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestImagePoliciesJudgeEachMatrixLiteral pins that a container image
// built from `${{ matrix.X }}`, whose matrix lists literals, is judged as
// each image it resolves to (ir.Job.MatrixImages): the forbidden tag
// (ISSUE-102), the digest pin (ISSUE-103) and the authorized source
// (ISSUE-101) findings name a real image, never the reference computed
// at run time.
func TestImagePoliciesJudgeEachMatrixLiteral(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"imageMutableTag": map[string]any{"forbiddenTags": []any{"24.04"}},
		"containerImageMustNotUseForbiddenTags": map[string]any{
			"mustBePinnedByDigest": true,
		},
		"imageAuthorizedSources": map[string]any{
			"trustedUrls":            []any{"ghcr.io/*"},
			"trustDockerHubOfficial": true,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:  "release/zsh",
			Image: &ir.Image{Name: "${{ matrix.image }}"},
			MatrixImages: []ir.Image{
				{Name: "arm64v8/ubuntu", Tag: "24.04"},
				{Name: "ubuntu", Tag: "24.04"},
			},
		}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	links := map[string][]string{}
	for _, f := range findings {
		switch f.Code {
		case "ISSUE-101", "ISSUE-102", "ISSUE-103":
			link, _ := f.Data["link"].(string)
			if strings.Contains(link, "${{") {
				t.Errorf("%s judged the reference as written: %s", f.Code, link)
			}
			links[f.Code] = append(links[f.Code], link)
		}
	}
	want := map[string][]string{
		"ISSUE-101": {"arm64v8/ubuntu:24.04"},
		"ISSUE-102": {"arm64v8/ubuntu:24.04", "ubuntu:24.04"},
		"ISSUE-103": {"arm64v8/ubuntu:24.04", "ubuntu:24.04"},
	}
	for code, w := range want {
		got := links[code]
		sort.Strings(got)
		if !stringSlicesEqual(got, w) {
			t.Errorf("%s: got %v, want %v", code, got, w)
		}
	}
}
