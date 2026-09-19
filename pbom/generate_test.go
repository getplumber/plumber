package pbom

import (
	"testing"

	"github.com/getplumber/plumber/gitlab"
)

// TestProcessIncludesLeavesUpToDateUnknownWithoutALatestVersion covers a
// versioned template include whose source project's tag listing failed: the
// collector still reports FromPlumber (the identity is a fact of the ref),
// but with no LatestVersion resolved there is nothing to compare the pin
// against. The PBOM must report the include's Version, and leave
// LatestVersion empty and UpToDate nil/absent - not fabricate an "outdated"
// verdict out of the zero-valued UpToDate field.
func TestProcessIncludesLeavesUpToDateUnknownWithoutALatestVersion(t *testing.T) {
	originData := &gitlab.GitlabPipelineOriginData{
		Origins: []gitlab.GitlabPipelineOriginDataFull{
			{
				GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
					OriginType:  "project",
					FromPlumber: true,
					PlumberOrigin: gitlab.GitlabPipelineJobPlumberOrigin{
						Path:          "templates/trivy/trivy",
						LatestVersion: "", // the tag listing failed
					},
				},
				GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
					Version:  "0.1.0",
					UpToDate: false, // zero value; must not be read as a verdict
				},
			},
		},
	}

	g := &Generator{}
	got := g.processIncludes(originData)
	if len(got) != 1 {
		t.Fatalf("expected exactly one include, got %d", len(got))
	}
	inc := got[0]

	if inc.LatestVersion != "" {
		t.Errorf("LatestVersion = %q, want empty", inc.LatestVersion)
	}
	if inc.UpToDate != nil {
		t.Errorf("UpToDate = %v, want nil (never determined)", *inc.UpToDate)
	}
}

// TestProcessIncludesReportsUpToDateWhenALatestVersionIsKnown is the control:
// once a latest version IS known, the verdict still comes through as before.
func TestProcessIncludesReportsUpToDateWhenALatestVersionIsKnown(t *testing.T) {
	originData := &gitlab.GitlabPipelineOriginData{
		Origins: []gitlab.GitlabPipelineOriginDataFull{
			{
				GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
					OriginType:  "project",
					FromPlumber: true,
					PlumberOrigin: gitlab.GitlabPipelineJobPlumberOrigin{
						Path:          "templates/trivy/trivy",
						LatestVersion: "0.2.0",
					},
				},
				GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
					Version:  "0.1.0",
					UpToDate: false,
				},
			},
		},
	}

	g := &Generator{}
	got := g.processIncludes(originData)
	if len(got) != 1 {
		t.Fatalf("expected exactly one include, got %d", len(got))
	}
	inc := got[0]

	if inc.LatestVersion != "0.2.0" {
		t.Errorf("LatestVersion = %q, want %q", inc.LatestVersion, "0.2.0")
	}
	if inc.UpToDate == nil || *inc.UpToDate != false {
		t.Errorf("UpToDate = %v, want pointer to false", inc.UpToDate)
	}
}
