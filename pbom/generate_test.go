package pbom

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
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

// jobsJSONKey is the quoted key the omitempty contract must leave out of a
// document generated without the pipeline model.
const jobsJSONKey = "\"jobs\""

// TestGenerateJobResources covers the per-job half of the bill of materials
// (design spec 2026-09-23-dependencies-graph-design section 5): a job's
// service images and runner tags reach the PBOM from the pipeline model, and
// only the jobs that carry one or the other are listed. Everything else about
// the document is unchanged, which is what keeps the existing PBOM and
// CycloneDX exports byte-identical for a pipeline with no services and no
// tags.
func TestGenerateJobResources(t *testing.T) {
	jobs := []ir.Job{
		{
			Name:     "test",
			Services: []ir.Image{{Name: "docker", Tag: "24.0.5-dind"}},
			Tags:     []string{"docker"},
		},
		{Name: "lint"},
	}

	got := NewGenerator("group/app", 7, "https://gitlab.example.com", "main").
		WithJobResources(jobs).
		Generate(nil, nil)

	if len(got.Jobs) != 1 {
		t.Fatalf("Jobs = %#v, want exactly the one job that carries a service or a tag", got.Jobs)
	}
	job := got.Jobs[0]
	if job.Name != "test" {
		t.Errorf("Jobs[0].Name = %q, want %q", job.Name, "test")
	}
	if len(job.Services) != 1 {
		t.Fatalf("Jobs[0].Services = %#v, want one entry", job.Services)
	}
	if job.Services[0].Name != "docker" {
		t.Errorf("Jobs[0].Services[0].Name = %q, want %q", job.Services[0].Name, "docker")
	}
	if job.Services[0].Tag != "24.0.5-dind" {
		t.Errorf("Jobs[0].Services[0].Tag = %q, want %q", job.Services[0].Tag, "24.0.5-dind")
	}
	if job.Services[0].Image != "docker:24.0.5-dind" {
		t.Errorf("Jobs[0].Services[0].Image = %q, want the reference as the pipeline reads it", job.Services[0].Image)
	}
	if !reflect.DeepEqual(job.RunnerTags, []string{"docker"}) {
		t.Errorf("Jobs[0].RunnerTags = %#v, want %#v", job.RunnerTags, []string{"docker"})
	}
}

// TestGenerateWithoutJobResourcesOmitsTheKey is the control: a generator that
// was never handed the pipeline model reports no jobs at all, and the JSON
// leaves the key out entirely rather than publishing an empty list, which
// would read as "this pipeline has no service and no runner tag" for a run
// that simply never looked.
func TestGenerateWithoutJobResourcesOmitsTheKey(t *testing.T) {
	got := NewGenerator("group/app", 7, "https://gitlab.example.com", "main").Generate(nil, nil)
	if got.Jobs != nil {
		t.Fatalf("Jobs = %#v, want nil without WithJobResources", got.Jobs)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), jobsJSONKey) {
		t.Errorf("the PBOM JSON carries a jobs key with no job resources collected: %s", raw)
	}
}

// TestGenerateJobResourcesSortedByName pins the order: jobs are sorted by
// name so two runs over the same pipeline produce the same document and the
// platform's replacement rule never sees a spurious change.
func TestGenerateJobResourcesSortedByName(t *testing.T) {
	jobs := []ir.Job{
		{Name: "zeta", Tags: []string{"linux"}},
		{Name: "alpha", Tags: []string{"linux"}},
	}
	got := NewGenerator("group/app", 7, "https://gitlab.example.com", "main").
		WithJobResources(jobs).
		Generate(nil, nil)
	if len(got.Jobs) != 2 || got.Jobs[0].Name != "alpha" || got.Jobs[1].Name != "zeta" {
		t.Fatalf("Jobs = %#v, want alpha before zeta", got.Jobs)
	}
}

// TestJobServiceRefCarriesRegistryAndDigest covers a service reference the
// collector fully resolved: registry, name and digest are copied as the
// pipeline model parsed them, and the reference string is rebuilt from them
// rather than re-parsed here (one parser, invariant I1).
func TestJobServiceRefCarriesRegistryAndDigest(t *testing.T) {
	jobs := []ir.Job{{
		Name: "test",
		Services: []ir.Image{{
			Registry: "registry.example.com",
			Name:     "team/postgres",
			Digest:   "sha256:abc",
		}},
	}}
	got := NewGenerator("group/app", 7, "https://gitlab.example.com", "main").
		WithJobResources(jobs).
		Generate(nil, nil)
	if len(got.Jobs) != 1 || len(got.Jobs[0].Services) != 1 {
		t.Fatalf("Jobs = %#v, want one job with one service", got.Jobs)
	}
	svc := got.Jobs[0].Services[0]
	if svc.Registry != "registry.example.com" || svc.Name != "team/postgres" || svc.Digest != "sha256:abc" {
		t.Errorf("service ref = %#v, want the pipeline model's own split", svc)
	}
	if svc.Image != "registry.example.com/team/postgres@sha256:abc" {
		t.Errorf("service ref Image = %q, want the canonical reference", svc.Image)
	}
}

// TestProcessImagesCarriesTheUnresolvedFlag covers the fact the collector
// already knows and the document threw away: a reference that still held a
// $VARIABLE after substitution was parsed out of a placeholder, so its
// registry, name and tag describe a variable rather than an image. The
// document already refuses to publish a verdict about such an image
// (ImageComplianceFor); carrying the flag lets the platform push refuse to
// publish it as a dependency at all.
func TestProcessImagesCarriesTheUnresolvedFlag(t *testing.T) {
	imageData := &gitlab.GitlabPipelineImageData{
		Images: []gitlab.GitlabPipelineImageInfo{
			{Link: "unknown/$CI_REGISTRY_IMAGE:$TAG", Registry: "unknown", Name: "$CI_REGISTRY_IMAGE", Tag: "$TAG", Job: "deploy", Unresolved: true},
			{Link: "docker.io/node:20", Registry: "docker.io", Name: "node", Tag: "20", Job: "build"},
		},
	}
	got := NewGenerator("group/app", 7, "https://gitlab.example.com", "main").Generate(imageData, nil)

	byName := map[string]ContainerImage{}
	for _, img := range got.ContainerImages {
		byName[img.Name] = img
	}
	if !byName["$CI_REGISTRY_IMAGE"].Unresolved {
		t.Errorf("the placeholder image is not marked unresolved: %#v", byName["$CI_REGISTRY_IMAGE"])
	}
	if byName["node"].Unresolved {
		t.Errorf("a literal image is marked unresolved: %#v", byName["node"])
	}
}

// TestGenerateJobResourcesSkipsAnEmptyServiceReference covers a blank
// services: entry (services: [""] or services: [{name: ""}], both of which
// the collector turns into a zero-valued image). An entry with no reference
// names no dependency, and a consumer that keys a resource on its reference
// would mint one keyed on nothing. The GitHub path already skips such a
// reference; this one now does too.
func TestGenerateJobResourcesSkipsAnEmptyServiceReference(t *testing.T) {
	jobs := []ir.Job{{
		Name: "test",
		Services: []ir.Image{
			{},
			{Name: "docker", Tag: "24.0.5-dind"},
		},
	}}
	got := NewGenerator("group/app", 7, "https://gitlab.example.com", "main").
		WithJobResources(jobs).
		Generate(nil, nil)
	if len(got.Jobs) != 1 {
		t.Fatalf("Jobs = %#v, want one job", got.Jobs)
	}
	if len(got.Jobs[0].Services) != 1 {
		t.Fatalf("Jobs[0].Services = %#v, want the blank entry skipped", got.Jobs[0].Services)
	}
	if got.Jobs[0].Services[0].Name != "docker" {
		t.Errorf("Jobs[0].Services[0].Name = %q, want docker", got.Jobs[0].Services[0].Name)
	}
}

// TestGenerateJobResourcesDropsAJobLeftWithNoService is the corollary: a job
// whose only service was a blank entry, and which names no runner tag, has
// nothing left to report and is not listed at all.
func TestGenerateJobResourcesDropsAJobLeftWithNoService(t *testing.T) {
	jobs := []ir.Job{{Name: "test", Services: []ir.Image{{}}}}
	got := NewGenerator("group/app", 7, "https://gitlab.example.com", "main").
		WithJobResources(jobs).
		Generate(nil, nil)
	if got.Jobs != nil {
		t.Errorf("Jobs = %#v, want nil: the job carries nothing after the blank service is dropped", got.Jobs)
	}
}

// TestJobServiceRefCarriesTheUnresolvedFlag pins the same signal on a service
// reference, so a consumer of the document can tell a placeholder apart from
// an image without re-parsing the reference itself.
func TestJobServiceRefCarriesTheUnresolvedFlag(t *testing.T) {
	jobs := []ir.Job{{
		Name:     "test",
		Services: []ir.Image{{Name: "$SERVICE_IMAGE", Tag: "latest", Unresolved: true}},
	}}
	got := NewGenerator("group/app", 7, "https://gitlab.example.com", "main").
		WithJobResources(jobs).
		Generate(nil, nil)
	if len(got.Jobs) != 1 || len(got.Jobs[0].Services) != 1 {
		t.Fatalf("Jobs = %#v, want one job with one service", got.Jobs)
	}
	if !got.Jobs[0].Services[0].Unresolved {
		t.Errorf("service ref = %#v, want it marked unresolved", got.Jobs[0].Services[0])
	}
}

// TestProcessIncludesCarriesTheComponentProject pins the generator's half of
// the component node's key (dependencies-graph design spec 4.1: a component
// node is keyed on project + component_name). The origin below is shaped the
// way the collector records the catalog-resolved component include of the
// capture this fix came from, project included, and the PBOM include must
// carry that project through: Project is not a project-include-only field,
// and a component that loses it is unkeyable on the platform side.
func TestProcessIncludesCarriesTheComponentProject(t *testing.T) {
	originData := &gitlab.GitlabPipelineOriginData{
		Origins: []gitlab.GitlabPipelineOriginDataFull{
			{
				GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
					OriginType:        "component",
					FromGitlabCatalog: true,
					GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
						Location: "gitlab.com/getplumber/plumber/plumber",
						Type:     "component",
						Project:  "getplumber/plumber",
					},
					GitlabComponent: gitlab.GitlabPipelineJobGitlabComponent{
						ComponentName:          "plumber",
						ComponentLatestVersion: "v0.5.7",
					},
				},
				GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
					Version: "v0.5.2",
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

	if inc.Project != "getplumber/plumber" {
		t.Errorf("Project = %q, want %q", inc.Project, "getplumber/plumber")
	}
	if inc.ComponentName != "plumber" {
		t.Errorf("ComponentName = %q, want %q", inc.ComponentName, "plumber")
	}
	if inc.Location != "gitlab.com/getplumber/plumber/plumber" {
		t.Errorf("Location = %q, want it untouched", inc.Location)
	}
}
