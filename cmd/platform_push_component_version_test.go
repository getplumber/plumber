package cmd

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
	providerPkg "github.com/getplumber/plumber/provider"
)

// TestComponentVersionForPush pins the selection rule of issue #562: the
// push names, in cli.component_version, the version of the component include
// that defines the running job (contract docs/contracts/openapi.yaml of the
// platform: the pinned CI component's own version, read FIRST for the
// component_ref refresh), and only when that version is version-like.
func TestComponentVersionForPush(t *testing.T) {
	product := "gitlab.com/getplumber/plumber/plumber"
	cases := []struct {
		name     string
		includes []pushComponentInclude
		job      string
		want     string
	}{
		{
			name: "the include that declares the running job wins",
			includes: []pushComponentInclude{
				{Type: "component", Location: product, Version: "v0.7.6", Jobs: []string{"plumber"}},
				{Type: "component", Location: "gitlab.example.com/acme/scan/scan", Version: "1.2.3", Jobs: []string{"security-scan"}},
			},
			job:  "security-scan",
			want: "1.2.3",
		},
		{
			// Review of PR 563: the running job's include is the only one
			// declaring "myjob", so rule 1 selects it alone; its version
			// ("main") is not version-like, so the function must return ""
			// right there instead of falling through to rule 2, where the
			// plumber include's version-like "v0.7.6" would otherwise win.
			name: "the running-job rule's non-version-like winner blocks the later rules",
			includes: []pushComponentInclude{
				{Type: "component", Location: "gitlab.example.com/acme/custom/custom", Version: "main", Jobs: []string{"myjob"}},
				{Type: "component", Location: product, Version: "v0.7.6", Jobs: []string{"plumber"}},
			},
			job:  "myjob",
			want: "",
		},
		{
			name: "no job name falls back on the one component listing the plumber job",
			includes: []pushComponentInclude{
				{Type: "component", Location: "gitlab.example.com/acme/plumber-fork/plumber", Version: "v2.0.0", Jobs: []string{"plumber"}},
				{Type: "component", Location: "gitlab.example.com/acme/sast/sast", Version: "3.3.0", Jobs: []string{"sast"}},
			},
			job:  "",
			want: "v2.0.0",
		},
		{
			name: "an unmatched job falls back on the product path",
			includes: []pushComponentInclude{
				{Type: "component", Location: "$CI_SERVER_FQDN/getplumber/plumber/plumber", Version: "v0.7.6", Jobs: []string{"compliance"}},
				{Type: "component", Location: "gitlab.example.com/acme/sast/sast", Version: "3.3.0", Jobs: []string{"sast"}},
			},
			job:  "renamed-job",
			want: "v0.7.6",
		},
		{
			name: "two candidates and no job match send nothing",
			includes: []pushComponentInclude{
				{Type: "component", Location: "gitlab.example.com/a/plumber/plumber", Version: "v1.0.0", Jobs: []string{"plumber"}},
				{Type: "component", Location: "gitlab.example.com/b/plumber/plumber", Version: "v1.1.0", Jobs: []string{"plumber"}},
				{Type: "component", Location: "gitlab.com/getplumber/plumber/plumber", Version: "v0.7.6", Jobs: []string{"other"}},
				{Type: "component", Location: "gitlab.example.com/getplumber/plumber/plumber", Version: "v0.7.5", Jobs: []string{"other2"}},
			},
			job:  "unknown",
			want: "",
		},
		{
			name: "a ~latest pin is never sent",
			includes: []pushComponentInclude{
				{Type: "component", Location: product, Version: "~latest", Jobs: []string{"plumber"}},
			},
			job:  "plumber",
			want: "",
		},
		{
			name: "a sha pin is never sent",
			includes: []pushComponentInclude{
				{Type: "component", Location: product, Version: "7f1e28b3c0ffee0123456789abcdef0123456789", Jobs: []string{"plumber"}},
			},
			job:  "plumber",
			want: "",
		},
		{
			name: "a branch pin is never sent",
			includes: []pushComponentInclude{
				{Type: "component", Location: product, Version: "main", Jobs: []string{"plumber"}},
			},
			job:  "plumber",
			want: "",
		},
		{
			name: "a pre-release version is sent as written",
			includes: []pushComponentInclude{
				{Type: "component", Location: product, Version: "v0.8.0-rc.1", Jobs: []string{"plumber"}},
			},
			job:  "plumber",
			want: "v0.8.0-rc.1",
		},
		{
			name: "a project include declaring the job is not a component",
			includes: []pushComponentInclude{
				{Type: "project", Location: "acme/templates", Version: "1.0.0", Jobs: []string{"plumber"}},
			},
			job:  "plumber",
			want: "",
		},
		{
			name: "a GitHub bill has no component include",
			includes: []pushComponentInclude{
				{Type: "action", Location: "getplumber/plumber", Version: "v0.7.6"},
				{Type: "reusableWorkflow", Location: "getplumber/plumber/.github/workflows/plumber.yml", Version: "v0.7.6"},
			},
			job:  "plumber",
			want: "",
		},
		{
			name:     "no include sends nothing",
			includes: nil,
			job:      "plumber",
			want:     "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := componentVersionForPush(tc.includes, tc.job); got != tc.want {
				t.Errorf("componentVersionForPush = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestComponentVersionForGitHubPush pins the GitHub half of issue #562
// (review of PR 563): on GitHub the CLI's own pin is the `uses:` action
// reference, getplumber/plumber@<ref>, not a GitLab component include.
// Among the direct action references of the run's jobs, the one whose job
// is the running job (GITHUB_JOB) wins when it is the product action; else
// the product action wins when exactly one job references it; the chosen
// ref is sent only when it is version-like, same pattern as the GitLab
// side.
func TestComponentVersionForGitHubPush(t *testing.T) {
	product := "getplumber/plumber"
	cases := []struct {
		name     string
		includes []pushComponentInclude
		job      string
		want     string
	}{
		{
			name: "job match on GitHub",
			includes: []pushComponentInclude{
				{Type: "action", Location: product, Version: "v0.7.6", Jobs: []string{"lint"}},
				{Type: "action", Location: product, Version: "v0.8.0", Jobs: []string{"scan"}},
			},
			job:  "scan",
			want: "v0.8.0",
		},
		{
			name: "single-reference fallback",
			includes: []pushComponentInclude{
				{Type: "action", Location: product, Version: "v0.7.6", Jobs: []string{"ci"}},
			},
			job:  "",
			want: "v0.7.6",
		},
		{
			name: "two jobs with no GITHUB_JOB -> empty",
			includes: []pushComponentInclude{
				{Type: "action", Location: product, Version: "v0.7.6", Jobs: []string{"lint"}},
				{Type: "action", Location: product, Version: "v0.8.0", Jobs: []string{"scan"}},
			},
			job:  "",
			want: "",
		},
		{
			name: "@main -> empty",
			includes: []pushComponentInclude{
				{Type: "action", Location: product, Version: "main", Jobs: []string{"ci"}},
			},
			job:  "ci",
			want: "",
		},
		{
			name: "SHA -> empty",
			includes: []pushComponentInclude{
				{Type: "action", Location: product, Version: "7f1e28b3c0ffee0123456789abcdef0123456789", Jobs: []string{"ci"}},
			},
			job:  "ci",
			want: "",
		},
		{
			name: "a third-party action only -> empty",
			includes: []pushComponentInclude{
				{Type: "action", Location: "actions/checkout", Version: "v4.1.0", Jobs: []string{"ci"}},
			},
			job:  "ci",
			want: "",
		},
		{
			// Review of PR 563: the running job "ci" declares exactly one
			// product action, whose ref ("main") is not version-like, so
			// the function must return "" right there rather than treating
			// "deploy"'s version-like "v1.0.0" as the single-reference
			// fallback winner.
			name: "the running job's non-version-like reference blocks the single-reference fallback",
			includes: []pushComponentInclude{
				{Type: "action", Location: product, Version: "main", Jobs: []string{"ci"}},
				{Type: "action", Location: product, Version: "v1.0.0", Jobs: []string{"deploy"}},
			},
			job:  "ci",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := componentVersionForGitHubPush(tc.includes, tc.job); got != tc.want {
				t.Errorf("componentVersionForGitHubPush = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPushComponentIncludesOf_SkipsNestedOrigins pins the coordinator
// ruling on review of PR 563: the GitLab side skips nested component
// origins too, for the same reason the GitHub side already does
// (pushComponentIncludesOfGitHub) - the project's own pin is the include its
// own CI file names, so an origin pulled in transitively (Nested true, set
// by collect_pipeline_origin.go for an include whose context project
// differs from the current project) is never a candidate. The existing
// originHardcoded skip is covered alongside it as a regression case.
func TestPushComponentIncludesOf_SkipsNestedOrigins(t *testing.T) {
	p, ok := providerPkg.Get("gitlab")
	if !ok {
		t.Skip("gitlab provider not registered")
	}
	cases := []struct {
		name   string
		origin *gitlab.GitlabPipelineOriginData
		want   []pushComponentInclude
	}{
		{
			name: "a nested component origin is skipped, only the direct one is emitted",
			origin: &gitlab.GitlabPipelineOriginData{
				Origins: []gitlab.GitlabPipelineOriginDataFull{
					{
						GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
							OriginType: "component",
							GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
								Location: "gitlab.com/getplumber/plumber/plumber",
							},
						},
						GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
							Version: "v0.7.6",
							Jobs:    []gitlab.GitlabPipelineJobData{{Name: "plumber"}},
						},
					},
					{
						GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
							OriginType: "component",
							GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
								Location: "gitlab.com/acme/wrapper/wrapper",
							},
						},
						GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
							Version: "v9.9.9",
							Nested:  true,
							Jobs:    []gitlab.GitlabPipelineJobData{{Name: "nested-job"}},
						},
					},
				},
			},
			want: []pushComponentInclude{
				{Type: "component", Location: "gitlab.com/getplumber/plumber/plumber", Version: "v0.7.6", Jobs: []string{"plumber"}},
			},
		},
		{
			name: "a hardcoded origin is skipped",
			origin: &gitlab.GitlabPipelineOriginData{
				Origins: []gitlab.GitlabPipelineOriginDataFull{
					{
						GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
							OriginType: "hardcoded",
						},
						GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
							Jobs: []gitlab.GitlabPipelineJobData{{Name: "build"}},
						},
					},
				},
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pushComponentIncludesOf(p, tc.origin)
			if len(got) != len(tc.want) {
				t.Fatalf("pushComponentIncludesOf returned %d includes, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].Type != tc.want[i].Type || got[i].Location != tc.want[i].Location || got[i].Version != tc.want[i].Version || fmt.Sprint(got[i].Jobs) != fmt.Sprint(tc.want[i].Jobs) {
					t.Errorf("pushComponentIncludesOf[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestPushComponentIncludesOfGitHub_SkipsNestedReferences pins review of PR
// 563: a step pulled in by a composite action (Nested true) is never a
// candidate for cli.component_version, because it is not the project's own
// pin. A job with one direct product reference (v1.0.0) and one nested
// reference (v2.0.0, reached through a Via chain) must yield exactly one
// include, the direct one, and the assembled push must carry its version.
func TestPushComponentIncludesOfGitHub_SkipsNestedReferences(t *testing.T) {
	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
		Name: "ci/ci",
		Uses: []ir.Action{
			{Uses: "getplumber/plumber@v1.0.0"},
			{
				Uses:   "getplumber/plumber@v2.0.0",
				Nested: true,
				Via:    []string{"someone/composite@main"},
			},
		},
	}}}

	includes := pushComponentIncludesOfGitHub(pipeline)
	if len(includes) != 1 {
		t.Fatalf("pushComponentIncludesOfGitHub returned %d includes, want 1: %+v", len(includes), includes)
	}
	if includes[0].Version != "v1.0.0" {
		t.Errorf("includes[0].Version = %q, want v1.0.0", includes[0].Version)
	}

	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}
	t.Setenv("GITHUB_JOB", "ci")
	if got := pushComponentVersionForGitHub(p, pipeline); got != "v1.0.0" {
		t.Errorf("pushComponentVersionForGitHub = %q, want v1.0.0", got)
	}
}

// TestBuildPlatformPush_CarriesTheComponentVersion pins issue #562 on the
// assembled envelope: cli.component_version is the version of the component
// include that defines the running job, and the key is absent when no
// version-like candidate exists or the provider is GitHub.
func TestBuildPlatformPush_CarriesTheComponentVersion(t *testing.T) {
	originWith := func(version string) *gitlab.GitlabPipelineOriginData {
		return &gitlab.GitlabPipelineOriginData{
			Origins: []gitlab.GitlabPipelineOriginDataFull{{
				GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
					OriginType: "component",
					GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
						Location: "gitlab.com/getplumber/plumber/plumber",
						Project:  "getplumber/plumber",
					},
				},
				GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
					Version: version,
					Jobs:    []gitlab.GitlabPipelineJobData{{Name: "plumber"}},
				},
			}},
		}
	}
	originWithTwo := func(secondVersion string) *gitlab.GitlabPipelineOriginData {
		return &gitlab.GitlabPipelineOriginData{
			Origins: []gitlab.GitlabPipelineOriginDataFull{
				{
					GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
						OriginType: "component",
						GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
							Location: "gitlab.com/getplumber/plumber/plumber",
							Project:  "getplumber/plumber",
						},
					},
					GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
						Version: "v0.7.6",
						Jobs:    []gitlab.GitlabPipelineJobData{{Name: "plumber"}},
					},
				},
				{
					GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
						OriginType: "component",
						GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
							Location: "gitlab.example.com/acme/scan/scan",
							Project:  "acme/scan",
						},
					},
					GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
						Version: secondVersion,
						Jobs:    []gitlab.GitlabPipelineJobData{{Name: "security-scan"}},
					},
				},
			},
		}
	}

	cliOf := func(t *testing.T, p providerPkg.Provider, result *control.AnalysisResult) map[string]any {
		t.Helper()
		body, err := buildPlatformPush(p, nil, result, nil, ".plumber.yaml", nil)
		if err != nil {
			t.Fatalf("buildPlatformPush: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("push does not parse as JSON: %v", err)
		}
		cli, ok := raw["cli"].(map[string]any)
		if !ok {
			t.Fatalf("the push carries no cli block: %s", body)
		}
		return cli
	}

	t.Run("the component include version reaches the wire", func(t *testing.T) {
		t.Setenv("CI_JOB_NAME", "plumber")
		cli := cliOf(t, testProvider(t), &control.AnalysisResult{PipelineOriginData: originWith("v0.7.6")})
		if cli["component_version"] != "v0.7.6" {
			t.Errorf("cli.component_version = %#v, want v0.7.6", cli["component_version"])
		}
	})
	t.Run("a ~latest pin omits the key", func(t *testing.T) {
		t.Setenv("CI_JOB_NAME", "plumber")
		cli := cliOf(t, testProvider(t), &control.AnalysisResult{PipelineOriginData: originWith("~latest")})
		if _, present := cli["component_version"]; present {
			t.Errorf("cli.component_version = %#v, want the key absent", cli["component_version"])
		}
	})
	t.Run("a GitHub push omits the key for a workflow with no product action", func(t *testing.T) {
		p, ok := providerPkg.Get("github")
		if !ok {
			t.Skip("github provider not registered")
		}
		t.Setenv("GITHUB_JOB", "ci")
		pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
			Name: "ci/ci", Uses: []ir.Action{{Uses: "actions/checkout@v4"}},
		}}}
		// PipelineOriginData is GitLab-shaped data that must never leak onto
		// a GitHub push; GitHubPipeline carries only a third-party action,
		// so neither source gives the key a value.
		cli := cliOf(t, p, &control.AnalysisResult{PipelineOriginData: originWith("v0.7.6"), GitHubPipeline: pipeline})
		if _, present := cli["component_version"]; present {
			t.Errorf("cli.component_version = %#v, want the key absent on GitHub", cli["component_version"])
		}
	})
	t.Run("a GitHub push carries the product action's version", func(t *testing.T) {
		p, ok := providerPkg.Get("github")
		if !ok {
			t.Skip("github provider not registered")
		}
		t.Setenv("GITHUB_JOB", "plumber")
		pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
			Name: "ci/plumber", Uses: []ir.Action{{Uses: "getplumber/plumber@v0.7.6"}},
		}}}
		cli := cliOf(t, p, &control.AnalysisResult{GitHubPipeline: pipeline})
		if cli["component_version"] != "v0.7.6" {
			t.Errorf("cli.component_version = %#v, want v0.7.6", cli["component_version"])
		}
	})

	// Review of PR 563: the prior cases above all use a single component
	// origin that is both the product path and the one declaring the
	// "plumber" job, so they pass whatever CI_JOB_NAME wiring or Jobs
	// mapping componentVersionForPush does, including a wiring that is
	// broken in a way the single-origin cases cannot see. These two cases
	// add a second, non-product component origin that declares a
	// different job, so the running-job rule and the job-fallback rule
	// each select a different include.
	t.Run("the running job's include wins over the plumber-job component", func(t *testing.T) {
		t.Setenv("CI_JOB_NAME", "security-scan")
		cli := cliOf(t, testProvider(t), &control.AnalysisResult{PipelineOriginData: originWithTwo("1.2.3")})
		if cli["component_version"] != "1.2.3" {
			t.Errorf("cli.component_version = %#v, want 1.2.3", cli["component_version"])
		}
	})
	t.Run("no job name falls back on the component listing the plumber job", func(t *testing.T) {
		t.Setenv("CI_JOB_NAME", "")
		cli := cliOf(t, testProvider(t), &control.AnalysisResult{PipelineOriginData: originWithTwo("1.2.3")})
		if cli["component_version"] != "v0.7.6" {
			t.Errorf("cli.component_version = %#v, want v0.7.6", cli["component_version"])
		}
	})

	// Coordinator ruling on review of PR 563: the GitLab side skips nested
	// component origins too. A product component pulled in transitively by
	// a wrapper component (Nested true, v9.9.9) sits next to the project's
	// own direct pin of the same component (v0.7.6, declaring a job that is
	// not the running job). Before the skip, the nested origin is the only
	// one declaring the plumber job and is wrongly reported as the
	// project's own pin.
	t.Run("a nested product component is skipped, the project's own pin wins", func(t *testing.T) {
		t.Setenv("CI_JOB_NAME", "")
		origin := &gitlab.GitlabPipelineOriginData{
			Origins: []gitlab.GitlabPipelineOriginDataFull{
				{
					GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
						OriginType: "component",
						GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
							Location: "gitlab.com/getplumber/plumber/plumber",
							Project:  "getplumber/plumber",
						},
					},
					GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
						Version: "v0.7.6",
						Jobs:    []gitlab.GitlabPipelineJobData{{Name: "compliance"}},
					},
				},
				{
					GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
						OriginType: "component",
						GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
							Location: "gitlab.com/getplumber/plumber/plumber",
							Project:  "getplumber/plumber",
						},
					},
					GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
						Version: "v9.9.9",
						Nested:  true,
						Jobs:    []gitlab.GitlabPipelineJobData{{Name: "plumber"}},
					},
				},
			},
		}
		cli := cliOf(t, testProvider(t), &control.AnalysisResult{PipelineOriginData: origin})
		if cli["component_version"] != "v0.7.6" {
			t.Errorf("cli.component_version = %#v, want v0.7.6", cli["component_version"])
		}
	})

	// Review of PR 563: component_version is read from the run's origin
	// data directly (platform_push.go), never from the bill of materials,
	// so the guarantee of issue #562 must survive a bill the platform
	// bound refuses whole. A 501-job pipeline trips the jobs > 500 bound
	// (TestPlatformBOMFrom_Bounds) while the single component origin still
	// names the running CI_JOB_NAME with a version-like pin.
	t.Run("component_version survives when the bill is dropped past a bound", func(t *testing.T) {
		t.Setenv("CI_JOB_NAME", "plumber")
		jobs := make([]ir.Job, 501)
		for i := range jobs {
			jobs[i] = ir.Job{Name: fmt.Sprintf("job%d", i), Tags: []string{"docker"}}
		}
		result := &control.AnalysisResult{
			PipelineOriginData: originWith("v0.7.6"),
			Pipeline:           &ir.NormalizedPipeline{Jobs: jobs},
		}
		body, err := buildPlatformPush(testProvider(t), nil, result, nil, ".plumber.yaml", nil)
		if err != nil {
			t.Fatalf("buildPlatformPush: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("push does not parse as JSON: %v", err)
		}
		if _, present := raw["bom"]; present {
			t.Errorf("push carries a bom key, want it dropped past the jobs bound: %s", body)
		}
		cli, ok := raw["cli"].(map[string]any)
		if !ok {
			t.Fatalf("the push carries no cli block: %s", body)
		}
		if cli["component_version"] != "v0.7.6" {
			t.Errorf("cli.component_version = %#v, want v0.7.6", cli["component_version"])
		}
	})
}
