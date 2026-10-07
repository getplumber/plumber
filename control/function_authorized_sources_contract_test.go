package control

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"gopkg.in/yaml.v2"
)

// clearRegistryEnv makes gitlabRegistryHost deterministic whatever
// environment the suite itself runs in (Plumber's own GitLab CI included).
func clearRegistryEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"CI", "CI_SERVER_HOST", "CI_TEMPLATE_REGISTRY_HOST", "CI_REGISTRY"} {
		t.Setenv(name, "")
	}
}

func TestGitlabRegistryHost(t *testing.T) {
	cases := []struct {
		name      string
		gitlabURL string
		env       map[string]string
		want      string
	}{
		{name: "saas_outside_ci", gitlabURL: "https://gitlab.com", want: "registry.gitlab.com"},
		{name: "self_hosted_outside_ci", gitlabURL: "https://gitlab.example.com/", want: "registry.gitlab.example.com"},
		{name: "no_url", gitlabURL: "", want: ""},
		{
			// Outside a pipeline the environment is never read.
			name:      "env_ignored_outside_ci",
			gitlabURL: "https://gitlab.com",
			env:       map[string]string{"CI_TEMPLATE_REGISTRY_HOST": "registry.other.example"},
			want:      "registry.gitlab.com",
		},
		{
			name:      "ci_template_registry_host",
			gitlabURL: "https://gitlab.example.com",
			env:       map[string]string{"CI": "true", "CI_SERVER_HOST": "gitlab.example.com", "CI_TEMPLATE_REGISTRY_HOST": "cr.example.com", "CI_REGISTRY": "other.example.com"},
			want:      "cr.example.com",
		},
		{
			name:      "ci_registry_fallback",
			gitlabURL: "https://gitlab.example.com",
			env:       map[string]string{"CI": "true", "CI_SERVER_HOST": "gitlab.example.com", "CI_REGISTRY": "gitlab.example.com:5050"},
			want:      "gitlab.example.com:5050",
		},
		{
			name:      "ci_no_registry_env_derived",
			gitlabURL: "https://gitlab.example.com",
			env:       map[string]string{"CI": "true", "CI_SERVER_HOST": "gitlab.example.com"},
			want:      "registry.gitlab.example.com",
		},
		{
			// Plumber running on gitlab.com while scanning a self-hosted
			// instance: the job's own registry is the wrong instance's.
			name:      "ci_other_instance_derived",
			gitlabURL: "https://gitlab.example.com",
			env:       map[string]string{"CI": "true", "CI_SERVER_HOST": "gitlab.com", "CI_TEMPLATE_REGISTRY_HOST": "registry.gitlab.com"},
			want:      "registry.gitlab.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearRegistryEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := gitlabRegistryHost(tc.gitlabURL); got != tc.want {
				t.Fatalf("gitlabRegistryHost(%q) = %q, want %q", tc.gitlabURL, got, tc.want)
			}
		})
	}
}

// TestFunctionAuthorizedSourcesConfigContract runs the REAL
// buildEngineConfig projection of the EMBEDDED default config through the
// rego, so a host the projection gets wrong (or a key mismatch with the
// rego's object.get keys) fails here instead of shipping silently behind
// hand-built test configs.
func TestFunctionAuthorizedSourcesConfigContract(t *testing.T) {
	clearRegistryEnv(t)

	var conf configuration.PlumberConfig
	if err := yaml.Unmarshal(defaultconfig.Get(), &conf); err != nil {
		t.Fatalf("unmarshal embedded default: %v", err)
	}
	engineCfg := buildEngineConfig(conf.ControlsFor("gitlab"), "https://gitlab.com")
	if _, ok := engineCfg["functionAuthorizedSources"]; !ok {
		t.Fatal("buildEngineConfig did not project a functionAuthorizedSources block from the embedded default")
	}

	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	countISSUE415 := func(t *testing.T, job ir.Job) int {
		t.Helper()
		p := &ir.NormalizedPipeline{
			Provider:    ir.ProviderGitLab,
			ProjectPath: "my-group/my-project",
			Jobs:        []ir.Job{job},
		}
		findings, err := evaluateStrict(engine, context.Background(), p, engineCfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		n := 0
		for _, f := range findings {
			if f.Code == "ISSUE-415" {
				n++
			}
		}
		return n
	}

	cases := []struct {
		name string
		job  ir.Job
		want int
	}{
		{
			// The project's own function in the supported OCI form on
			// gitlab.com: trusted through same-group on the registry host.
			name: "own_namespace_oci_ref",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "deploy", Ref: "registry.gitlab.com/my-group/my-project/deploy:1.0.0", Kind: "oci"}}},
			want: 0,
		},
		{
			name: "own_namespace_deprecated_git_ref",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "deploy", Ref: "gitlab.com/my-group/my-project@v1", Kind: "git", Deprecated: true}}},
			want: 0,
		},
		{
			name: "other_namespace_oci_ref",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "deploy", Ref: "registry.gitlab.com/attacker/x/deploy:1.0.0", Kind: "oci"}}},
			want: 1,
		},
		{
			name: "default_pattern_trusted",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "echo", Ref: "$CI_TEMPLATE_REGISTRY_HOST/$CI_PROJECT_PATH/echo:1", Kind: "oci"}}},
			want: 0,
		},
		{
			// The default pattern's variable shadowed in the job's own
			// `variables:` block resolves to an attacker registry.
			name: "default_pattern_shadowed_on_job",
			job: ir.Job{
				Name:           "build",
				LocalVariables: map[string]string{"CI_TEMPLATE_REGISTRY_HOST": "registry.evil.example"},
				Functions:      []ir.Function{{Name: "pwn", Ref: "$CI_TEMPLATE_REGISTRY_HOST/$CI_PROJECT_PATH/backdoor:1", Kind: "oci"}},
			},
			want: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if n := countISSUE415(t, tc.job); n != tc.want {
				t.Fatalf("through the real config projection: expected %d ISSUE-415, got %d", tc.want, n)
			}
		})
	}
}
