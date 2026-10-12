package control

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"gopkg.in/yaml.v2"
)

// TestApplyGitLabRegistryHost pins where the registry host that anchors
// same-group function trust comes from: the GitLab API's image prefix, else
// the configured instance URL. The environment is never read — on a
// self-managed instance CI_TEMPLATE_REGISTRY_HOST is registry.gitlab.com,
// and the scanned pipeline can redefine any of these variables.
func TestApplyGitLabRegistryHost(t *testing.T) {
	cases := []struct {
		name      string
		project   *gitlab.Project
		gitlabURL string
		want      string
	}{
		{name: "api_prefix_saas", project: &gitlab.Project{ContainerRegistryImagePrefix: "registry.gitlab.com/my-group/my-project"}, gitlabURL: "https://gitlab.com", want: "registry.gitlab.com"},
		{name: "api_prefix_custom_host_and_port", project: &gitlab.Project{ContainerRegistryImagePrefix: "gitlab.example.com:5050/my-group/my-project"}, gitlabURL: "https://gitlab.example.com", want: "gitlab.example.com:5050"},
		{name: "api_prefix_lowercased", project: &gitlab.Project{ContainerRegistryImagePrefix: "Registry.Example.com/g/p"}, gitlabURL: "https://gitlab.example.com", want: "registry.example.com"},
		{name: "no_prefix_derived_from_url", project: &gitlab.Project{}, gitlabURL: "https://gitlab.example.com/", want: "registry.gitlab.example.com"},
		{name: "nil_project_derived_from_url", project: nil, gitlabURL: "https://gitlab.com", want: "registry.gitlab.com"},
		{name: "nothing_known", project: nil, gitlabURL: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A pipeline redefining these must change nothing.
			t.Setenv("CI", "true")
			t.Setenv("CI_SERVER_HOST", "gitlab.example.com")
			t.Setenv("CI_TEMPLATE_REGISTRY_HOST", "registry.evil.example")
			t.Setenv("CI_REGISTRY", "registry.evil.example")
			p := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab}
			applyGitLabRegistryHost(p, tc.project, tc.gitlabURL)
			if p.RegistryHost != tc.want {
				t.Fatalf("RegistryHost = %q, want %q", p.RegistryHost, tc.want)
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
	// Plumber's own CI job (or a scanned pipeline) setting these must not
	// move the trust anchor: the registry host comes from the API.
	t.Setenv("CI", "true")
	t.Setenv("CI_TEMPLATE_REGISTRY_HOST", "registry.evil.example")
	t.Setenv("CI_REGISTRY", "registry.evil.example")

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
		applyGitLabRegistryHost(p, &gitlab.Project{ContainerRegistryImagePrefix: "registry.gitlab.com/my-group/my-project"}, "https://gitlab.com")
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
			// The registry the environment names is not the project's: an
			// own-namespace path on it stays untrusted.
			name: "own_namespace_on_env_registry_untrusted",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "pwn", Ref: "registry.evil.example/my-group/backdoor:1", Kind: "oci"}}},
			want: 1,
		},
		{
			// The structured git form reaches the policy like the short
			// form: under the own namespace it is trusted...
			name: "own_namespace_structured_git_ref",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "deploy", Ref: "gitlab.com/my-group/funcs/-/deploy@main", Kind: "git", Deprecated: true}}},
			want: 0,
		},
		{
			// ...and a reference Plumber could not read fails closed.
			name: "unknown_structured_ref_fails_closed",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "deploy", Ref: `{"oci":{"repository":"registry.gitlab.com/my-group/x"}}`, Kind: "unknown"}}},
			want: 1,
		},
		{
			// No pattern is shipped: the runner does not expand $VAR in a
			// `func:` reference, so this literal ref never runs and nothing
			// in the defaults trusts it.
			name: "variable_ref_not_trusted_by_default",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "echo", Ref: "$CI_TEMPLATE_REGISTRY_HOST/$CI_PROJECT_PATH/echo:1", Kind: "oci"}}},
			want: 1,
		},
		{
			// GitLab built-in functions ship inside the runner.
			name: "builtin_function_out_of_scope",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "build", Ref: "builtin://function/oci/build", Kind: "builtin"}}},
			want: 0,
		},
		{
			// GitLab paths are case-insensitive: a mixed-case spelling of
			// the own namespace is still the own namespace.
			name: "own_namespace_mixed_case_git_ref",
			job:  ir.Job{Name: "build", Functions: []ir.Function{{Name: "deploy", Ref: "GitLab.com/My-Group/my-project@v1", Kind: "git", Deprecated: true}}},
			want: 0,
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
