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

// TestComponentAuthorizedSourcesConfigContract runs the REAL
// buildEngineConfig projection of the EMBEDDED default config through the
// rego, mirroring TestFunctionAuthorizedSourcesConfigContract. Every
// TestIssue414 case injects a hand-built config map, so without this a
// key typo or a deleted SaaS override in the projection would silently
// change what the control trusts on gitlab.com with the suite green.
func TestComponentAuthorizedSourcesConfigContract(t *testing.T) {
	var conf configuration.PlumberConfig
	if err := yaml.Unmarshal(defaultconfig.Get(), &conf); err != nil {
		t.Fatalf("unmarshal embedded default: %v", err)
	}

	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}

	cases := []struct {
		name      string
		gitlabURL string
		source    string
		want      int
	}{
		{
			name:      "saas_own_root_namespace",
			gitlabURL: "https://gitlab.com",
			source:    "gitlab.com/my-group/ci-components/build",
			want:      0,
		},
		{
			name:      "saas_official_components",
			gitlabURL: "https://gitlab.com",
			source:    "gitlab.com/components/sast/sast",
			want:      0,
		},
		{
			name:      "saas_official_gitlab_org",
			gitlabURL: "https://gitlab.com",
			source:    "gitlab.com/gitlab-org/components/release/release",
			want:      0,
		},
		{
			// The embedded default sets trustSameInstanceComponents: true,
			// but the projection forces it off on gitlab.com: any other
			// namespace on the shared instance stays untrusted.
			name:      "saas_other_namespace",
			gitlabURL: "https://gitlab.com",
			source:    "gitlab.com/other-group/x/backdoor",
			want:      1,
		},
		{
			// GitLab resolves namespaces case-insensitively: a mixed-case
			// spelling of the own root namespace is the own namespace.
			name:      "saas_own_root_namespace_mixed_case",
			gitlabURL: "https://gitlab.com",
			source:    "gitlab.com/My-Group/ci-components/build",
			want:      0,
		},
		{
			// A mixed-case instance URL is still gitlab.com: the same-instance
			// trust stays off there.
			name:      "saas_mixed_case_url_other_namespace",
			gitlabURL: "https://GitLab.com/",
			source:    "gitlab.com/other-group/x/backdoor",
			want:      1,
		},
		{
			name:      "self_hosted_same_instance_any_namespace",
			gitlabURL: "https://gitlab.example.com",
			source:    "gitlab.example.com/other-group/x/build",
			want:      0,
		},
		{
			name:      "self_hosted_component_from_other_host",
			gitlabURL: "https://gitlab.example.com",
			source:    "gitlab.com/other-group/x/backdoor",
			want:      1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engineCfg := buildEngineConfig(conf.ControlsFor("gitlab"), tc.gitlabURL)
			if _, ok := engineCfg["componentAuthorizedSources"]; !ok {
				t.Fatal("buildEngineConfig did not project a componentAuthorizedSources block from the embedded default")
			}
			p := &ir.NormalizedPipeline{
				Provider:    ir.ProviderGitLab,
				ProjectPath: "my-group/my-project",
				Includes:    []ir.Include{{Kind: "component", Source: tc.source}},
			}
			findings, err := evaluateStrict(engine, context.Background(), p, engineCfg)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			n := 0
			for _, f := range findings {
				if f.Code == "ISSUE-414" {
					n++
				}
			}
			if n != tc.want {
				t.Fatalf("through the real config projection: expected %d ISSUE-414 for %q, got %d", tc.want, tc.source, n)
			}
		})
	}

	// The keys the rego reads, pinned directly so a renamed key fails
	// with its name rather than as a trust outcome.
	t.Run("projected_keys", func(t *testing.T) {
		for _, tc := range []struct {
			gitlabURL     string
			instanceHost  string
			sameInstance  bool
			officialTrust bool
		}{
			{gitlabURL: "https://gitlab.com", instanceHost: "gitlab.com", sameInstance: false, officialTrust: true},
			{gitlabURL: "https://gitlab.example.com", instanceHost: "gitlab.example.com", sameInstance: true, officialTrust: true},
		} {
			entry, ok := buildEngineConfig(conf.ControlsFor("gitlab"), tc.gitlabURL)["componentAuthorizedSources"].(map[string]any)
			if !ok {
				t.Fatalf("%s: componentAuthorizedSources block missing or not a map", tc.gitlabURL)
			}
			if got := entry["instanceHost"]; got != tc.instanceHost {
				t.Errorf("%s: instanceHost = %v, want %q", tc.gitlabURL, got, tc.instanceHost)
			}
			if got := entry["trustSameGroupComponents"]; got != true {
				t.Errorf("%s: trustSameGroupComponents = %v, want true", tc.gitlabURL, got)
			}
			if got := entry["trustSameInstanceComponents"]; got != tc.sameInstance {
				t.Errorf("%s: trustSameInstanceComponents = %v, want %v", tc.gitlabURL, got, tc.sameInstance)
			}
			if got := entry["trustGitlabOfficialComponents"]; got != tc.officialTrust {
				t.Errorf("%s: trustGitlabOfficialComponents = %v, want %v", tc.gitlabURL, got, tc.officialTrust)
			}
		}
	})
}
