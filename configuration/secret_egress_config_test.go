package configuration

import (
	"strings"
	"testing"
)

// The control ships enabled with working defaults (spec 4.2): an empty block
// is a complete configuration, so it is NOT "unconfigured".
func TestSecretEgressConfigLoadsWithDefaults(t *testing.T) {
	const yml = `version: "2.0"
gitlab:
  controls:
    pipelineMustNotSendSecretsToUntrustedHosts:
      enabled: true
github:
  controls:
    pipelineMustNotSendSecretsToUntrustedHosts:
      enabled: true
      trustVcsHosts: false
      trustedHosts:
        - "*.internal.example.com"
        - "10.*"
`
	pc, _, _, err := LoadPlumberConfigFromBytes([]byte(yml), "secret-egress-test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	gl := pc.GetPipelineMustNotSendSecretsToUntrustedHostsConfig()
	if gl == nil || !gl.IsEnabled() || gl.TrustVcsHosts != nil || len(gl.TrustedHosts) != 0 {
		t.Fatalf("gitlab block = %+v", gl)
	}
	gh := pc.ControlsFor("github").PipelineMustNotSendSecretsToUntrustedHosts
	if gh == nil || gh.TrustVcsHosts == nil || *gh.TrustVcsHosts || len(gh.TrustedHosts) != 2 {
		t.Fatalf("github block = %+v", gh)
	}
	if IsUnconfigured(pc, ProviderGitLab, "pipelineMustNotSendSecretsToUntrustedHosts") {
		t.Fatal("enabled with defaults is a complete configuration, never unconfigured")
	}
}

// The loader reports an unknown sub-key as a warning (fatal under
// --fail-warnings), the contract every control shares: trustedUrls belongs to
// ISSUE-411, not to this control, so it must be named.
func TestSecretEgressUnknownKeyWarns(t *testing.T) {
	const yml = `version: "2.0"
github:
  controls:
    pipelineMustNotSendSecretsToUntrustedHosts:
      enabled: true
      trustedUrls: ["x"]
`
	_, _, warnings, err := LoadPlumberConfigFromBytes([]byte(yml), "secret-egress-test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w, `Unknown key "trustedUrls" in control "pipelineMustNotSendSecretsToUntrustedHosts"`) {
			return
		}
	}
	t.Fatalf("trustedUrls is not a key of this control; the loader must warn on it, got %v", warnings)
}
