package cmd

import (
	"testing"

	"github.com/getplumber/plumber/utils"
	"github.com/spf13/cobra"
)

// TestResolveProvider locks in the provider-selection precedence:
//  1. --github-url / --gitlab-url   (pins provider, beats everything)
//  2. --provider                    (pins provider; host auto-detected)
//  3. git-remote auto-detection
//  4. nothing -> ("","")
func TestResolveProvider(t *testing.T) {
	ghRemote := &utils.GitRemoteInfo{Provider: "github", ProviderReason: "host is github.com"}
	glRemote := &utils.GitRemoteInfo{Provider: "gitlab", ProviderReason: "host is gitlab.com"}

	tests := []struct {
		name                             string
		providerFlag                     string
		gitlabURLFromFlag, githubURLFlag bool
		remote                           *utils.GitRemoteInfo
		wantProvider                     string
	}{
		// URL flags win over everything.
		{"github-url beats provider+remote", "gitlab", false, true, glRemote, "github"},
		{"gitlab-url beats provider+remote", "github", true, false, ghRemote, "gitlab"},

		// --provider wins over auto-detection.
		{"provider github over gitlab remote", "github", false, false, glRemote, "github"},
		{"provider gitlab over github remote", "gitlab", false, false, ghRemote, "gitlab"},

		// Auto-detection when no flags.
		{"auto github", "", false, false, ghRemote, "github"},
		{"auto gitlab", "", false, false, glRemote, "gitlab"},

		// --provider with no remote (works outside a clone).
		{"provider github no remote", "github", false, false, nil, "github"},
		{"provider gitlab no remote", "gitlab", false, false, nil, "gitlab"},

		// Nothing to go on.
		{"no flags no remote", "", false, false, nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := resolveProvider(tt.providerFlag, tt.gitlabURLFromFlag, tt.githubURLFlag, tt.remote)
			if got != tt.wantProvider {
				t.Errorf("resolveProvider() provider = %q, want %q", got, tt.wantProvider)
			}
			if got != "" && reason == "" {
				t.Errorf("resolveProvider() returned provider %q with empty reason", got)
			}
		})
	}
}

// TestEnvStringFallback_MarksFlagSet guards the regression where the GitLab CI
// component passes coordinates via PLUMBER_ANALYZE_* env vars (not flags). The
// env fallback must mark the flag as Changed, or both provider selection and the
// host fall back to defaults (the run fails with "could not determine the
// provider", or a self-hosted URL is overwritten with gitlab.com).
func TestEnvStringFallback_MarksFlagSet(t *testing.T) {
	t.Setenv("PLUMBER_ANALYZE_GITLAB_URL", "https://gitlab.example.com")

	var url string
	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&url, "gitlab-url", "", "")

	if err := envStringFallback(cmd, "gitlab-url", "PLUMBER_ANALYZE_GITLAB_URL", &url); err != nil {
		t.Fatalf("envStringFallback returned error: %v", err)
	}
	if url != "https://gitlab.example.com" {
		t.Errorf("value not applied from env: got %q", url)
	}
	if !cmd.Flags().Changed("gitlab-url") {
		t.Fatal("env var must mark the flag Changed so provider/host selection honors it")
	}
	// resolveProvider keys off the flag-changed state, which the env fallback now
	// sets, so an env-provided host selects the gitlab provider.
	if got, _ := resolveProvider("", cmd.Flags().Changed("gitlab-url"), false, nil); got != "gitlab" {
		t.Errorf("provider = %q, want gitlab (env host should select provider)", got)
	}
}
