package configuration

import (
	"os"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestConvertV1ToV2_emptyConfig(t *testing.T) {
	pc := &PlumberConfig{}
	warnings := convertV1ToV2(pc)

	if pc.Version != "2.0" {
		t.Errorf("expected Version=\"2.0\", got %q", pc.Version)
	}
	if pc.GitLab != nil {
		t.Errorf("expected GitLab nil for empty input, got %#v", pc.GitLab)
	}
	if pc.GitHub != nil {
		t.Errorf("expected GitHub nil for empty input, got %#v", pc.GitHub)
	}
	// Empty input has no structural change; the version bump is silent.
	if len(warnings) != 0 {
		t.Errorf("expected zero warnings on empty input, got %v", warnings)
	}
}

func TestConvertV1ToV2_movesControlsToGitLab(t *testing.T) {
	pc := &PlumberConfig{
		Controls: ControlsConfig{
			ContainerImageMustNotUseForbiddenTags: &ImageForbiddenTagsControlConfig{
				Enabled: boolPtr(true),
				Tags:    []string{"latest", "main"},
			},
			BranchMustBeProtected: &BranchProtectionControlConfig{
				Enabled: boolPtr(true),
			},
		},
	}

	convertV1ToV2(pc)

	if pc.GitLab == nil {
		t.Fatal("expected GitLab populated after conversion")
	}
	if pc.GitLab.Controls.ContainerImageMustNotUseForbiddenTags == nil {
		t.Fatal("expected ContainerImageMustNotUseForbiddenTags moved to GitLab.Controls")
	}
	if pc.GitLab.Controls.BranchMustBeProtected == nil {
		t.Fatal("expected BranchMustBeProtected moved to GitLab.Controls")
	}
	if !controlsConfigIsZero(pc.Controls) {
		t.Errorf("expected legacy Controls cleared, got %#v", pc.Controls)
	}
	if pc.GitHub != nil {
		t.Errorf("v1 had no GitHub concept; expected GitHub nil, got %#v", pc.GitHub)
	}
}

func TestLoadPlumberConfig_warnsOnEngineBlock(t *testing.T) {
	tmp := t.TempDir() + "/p.yaml"
	yaml := []byte("version: \"2.0\"\nengine:\n  enabled: true\ngitlab:\n  controls: {}\n")
	if err := os.WriteFile(tmp, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, warnings, err := LoadPlumberConfig(tmp)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(strings.ToLower(w), "engine") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected deprecation warning for engine block, got %v", warnings)
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := t.TempDir() + "/p.yaml"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPlumberConfig_v1FlatAutoConverts(t *testing.T) {
	path := writeTempConfig(t, `version: "1.0"
controls:
  branchMustBeProtected:
    enabled: true
`)
	pc, _, warnings, err := LoadPlumberConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if pc.Version != "2.0" {
		t.Errorf("expected version normalised to 2.0, got %q", pc.Version)
	}
	if pc.GitLab == nil || pc.GitLab.Controls.BranchMustBeProtected == nil {
		t.Fatal("v1 controls did not migrate to gitlab.controls")
	}
	if !controlsConfigIsZero(pc.Controls) {
		t.Error("legacy Controls field should be cleared after conversion")
	}
	foundDeprecation := false
	for _, w := range warnings {
		if strings.Contains(strings.ToLower(w), "legacy config schema") {
			foundDeprecation = true
		}
	}
	if !foundDeprecation {
		t.Errorf("expected legacy-schema deprecation warning, got %v", warnings)
	}
}

func TestLoadPlumberConfig_v2NativeNoConversion(t *testing.T) {
	path := writeTempConfig(t, `version: "2.0"
gitlab:
  controls:
    branchMustBeProtected:
      enabled: true
`)
	pc, _, warnings, err := LoadPlumberConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if pc.Version != "2.0" {
		t.Errorf("version: %q", pc.Version)
	}
	if pc.GitLab == nil || pc.GitLab.Controls.BranchMustBeProtected == nil {
		t.Fatal("v2 gitlab.controls not parsed")
	}
	for _, w := range warnings {
		if strings.Contains(strings.ToLower(w), "legacy") {
			t.Errorf("unexpected legacy warning on v2 file: %v", warnings)
		}
	}
}

func TestLoadPlumberConfig_rejectsUnsupportedVersion(t *testing.T) {
	path := writeTempConfig(t, `version: "9.9"
gitlab:
  controls: {}
`)
	_, _, _, err := LoadPlumberConfig(path)
	if err == nil {
		t.Fatal("expected error on unsupported version")
	}
	if !strings.Contains(err.Error(), "unsupported config version") {
		t.Errorf("error message: %v", err)
	}
}

func TestValidateKnownKeys_warnsOnMisplacedControl(t *testing.T) {
	// actionsMustBePinnedByCommitSha is GitHub-only. Putting it under
	// gitlab.controls should trigger the misplacement warning.
	body := []byte(`version: "2.0"
gitlab:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
`)
	warnings := ValidateKnownKeys(body)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "actionsMustBePinnedByCommitSha") && strings.Contains(w, "not applicable to gitlab") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected misplacement warning, got %v", warnings)
	}
}

func TestValidateKnownKeys_quietWhenCorrectlyPlaced(t *testing.T) {
	// actionsMustBePinnedByCommitSha under github.controls is correct.
	body := []byte(`version: "2.0"
github:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
`)
	warnings := ValidateKnownKeys(body)
	for _, w := range warnings {
		if strings.Contains(w, "not applicable") {
			t.Errorf("did not expect misplacement warning, got %v", warnings)
		}
	}
}

func TestLoadPlumberConfig_v1WithStaleVersionOnNestedFile(t *testing.T) {
	// User manually nested controls but didn't update version: "1.0".
	// The file is structurally v2, so the converter should bump the
	// version silently (no deprecation warning).
	path := writeTempConfig(t, `version: "1.0"
gitlab:
  controls:
    branchMustBeProtected:
      enabled: true
`)
	pc, _, warnings, err := LoadPlumberConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if pc.Version != "2.0" {
		t.Errorf("expected version bumped to 2.0, got %q", pc.Version)
	}
	for _, w := range warnings {
		if strings.Contains(strings.ToLower(w), "legacy") {
			t.Errorf("expected silent bump, got legacy warning: %v", warnings)
		}
	}
}

func TestConvertV1ToV2_idempotentOnAlreadyV2(t *testing.T) {
	pc := &PlumberConfig{
		Version: "1.0",
		GitLab: &ProviderConfig{
			Controls: ControlsConfig{
				BranchMustBeProtected: &BranchProtectionControlConfig{Enabled: boolPtr(true)},
			},
		},
		GitHub: &ProviderConfig{
			Controls: ControlsConfig{
				ActionsMustBePinnedByCommitSha: &ActionsPinnedByShaControlConfig{Enabled: boolPtr(true)},
			},
		},
	}

	warnings := convertV1ToV2(pc)

	if pc.GitLab == nil || pc.GitLab.Controls.BranchMustBeProtected == nil {
		t.Fatal("conversion clobbered v2 GitLab config")
	}
	if pc.GitHub == nil || pc.GitHub.Controls.ActionsMustBePinnedByCommitSha == nil {
		t.Fatal("conversion clobbered v2 GitHub config")
	}
	if pc.Version != "2.0" {
		t.Errorf("Version changed: %q", pc.Version)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings on already-v2 input, got %v", warnings)
	}
}

func TestProviderConfig_lookup(t *testing.T) {
	pc := &PlumberConfig{
		GitLab: &ProviderConfig{},
		GitHub: &ProviderConfig{},
	}
	if pc.ProviderConfig("gitlab") != pc.GitLab {
		t.Error("ProviderConfig(\"gitlab\") wrong")
	}
	if pc.ProviderConfig("github") != pc.GitHub {
		t.Error("ProviderConfig(\"github\") wrong")
	}
	if pc.ProviderConfig("bitbucket") != nil {
		t.Error("expected nil for unknown provider")
	}
	var nilPC *PlumberConfig
	if nilPC.ProviderConfig("gitlab") != nil {
		t.Error("expected nil from nil receiver")
	}
}

func TestControlsFor_returnsZeroWhenAbsent(t *testing.T) {
	pc := &PlumberConfig{}
	got := pc.ControlsFor("gitlab")
	if got == nil {
		t.Fatal("ControlsFor must never return nil")
		return
	}
	if !controlsConfigIsZero(*got) {
		t.Errorf("expected zero ControlsConfig, got %#v", *got)
	}
}

func TestControlsFor_returnsLiveWhenPresent(t *testing.T) {
	cfg := &BranchProtectionControlConfig{Enabled: boolPtr(true)}
	pc := &PlumberConfig{
		GitLab: &ProviderConfig{
			Controls: ControlsConfig{BranchMustBeProtected: cfg},
		},
	}
	got := pc.ControlsFor("gitlab")
	if got.BranchMustBeProtected != cfg {
		t.Error("expected pointer-identical control entry")
	}
}
