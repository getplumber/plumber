package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/defaultconfig"
)

func TestSlimToOverlay_KeepsOnlyDifferences(t *testing.T) {
	// Start from the full base, change exactly one control value.
	var baseMap map[interface{}]interface{}
	if err := yaml.Unmarshal(defaultconfig.Get(), &baseMap); err != nil {
		t.Fatal(err)
	}
	gh := baseMap["github"].(map[interface{}]interface{})["controls"].(map[interface{}]interface{})
	ctrl := gh["githubActionMustComeFromAuthorizedSources"].(map[interface{}]interface{})
	ctrl["minimumStars"] = 4242

	full, err := yaml.Marshal(baseMap)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "full.yaml")
	if err := os.WriteFile(src, full, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(src)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "extends: plumber:default") {
		t.Fatal("slim output must opt into overlay mode")
	}
	if !strings.Contains(s, "githubActionMustComeFromAuthorizedSources") {
		t.Fatal("the changed control must be kept")
	}
	if strings.Contains(s, "actionsMustBePinnedByCommitSha") {
		t.Fatal("unchanged controls must be dropped from the overlay")
	}
}

// TestSlimToOverlay_PreservesNarrowedTrustList guards against a
// trust-widening regression: a legacy full config that narrows an
// allowlist-aware control's trust list (githubActionMustComeFromAuthorizedSources
// / trustedGithubActions, containerImageMustComeFromAuthorizedSources /
// trustedUrls) must not have that narrowing silently undone by slim ->
// resolve. In overlay mode includePlumberDefaults defaults to true, so
// naively keeping the user's raw control map as-is would union the
// curated base list (~140 entries) back in even though the legacy file
// used the list verbatim. slimToOverlay must pin
// includePlumberDefaults: false on these two controls when kept and the
// user did not already set the toggle themselves.
func TestSlimToOverlay_PreservesNarrowedTrustList(t *testing.T) {
	baseCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base-for-test")
	if err != nil {
		t.Fatal(err)
	}
	baseTrustedActions := baseCfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if len(baseTrustedActions) == 0 {
		t.Fatal("test assumption broken: base trustedGithubActions is empty")
	}
	baseTrustedURLs := baseCfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources.TrustedUrls
	if len(baseTrustedURLs) == 0 {
		t.Fatal("test assumption broken: base trustedUrls is empty")
	}

	cases := []struct {
		name string
		want []interface{}
	}{
		{"narrowed", []interface{}{"myorg/*"}},
		{"empty", []interface{}{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var baseMap map[interface{}]interface{}
			if err := yaml.Unmarshal(defaultconfig.Get(), &baseMap); err != nil {
				t.Fatal(err)
			}

			gh := baseMap["github"].(map[interface{}]interface{})["controls"].(map[interface{}]interface{})
			ghCtrl := gh["githubActionMustComeFromAuthorizedSources"].(map[interface{}]interface{})
			ghCtrl["trustedGithubActions"] = tc.want

			gl := baseMap["gitlab"].(map[interface{}]interface{})["controls"].(map[interface{}]interface{})
			glCtrl := gl["containerImageMustComeFromAuthorizedSources"].(map[interface{}]interface{})
			glCtrl["trustedUrls"] = tc.want

			// Legacy full config: no `extends` key.
			full, err := yaml.Marshal(baseMap)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			src := filepath.Join(dir, "full.yaml")
			if err := os.WriteFile(src, full, 0o600); err != nil {
				t.Fatal(err)
			}

			out, err := slimToOverlay(src)
			if err != nil {
				t.Fatalf("slim: %v", err)
			}

			resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
			if err != nil {
				t.Fatalf("resolve slim overlay: %v", err)
			}

			gotActions := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
			gotURLs := resolved.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources.TrustedUrls

			wantStrs := make([]string, len(tc.want))
			for i, v := range tc.want {
				wantStrs[i] = v.(string)
			}

			if !equalStringSlices(gotActions, wantStrs) {
				t.Fatalf("trustedGithubActions widened: got %v, want %v", gotActions, wantStrs)
			}
			if !equalStringSlices(gotURLs, wantStrs) {
				t.Fatalf("trustedUrls widened: got %v, want %v", gotURLs, wantStrs)
			}

			for _, entry := range baseTrustedActions {
				if containsString(gotActions, entry) {
					t.Fatalf("resolved trustedGithubActions still contains base entry %q: %v", entry, gotActions)
				}
			}
			for _, entry := range baseTrustedURLs {
				if containsString(gotURLs, entry) {
					t.Fatalf("resolved trustedUrls still contains base entry %q: %v", entry, gotURLs)
				}
			}
		})
	}
}

// TestSlimToOverlay_LegacySourceForcesInertToggleOff is the trust-widening
// regression case (source-aware fix round): a LEGACY full config (no
// `extends`) where includePlumberDefaults is INERT (the legacy loader never
// reads it; the list is always used as-is). If the user hand-added
// `includePlumberDefaults: true` alongside a narrowed trustedGithubActions,
// that value did nothing in the legacy source. A slim implementation that
// merely "preserves whatever the user already set" would carry the inert
// `true` into the emitted overlay, and once resolved (where the toggle is
// NOT inert) it would union the curated base list back in, silently
// widening trust. slimToOverlay must force includePlumberDefaults: false
// on a kept allowlist-aware control whenever the SOURCE is legacy,
// regardless of what value (if any) was already present.
func TestSlimToOverlay_LegacySourceForcesInertToggleOff(t *testing.T) {
	baseCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base-for-test")
	if err != nil {
		t.Fatal(err)
	}
	baseTrustedActions := baseCfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if len(baseTrustedActions) == 0 {
		t.Fatal("test assumption broken: base trustedGithubActions is empty")
	}

	var baseMap map[interface{}]interface{}
	if err := yaml.Unmarshal(defaultconfig.Get(), &baseMap); err != nil {
		t.Fatal(err)
	}
	gh := baseMap["github"].(map[interface{}]interface{})["controls"].(map[interface{}]interface{})
	ctrl := gh["githubActionMustComeFromAuthorizedSources"].(map[interface{}]interface{})
	ctrl["trustedGithubActions"] = []interface{}{"myorg/*"}
	// Inert in a legacy source: the legacy loader never reads this, so a
	// user could have this lying around from a previous overlay attempt
	// or a copy-paste, without it affecting legacy resolution at all.
	ctrl["includePlumberDefaults"] = true

	// Legacy full config: no `extends` key.
	full, err := yaml.Marshal(baseMap)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "full.yaml")
	if err := os.WriteFile(src, full, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(src)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
	if err != nil {
		t.Fatalf("resolve slim overlay: %v", err)
	}

	got := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	want := []string{"myorg/*"}
	if !equalStringSlices(got, want) {
		t.Fatalf("trustedGithubActions widened by inert legacy toggle: got %v, want %v", got, want)
	}
	for _, entry := range baseTrustedActions {
		if containsString(got, entry) {
			t.Fatalf("resolved trustedGithubActions still contains base entry %q: %v", entry, got)
		}
	}
}

// TestSlimToOverlay_OverlaySourcePreservesOmittedToggle is the narrowing
// mirror case: when the SOURCE is already an overlay (extends:
// plumber:default), an absent includePlumberDefaults on an allowlist-aware
// control legitimately means "union with base" (the documented default).
// slimToOverlay must not inject includePlumberDefaults: false in this
// case: doing so would silently narrow a config that intended (by
// omission) to keep the curated base list unioned in.
func TestSlimToOverlay_OverlaySourcePreservesOmittedToggle(t *testing.T) {
	baseCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base-for-test")
	if err != nil {
		t.Fatal(err)
	}
	baseTrustedActions := baseCfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if len(baseTrustedActions) == 0 {
		t.Fatal("test assumption broken: base trustedGithubActions is empty")
	}

	overlaySrc := map[interface{}]interface{}{
		"extends": configuration.ExtendsPlumberDefault,
		"version": "2.0",
		"github": map[interface{}]interface{}{
			"controls": map[interface{}]interface{}{
				"githubActionMustComeFromAuthorizedSources": map[interface{}]interface{}{
					"trustedGithubActions": []interface{}{"myorg/*"},
					// includePlumberDefaults intentionally omitted.
				},
			},
		},
	}
	raw, err := yaml.Marshal(overlaySrc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "overlay.yaml")
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(src)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	var overlayMap map[interface{}]interface{}
	if err := yaml.Unmarshal(out, &overlayMap); err != nil {
		t.Fatal(err)
	}
	ghOut := overlayMap["github"].(map[interface{}]interface{})["controls"].(map[interface{}]interface{})
	ctrlOut := ghOut["githubActionMustComeFromAuthorizedSources"].(map[interface{}]interface{})
	if _, present := ctrlOut["includePlumberDefaults"]; present {
		t.Fatalf("includePlumberDefaults must stay absent (overlay source omitted it): got %v", ctrlOut["includePlumberDefaults"])
	}

	resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
	if err != nil {
		t.Fatalf("resolve slim overlay: %v", err)
	}
	got := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if !containsString(got, "myorg/*") {
		t.Fatalf("resolved trustedGithubActions must contain user's entry: %v", got)
	}
	if !containsString(got, baseTrustedActions[0]) {
		t.Fatalf("resolved trustedGithubActions must still union base (omitted toggle = default true): %v", got)
	}
}

// TestSlimToOverlay_OverlaySourcePreservesExplicitIncludePlumberDefaults
// covers the companion case to the two above: when the SOURCE is already
// an overlay AND it explicitly sets includePlumberDefaults, that explicit
// value is the user's real overlay-mode intent and must survive slim
// unchanged (not be overridden in either direction).
func TestSlimToOverlay_OverlaySourcePreservesExplicitIncludePlumberDefaults(t *testing.T) {
	var baseMap map[interface{}]interface{}
	if err := yaml.Unmarshal(defaultconfig.Get(), &baseMap); err != nil {
		t.Fatal(err)
	}
	baseMap["extends"] = configuration.ExtendsPlumberDefault
	gh := baseMap["github"].(map[interface{}]interface{})["controls"].(map[interface{}]interface{})
	ctrl := gh["githubActionMustComeFromAuthorizedSources"].(map[interface{}]interface{})
	ctrl["trustedGithubActions"] = []interface{}{"myorg/*"}
	ctrl["includePlumberDefaults"] = true

	full, err := yaml.Marshal(baseMap)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "overlay-source.yaml")
	if err := os.WriteFile(src, full, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(src)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	var overlayMap map[interface{}]interface{}
	if err := yaml.Unmarshal(out, &overlayMap); err != nil {
		t.Fatal(err)
	}
	ghOut := overlayMap["github"].(map[interface{}]interface{})["controls"].(map[interface{}]interface{})
	ctrlOut := ghOut["githubActionMustComeFromAuthorizedSources"].(map[interface{}]interface{})
	got, ok := ctrlOut["includePlumberDefaults"]
	if !ok {
		t.Fatal("includePlumberDefaults must be present (explicitly set by the user in an overlay source)")
	}
	if got != true {
		t.Fatalf("includePlumberDefaults must stay true (user's explicit overlay-mode choice), got %v", got)
	}
}

// TestSlimToOverlay_V1LegacyConfigPreservesNarrowTrust is finding #7's
// regression guard: a v1 legacy config (top-level `controls:`,
// `version: "1.0"`) has no gitlab/github keys at all, so the raw-map diff
// slimToOverlay used to compute was empty and the emitted overlay was just
// `extends + version`. Resolving that against the base then expanded to
// the FULL base config: every control enabled and every trust list widened
// to the curated ~140-entry list, even though the v1 source narrowed its
// trust list to a single entry. v1 is still supported (LoadPlumberConfig
// auto-migrates it via convertV1ToV2), so slim must operate on the
// migrated, effective config rather than the raw v1 bytes.
func TestSlimToOverlay_V1LegacyConfigPreservesNarrowTrust(t *testing.T) {
	src := `version: "1.0"
controls:
  containerImageMustComeFromAuthorizedSources:
    enabled: true
    trustedUrls:
      - docker.io/myorg/*
`
	dir := t.TempDir()
	path := filepath.Join(dir, "v1.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(path)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
	if err != nil {
		t.Fatalf("resolve slim overlay: %v", err)
	}

	ctrl := resolved.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources
	if ctrl == nil || !ctrl.IsEnabled() {
		t.Fatalf("containerImageMustComeFromAuthorizedSources must be present and enabled after slim -> resolve, got %+v", ctrl)
	}
	want := []string{"docker.io/myorg/*"}
	if !equalStringSlices(ctrl.TrustedUrls, want) {
		t.Fatalf("v1 narrow trust list must survive slim -> resolve unwidened: got %v, want %v", ctrl.TrustedUrls, want)
	}
}

// TestSlimToOverlay_OmittedControlStaysDisabledAfterResolve is finding #8's
// regression guard: a legacy (no extends) v2-shaped source that declares
// only ONE github control and omits everything else has, by omission,
// disabled every control it did not mention (control.DisabledControlNames:
// an absent control is disabled). slimToOverlay used to diff only the
// controls present in the source, so an omitted-but-base-enabled control
// silently dropped out of the overlay and was re-enabled by inheritance
// once resolved against the base. slimToOverlay must instead emit an
// explicit `enabled: false` for any base-enabled control the source
// omitted.
func TestSlimToOverlay_OmittedControlStaysDisabledAfterResolve(t *testing.T) {
	baseCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base-for-test")
	if err != nil {
		t.Fatal(err)
	}
	pinnedCfg := baseCfg.GitHub.Controls.ActionsMustBePinnedByCommitSha
	if pinnedCfg == nil || !pinnedCfg.IsEnabled() {
		t.Fatal("test assumption broken: actionsMustBePinnedByCommitSha must be enabled in the embedded default")
	}

	src := `version: "2.0"
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      enabled: true
      trustedGithubActions:
        - myorg
`
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy-v2.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(path)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
	if err != nil {
		t.Fatalf("resolve slim overlay: %v", err)
	}

	disabled := control.DisabledControlNames(&resolved.GitHub.Controls)
	if !disabled["actionsMustBePinnedByCommitSha"] {
		t.Fatalf("actionsMustBePinnedByCommitSha was omitted by the source (disabled by omission) "+
			"and must stay disabled after slim -> resolve, got config: %+v",
			resolved.GitHub.Controls.ActionsMustBePinnedByCommitSha)
	}

	declared := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources
	if declared == nil || !declared.IsEnabled() {
		t.Fatalf("the control the source explicitly declared must stay enabled, got %+v", declared)
	}
	if !containsString(declared.TrustedGithubActions, "myorg") {
		t.Fatalf("the source's own trusted entry must survive, got %v", declared.TrustedGithubActions)
	}
}

// TestSlimToOverlay_MinimumStarsZeroNotWidened is the trust-widening
// regression case for cmd/config_slim.go:142 (finding): a LEGACY source
// (no extends) that enables githubActionMustComeFromAuthorizedSources but
// leaves minimumStars unset has an effective minimumStars of 0 (star-based
// trust disabled: the strict setting). minimumStars is a plain int with an
// omitempty yaml tag, so slim's control-submap diff silently dropped the
// zero value, and resolving the emitted overlay against the base then
// inherited the base's minimumStars: 20000, meaning any repo with >=20000
// stars became trusted post-slim even though the source explicitly
// disabled star-based trust.
func TestSlimToOverlay_MinimumStarsZeroNotWidened(t *testing.T) {
	baseCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base-for-test")
	if err != nil {
		t.Fatal(err)
	}
	baseMinimumStars := baseCfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.MinimumStars
	if baseMinimumStars == 0 {
		t.Fatal("test assumption broken: base minimumStars must be nonzero")
	}

	src := `version: "2.0"
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      enabled: true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(path)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
	if err != nil {
		t.Fatalf("resolve slim overlay: %v", err)
	}

	got := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.MinimumStars
	if got != 0 {
		t.Fatalf("minimumStars widened: legacy source left it unset (0, star-based trust disabled), "+
			"but resolved value is %d (inherited from base %d)", got, baseMinimumStars)
	}
}

// TestSlimToOverlay_TrustedOwnersEmptyNotWidened is the trust-widening
// regression case for actionsMustBePinnedByCommitSha.trustedOwners: a
// LEGACY source that enables the control but leaves trustedOwners empty
// means every action must be SHA-pinned, including actions/* and github/*
// (the strict setting). trustedOwners is a []string with an omitempty yaml
// tag, so slim's diff silently dropped the empty list, and resolving the
// emitted overlay against the base inherited trustedOwners: [actions,
// github], exempting those owners from pinning post-slim.
func TestSlimToOverlay_TrustedOwnersEmptyNotWidened(t *testing.T) {
	baseCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base-for-test")
	if err != nil {
		t.Fatal(err)
	}
	baseTrustedOwners := baseCfg.GitHub.Controls.ActionsMustBePinnedByCommitSha.TrustedOwners
	if len(baseTrustedOwners) == 0 {
		t.Fatal("test assumption broken: base trustedOwners must be nonempty")
	}

	src := `version: "2.0"
github:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(path)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
	if err != nil {
		t.Fatalf("resolve slim overlay: %v", err)
	}

	got := resolved.GitHub.Controls.ActionsMustBePinnedByCommitSha.TrustedOwners
	if len(got) != 0 {
		t.Fatalf("trustedOwners widened: legacy source left it empty (every action must be SHA-pinned), "+
			"but resolved value is %v (inherited from base %v)", got, baseTrustedOwners)
	}
}

// TestSlimToOverlay_TrustDockerHubOfficialImagesNilNotWidened is the
// trust-widening regression case for
// containerImageMustComeFromAuthorizedSources.trustDockerHubOfficialImages.
// Unlike trustGithubOfficialActions/trustSameOrgActions (whose nil
// scan-time fallback of true matches the base's literal true), this
// field's nil fallback in control/task.go is FALSE while the base sets it
// to true. A legacy source that enables the control but never mentions
// this *bool therefore has an effective (scan-time) value of false; slim
// must pin that effective value explicitly or resolving against base
// widens it to true.
func TestSlimToOverlay_TrustDockerHubOfficialImagesNilNotWidened(t *testing.T) {
	baseCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base-for-test")
	if err != nil {
		t.Fatal(err)
	}
	baseTrust := baseCfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources.TrustDockerHubOfficialImages
	if baseTrust == nil || !*baseTrust {
		t.Fatal("test assumption broken: base trustDockerHubOfficialImages must be true")
	}

	src := `version: "2.0"
gitlab:
  controls:
    containerImageMustComeFromAuthorizedSources:
      enabled: true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(path)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
	if err != nil {
		t.Fatalf("resolve slim overlay: %v", err)
	}

	ctrl := resolved.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources
	if ctrl == nil {
		t.Fatal("containerImageMustComeFromAuthorizedSources must be present after resolve")
	}
	// Mirror control/task.go's own nil => false fallback to compute the
	// effective (scan-time) value, exactly as the scanner would.
	effective := ctrl.TrustDockerHubOfficialImages != nil && *ctrl.TrustDockerHubOfficialImages
	if effective {
		t.Fatalf("trustDockerHubOfficialImages widened: legacy source left it unset "+
			"(nil, effective false at scan time), but resolved effective value is true "+
			"(inherited from base %v)", *baseTrust)
	}
}

// TestSlimToOverlay_PinnedStrictFieldsPreserveExplicitSourceValues is the
// non-regression companion to the three tests above: when a legacy source
// DOES set one of the pinned fields to a non-strict value, that explicit
// value must round-trip through slim -> resolve unchanged, not just the
// zero/strict value.
func TestSlimToOverlay_PinnedStrictFieldsPreserveExplicitSourceValues(t *testing.T) {
	src := `version: "2.0"
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      enabled: true
      minimumStars: 5000
    actionsMustBePinnedByCommitSha:
      enabled: true
      trustedOwners:
        - myorg
gitlab:
  controls:
    containerImageMustComeFromAuthorizedSources:
      enabled: true
      trustDockerHubOfficialImages: true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := slimToOverlay(path)
	if err != nil {
		t.Fatalf("slim: %v", err)
	}

	resolved, _, _, err := configuration.LoadPlumberConfigFromBytes(out, "slim-output-for-test")
	if err != nil {
		t.Fatalf("resolve slim overlay: %v", err)
	}

	if got := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.MinimumStars; got != 5000 {
		t.Fatalf("minimumStars must round-trip unchanged: got %d, want 5000", got)
	}
	if got := resolved.GitHub.Controls.ActionsMustBePinnedByCommitSha.TrustedOwners; !equalStringSlices(got, []string{"myorg"}) {
		t.Fatalf("trustedOwners must round-trip unchanged: got %v, want [myorg]", got)
	}
	ctrl := resolved.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources
	if ctrl == nil || ctrl.TrustDockerHubOfficialImages == nil || !*ctrl.TrustDockerHubOfficialImages {
		t.Fatalf("trustDockerHubOfficialImages must round-trip as true, got %+v", ctrl)
	}
}

// TestConfigSlimCmd_StdoutOutput covers the default stdout branch of
// configSlimCmd's RunE (empty configSlimOutput), which every other slim
// test bypasses by calling slimToOverlay directly or setting an explicit
// output path.
func TestConfigSlimCmd_StdoutOutput(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "legacy.yaml")
	legacy := `version: "2.0"
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      enabled: true
      trustedGithubActions:
        - myorg
`
	if err := os.WriteFile(src, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	oldFile, oldOutput := configSlimFile, configSlimOutput
	defer func() {
		configSlimFile = oldFile
		configSlimOutput = oldOutput
	}()
	configSlimFile = src
	configSlimOutput = ""

	out := captureStdoutDeferred(t, func() {
		if err := configSlimCmd.RunE(configSlimCmd, nil); err != nil {
			t.Fatalf("slim: %v", err)
		}
	})

	if !strings.Contains(out, "extends: plumber:default") {
		t.Fatalf("expected stdout to contain the overlay's extends line, got: %s", out)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
