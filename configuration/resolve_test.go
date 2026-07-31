package configuration

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/defaultconfig"
	"gopkg.in/yaml.v2"
)

func TestDetectExtends(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		want    string
		wantErr bool
	}{
		{"absent", "version: \"2.0\"\n", "", false},
		{"plumber default", "extends: plumber:default\nversion: \"2.0\"\n", "plumber:default", false},
		{"whitespace trimmed", "extends: \"  plumber:default  \"\n", "plumber:default", false},
		{"unsupported value", "extends: some:other\n", "", true},
		{"invalid yaml is not an extends error", "::::\n", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := detectExtends([]byte(tc.yaml))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveOverlayBytes_EmptyOverlayEqualsBase(t *testing.T) {
	overlay := []byte("extends: plumber:default\n")
	merged, err := resolveOverlayBytes(overlay)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var m map[interface{}]interface{}
	if err := yaml.Unmarshal(merged, &m); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}
	if _, ok := m["extends"]; ok {
		t.Fatal("extends key must be stripped from resolved output")
	}
	if _, ok := m["github"]; !ok {
		t.Fatal("resolved config should carry the base github section")
	}
}

func TestResolveOverlayBytes_OverridesOneFieldKeepsSiblings(t *testing.T) {
	overlay := []byte(`extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      minimumStars: 5000
`)
	merged, err := resolveOverlayBytes(overlay)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	cfg := &PlumberConfig{}
	if err := yaml.Unmarshal(merged, cfg); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	c := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources
	if c == nil || c.MinimumStars != 5000 {
		t.Fatalf("minimumStars override lost: %+v", c)
	}
	if c.Enabled == nil || !*c.Enabled {
		t.Fatal("enabled should still be inherited from base")
	}
}

func TestMaterialize_UnionByDefault(t *testing.T) {
	base := &PlumberConfig{GitHub: &ProviderConfig{Controls: ControlsConfig{
		GithubActionMustComeFromAuthorizedSources: &ActionAuthorizedSourcesControlConfig{
			TrustedGithubActions: []string{"base1", "base2"},
		},
	}}}
	resolved := &PlumberConfig{GitHub: &ProviderConfig{Controls: ControlsConfig{
		GithubActionMustComeFromAuthorizedSources: &ActionAuthorizedSourcesControlConfig{
			TrustedGithubActions: []string{"myorg"}, // list-replaced by merge
		},
	}}}
	overlay := &PlumberConfig{GitHub: &ProviderConfig{Controls: ControlsConfig{
		GithubActionMustComeFromAuthorizedSources: &ActionAuthorizedSourcesControlConfig{
			TrustedGithubActions: []string{"myorg"}, // include defaults nil => true
		},
	}}}

	materializeAuthorizedSources(resolved, base, overlay)

	got := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	want := []string{"base1", "base2", "myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestMaterialize_FalseUsesOnlyUserList(t *testing.T) {
	base := &PlumberConfig{GitHub: &ProviderConfig{Controls: ControlsConfig{
		GithubActionMustComeFromAuthorizedSources: &ActionAuthorizedSourcesControlConfig{
			TrustedGithubActions: []string{"base1"},
		},
	}}}
	resolved := &PlumberConfig{GitHub: &ProviderConfig{Controls: ControlsConfig{
		GithubActionMustComeFromAuthorizedSources: &ActionAuthorizedSourcesControlConfig{
			TrustedGithubActions: []string{"myorg"},
		},
	}}}
	overlay := &PlumberConfig{GitHub: &ProviderConfig{Controls: ControlsConfig{
		GithubActionMustComeFromAuthorizedSources: &ActionAuthorizedSourcesControlConfig{
			IncludePlumberDefaults: boolPtr(false),
			TrustedGithubActions:   []string{"myorg"},
		},
	}}}

	materializeAuthorizedSources(resolved, base, overlay)

	got := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if !reflect.DeepEqual(got, []string{"myorg"}) {
		t.Fatalf("got %v want [myorg]", got)
	}
}

// firstCuratedTrustedAction loads the real embedded default config and
// returns the first entry of its curated trustedGithubActions list. Tests
// use this instead of hardcoding a specific org, so they stay robust to
// future changes in the curated list.
func firstCuratedTrustedAction(t *testing.T) string {
	t.Helper()
	baseCfg, _, _, err := LoadPlumberConfigFromBytes(defaultconfig.Get(), "base")
	if err != nil {
		t.Fatalf("load base: %v", err)
	}
	baseList := baseCfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if len(baseList) == 0 {
		t.Fatal("expected curated base trustedGithubActions to be non-empty")
	}
	return baseList[0]
}

// --- Task 6: wiring resolution into LoadPlumberConfigFromBytes ---

func TestLoadPlumberConfigFromBytes_OverlayResolves(t *testing.T) {
	overlay := []byte(`extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      trustedGithubActions:
        - myorg
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "test-overlay")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources
	if c == nil {
		t.Fatal("control missing after resolve")
	}
	// base entries inherited (union), plus myorg present
	foundMyorg := false
	for _, a := range c.TrustedGithubActions {
		if a == "myorg" {
			foundMyorg = true
		}
	}
	if !foundMyorg {
		t.Fatal("myorg not present in resolved list")
	}
	if len(c.TrustedGithubActions) <= 1 {
		t.Fatalf("expected base list unioned in, got %v", c.TrustedGithubActions)
	}
	if cfg.Extends != "" {
		t.Fatal("resolved config should not carry extends after resolution")
	}
}

func TestLoadPlumberConfigFromBytes_LegacyUnchanged(t *testing.T) {
	legacy := []byte(`version: "2.0"
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      enabled: true
      trustedGithubActions:
        - onlyorg
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(legacy, "legacy")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if !reflect.DeepEqual(got, []string{"onlyorg"}) {
		t.Fatalf("legacy list must be replace-only, got %v", got)
	}
}

func TestLoadPlumberConfigFromBytes_BadExtendsErrors(t *testing.T) {
	if _, _, _, err := LoadPlumberConfigFromBytes([]byte("extends: nope\n"), "bad"); err == nil {
		t.Fatal("expected error for unsupported extends value")
	}
}

// TestLoadPlumberConfigFromBytes_LegacyByteIdentical proves that a
// no-extends config is untouched all the way down to config.Raw: the
// resolution wiring must be a complete no-op for legacy files, not just
// "same parsed values". This is the backward-compat guarantee the whole
// task is gated on.
func TestLoadPlumberConfigFromBytes_LegacyByteIdentical(t *testing.T) {
	legacy := []byte(`version: "2.0"
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      enabled: true
      trustedGithubActions:
        - onlyorg
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(legacy, "legacy")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Raw != string(legacy) {
		t.Fatalf("legacy config.Raw must be byte-identical to input.\ngot:  %q\nwant: %q", cfg.Raw, string(legacy))
	}
}

// TestLoadPlumberConfigFromBytes_OverlayNarrowsTrustedActions is the
// end-to-end trust test: it proves materializeAuthorizedSources is wired
// into the real load path (not dead code) by showing includePlumberDefaults:
// false actually narrows the resolved list to ONLY the user's entries, with
// the curated base entries absent. Loaded via the full LoadPlumberConfigFromBytes
// path, not by calling materialize directly.
func TestLoadPlumberConfigFromBytes_OverlayNarrowsTrustedActions(t *testing.T) {
	firstBase := firstCuratedTrustedAction(t)

	overlay := []byte(`extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      includePlumberDefaults: false
      trustedGithubActions:
        - myorg
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "narrow-overlay")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if !reflect.DeepEqual(got, []string{"myorg"}) {
		t.Fatalf("includePlumberDefaults:false must narrow to only user entries, got %v", got)
	}
	for _, a := range got {
		if a == firstBase {
			t.Fatalf("curated base entry %q must be absent when includePlumberDefaults is false", firstBase)
		}
	}
}

// TestLoadPlumberConfigFromBytes_OverlayDefaultUnionsTrustedActions is the
// counterpart: when the toggle is omitted, the resolved list is base union
// user (curated entries present alongside the user's own).
func TestLoadPlumberConfigFromBytes_OverlayDefaultUnionsTrustedActions(t *testing.T) {
	firstBase := firstCuratedTrustedAction(t)

	overlay := []byte(`extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      trustedGithubActions:
        - myorg
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "union-overlay")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	foundBase := false
	foundUser := false
	for _, a := range got {
		if a == firstBase {
			foundBase = true
		}
		if a == "myorg" {
			foundUser = true
		}
	}
	if !foundBase {
		t.Fatalf("default (toggle omitted) must include curated base entry %q, got %v", firstBase, got)
	}
	if !foundUser {
		t.Fatalf("default (toggle omitted) must include the user's own entry, got %v", got)
	}
}

// TestLoadPlumberConfigFromBytes_OverlayDedupsOverlappingEntry covers the
// dedup-overlap case: the overlay repeats the first curated base entry
// alongside a new one ("myorg"). The resolved list must contain the
// repeated entry exactly once, with order preserved (base order first).
func TestLoadPlumberConfigFromBytes_OverlayDedupsOverlappingEntry(t *testing.T) {
	firstBase := firstCuratedTrustedAction(t)

	overlay := []byte(fmt.Sprintf(`extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      trustedGithubActions:
        - %s
        - myorg
`, firstBase))
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "dedup-overlay")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions

	count := 0
	idx := -1
	for i, a := range got {
		if a == firstBase {
			count++
			idx = i
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one %q entry, got %d occurrences in %v", firstBase, count, got)
	}
	if idx != 0 {
		t.Fatalf("expected %q to keep its base position (0), got index %d in %v", firstBase, idx, got)
	}
	if got[len(got)-1] != "myorg" {
		t.Fatalf("expected \"myorg\" appended at the end (order preserved), got %v", got)
	}
}

// TestLoadPlumberConfigFromBytes_MalformedYAMLFailsClosed confirms the
// ordering guarantee: detectExtends deliberately swallows malformed YAML
// (returns "" with no error, deferring to the normal loader), but the
// subsequent real unmarshal of effectiveData must still fail closed on
// the same malformed input rather than silently succeeding with a zero
// value config.
func TestLoadPlumberConfigFromBytes_MalformedYAMLFailsClosed(t *testing.T) {
	// Genuinely malformed YAML (unterminated flow sequence): fails to
	// unmarshal even into a generic map[interface{}]interface{}.
	malformed := []byte("github:\n  controls: [1, 2\nfoo: 3\n")
	// Sanity check: detectExtends swallows the parse error and reports
	// "no extends", deferring entirely to the normal loader.
	extendsVal, extErr := detectExtends(malformed)
	if extErr != nil || extendsVal != "" {
		t.Fatalf("test premise broken: detectExtends(%q) = (%q, %v), want (\"\", nil)", malformed, extendsVal, extErr)
	}
	if _, _, _, err := LoadPlumberConfigFromBytes(malformed, "malformed"); err == nil {
		t.Fatal("expected malformed YAML to fail closed with an error from the real unmarshal")
	}
}

// TestLoadPlumberConfigFromBytes_RawReflectsMaterializedAllowlist is the
// regression guard for finding #6: config.Raw is the verbatim source the
// audit report's self-describing `plumberConfig` block (and its sha256
// hash) is built from, so it must reflect what actually ran -- the
// MATERIALIZED (unioned) trust list, not the overlay's own sparse list
// captured before materializeAuthorizedSources ran. Pre-fix, Raw was set
// from effectiveData before the materialize block executed, so it held
// only the overlay's own trustedGithubActions entry ("myorg") and never
// the ~140-entry curated base list actually merged into the resolved
// struct.
func TestLoadPlumberConfigFromBytes_RawReflectsMaterializedAllowlist(t *testing.T) {
	firstBase := firstCuratedTrustedAction(t)

	overlay := []byte(`extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      trustedGithubActions:
        - myorg
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "raw-materialize-overlay")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	got := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	found := false
	for _, a := range got {
		if a == firstBase {
			found = true
		}
	}
	if !found {
		t.Fatalf("resolved struct must contain base entry %q, got %v", firstBase, got)
	}

	if !strings.Contains(cfg.Raw, firstBase) {
		t.Fatalf("config.Raw must contain the materialized base entry %q "+
			"(regression guard for finding #6: Raw must reflect what actually ran); Raw:\n%s",
			firstBase, cfg.Raw)
	}
}

// firstCuratedTrustedURL loads the real embedded default and returns the
// first entry of its curated containerImageMustComeFromAuthorizedSources
// trustedUrls list. Mirrors firstCuratedTrustedAction for the GitLab
// container-image control.
func firstCuratedTrustedURL(t *testing.T) string {
	t.Helper()
	baseCfg, _, _, err := LoadPlumberConfigFromBytes(defaultconfig.Get(), "base")
	if err != nil {
		t.Fatalf("load base: %v", err)
	}
	baseList := baseCfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources.TrustedUrls
	if len(baseList) == 0 {
		t.Fatal("expected curated base trustedUrls to be non-empty")
	}
	return baseList[0]
}

// TestLoadPlumberConfigFromBytes_OverlayDefaultUnionsTrustedUrls is finding
// #9's missing coverage: materializeAuthorizedSources has two parallel
// branches (GitHub trustedGithubActions and GitLab trustedUrls) but only
// the GitHub one had an end-to-end default-union test. This is the GitLab
// containerImageMustComeFromAuthorizedSources mirror of
// TestLoadPlumberConfigFromBytes_OverlayDefaultUnionsTrustedActions: when
// includePlumberDefaults is omitted, the resolved trustedUrls is base
// union user.
func TestLoadPlumberConfigFromBytes_OverlayDefaultUnionsTrustedUrls(t *testing.T) {
	firstBase := firstCuratedTrustedURL(t)

	overlay := []byte(`extends: plumber:default
gitlab:
  controls:
    containerImageMustComeFromAuthorizedSources:
      trustedUrls:
        - myregistry/*
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "union-overlay-gitlab")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	got := cfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources.TrustedUrls
	foundBase := false
	foundUser := false
	for _, u := range got {
		if u == firstBase {
			foundBase = true
		}
		if u == "myregistry/*" {
			foundUser = true
		}
	}
	if !foundBase {
		t.Fatalf("default (toggle omitted) must include curated base entry %q, got %v", firstBase, got)
	}
	if !foundUser {
		t.Fatalf("default (toggle omitted) must include the user's own entry, got %v", got)
	}
}

// TestLoadPlumberConfigFromBytes_OverlayNarrowsTrustedUrls is the GitLab
// containerImageMustComeFromAuthorizedSources mirror of
// TestLoadPlumberConfigFromBytes_OverlayNarrowsTrustedActions: the
// narrowing direction (includePlumberDefaults: false) must resolve to
// ONLY the user's entries, with the curated base trustedUrls absent.
// This is the security-critical direction: a regression that unions the
// curated list back in would silently re-widen container-image trust.
func TestLoadPlumberConfigFromBytes_OverlayNarrowsTrustedUrls(t *testing.T) {
	firstBase := firstCuratedTrustedURL(t)

	overlay := []byte(`extends: plumber:default
gitlab:
  controls:
    containerImageMustComeFromAuthorizedSources:
      includePlumberDefaults: false
      trustedUrls:
        - myregistry/*
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "narrow-overlay-gitlab")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := cfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources.TrustedUrls
	if !reflect.DeepEqual(got, []string{"myregistry/*"}) {
		t.Fatalf("includePlumberDefaults:false must narrow to only user entries, got %v", got)
	}
	for _, u := range got {
		if u == firstBase {
			t.Fatalf("curated base entry %q must be absent when includePlumberDefaults is false", firstBase)
		}
	}
}

// TestLoadPlumberConfigFromBytes_NullOverlaySectionInheritsBase is the
// end-to-end regression guard for the "null overlay wipes base" bug: an
// overlay that extends plumber:default and leaves gitlab.controls empty
// (e.g. every control under it commented out) must NOT wipe the inherited
// base gitlab controls. A base-enabled control (branchMustBeProtected) must
// still be present and enabled after resolution, not silently disabled.
func TestLoadPlumberConfigFromBytes_NullOverlaySectionInheritsBase(t *testing.T) {
	overlay := []byte(`extends: plumber:default
gitlab:
  controls:
    # branchMustBeProtected:
    #   enabled: false
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "null-section-overlay")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := cfg.GitLab.Controls.BranchMustBeProtected
	if c == nil {
		t.Fatal("gitlab.controls.branchMustBeProtected must survive a null gitlab.controls overlay value, got nil (base was wiped)")
	}
	if c.Enabled == nil || !*c.Enabled {
		t.Fatalf("gitlab.controls.branchMustBeProtected must still be enabled from base, got %+v", c)
	}
}

// TestLoadPlumberConfigFromBytes_ScalarOnlyOverlayKeepsBaseTrustedActions
// covers finding #2's missing coverage: when the overlay mentions
// githubActionMustComeFromAuthorizedSources but only sets a scalar
// (minimumStars) and omits trustedGithubActions entirely, the base curated
// list must survive via union(baseList, nil, true) == baseList, not be
// wiped or left empty.
func TestLoadPlumberConfigFromBytes_ScalarOnlyOverlayKeepsBaseTrustedActions(t *testing.T) {
	firstBase := firstCuratedTrustedAction(t)
	baseCfg, _, _, err := LoadPlumberConfigFromBytes(defaultconfig.Get(), "base")
	if err != nil {
		t.Fatalf("load base: %v", err)
	}
	baseLen := len(baseCfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions)

	overlay := []byte(`extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      minimumStars: 5000
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "scalar-only-overlay-github")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources
	if c == nil {
		t.Fatal("control missing after resolve")
	}
	if c.MinimumStars != 5000 {
		t.Fatalf("minimumStars override lost, got %d", c.MinimumStars)
	}
	found := false
	for _, a := range c.TrustedGithubActions {
		if a == firstBase {
			found = true
		}
	}
	if !found {
		t.Fatalf("scalar-only overlay must not wipe inherited base trustedGithubActions; base entry %q missing from %v", firstBase, c.TrustedGithubActions)
	}
	if len(c.TrustedGithubActions) != baseLen {
		t.Fatalf("scalar-only overlay must keep the base trustedGithubActions list intact, got len %d want %d", len(c.TrustedGithubActions), baseLen)
	}
}

// TestLoadPlumberConfigFromBytes_ScalarOnlyOverlayKeepsBaseTrustedUrls
// mirrors the GitHub case above for GitLab's
// containerImageMustComeFromAuthorizedSources: the overlay mentions the
// control (setting only `enabled: true`, since this control has no other
// scalar besides enabled) and omits trustedUrls entirely. The inherited
// base trustedUrls list must survive intact.
func TestLoadPlumberConfigFromBytes_ScalarOnlyOverlayKeepsBaseTrustedUrls(t *testing.T) {
	firstBase := firstCuratedTrustedURL(t)
	baseCfg, _, _, err := LoadPlumberConfigFromBytes(defaultconfig.Get(), "base")
	if err != nil {
		t.Fatalf("load base: %v", err)
	}
	baseLen := len(baseCfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources.TrustedUrls)

	overlay := []byte(`extends: plumber:default
gitlab:
  controls:
    containerImageMustComeFromAuthorizedSources:
      enabled: true
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(overlay, "scalar-only-overlay-gitlab")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := cfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources
	if c == nil {
		t.Fatal("control missing after resolve")
	}
	if c.Enabled == nil || !*c.Enabled {
		t.Fatalf("enabled override lost, got %+v", c)
	}
	found := false
	for _, u := range c.TrustedUrls {
		if u == firstBase {
			found = true
		}
	}
	if !found {
		t.Fatalf("scalar-only overlay must not wipe inherited base trustedUrls; base entry %q missing from %v", firstBase, c.TrustedUrls)
	}
	if len(c.TrustedUrls) != baseLen {
		t.Fatalf("scalar-only overlay must keep the base trustedUrls list intact, got len %d want %d", len(c.TrustedUrls), baseLen)
	}
}

func TestMaterialize_ControlNotInOverlayIsUntouched(t *testing.T) {
	base := &PlumberConfig{GitHub: &ProviderConfig{Controls: ControlsConfig{
		GithubActionMustComeFromAuthorizedSources: &ActionAuthorizedSourcesControlConfig{
			TrustedGithubActions: []string{"base1"},
		},
	}}}
	resolved := &PlumberConfig{GitHub: &ProviderConfig{Controls: ControlsConfig{
		GithubActionMustComeFromAuthorizedSources: &ActionAuthorizedSourcesControlConfig{
			TrustedGithubActions: []string{"base1"}, // inherited full list via merge
		},
	}}}
	overlay := &PlumberConfig{} // overlay never mentioned this control

	materializeAuthorizedSources(resolved, base, overlay)

	got := resolved.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if !reflect.DeepEqual(got, []string{"base1"}) {
		t.Fatalf("got %v want [base1]", got)
	}
}
