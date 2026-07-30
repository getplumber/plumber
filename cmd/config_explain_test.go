package cmd

import "testing"

func TestControlProvenance_OverlayVsBase(t *testing.T) {
	overlay := []byte(`extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      minimumStars: 5000
`)
	prov, err := controlProvenance(overlay)
	if err != nil {
		t.Fatalf("provenance: %v", err)
	}
	if prov["github.controls.githubActionMustComeFromAuthorizedSources"] != "overlay" {
		t.Fatalf("overridden control should be overlay, got %q",
			prov["github.controls.githubActionMustComeFromAuthorizedSources"])
	}
	// A control the overlay never mentioned but base provides is "base".
	if prov["github.controls.actionsMustBePinnedByCommitSha"] != "base" {
		t.Fatalf("inherited control should be base, got %q",
			prov["github.controls.actionsMustBePinnedByCommitSha"])
	}
}

// TestControlProvenance_LegacyNoBaseLabels drives the isOverlay == false
// branch of controlProvenance: a legacy config (no extends) never merges in
// the embedded base, so every control it reports must be labeled "overlay"
// and none may be labeled "base".
func TestControlProvenance_LegacyNoBaseLabels(t *testing.T) {
	legacy := []byte(`version: "2.0"
github:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
    githubActionMustComeFromAuthorizedSources:
      enabled: true
      minimumStars: 5000
`)
	prov, err := controlProvenance(legacy)
	if err != nil {
		t.Fatalf("provenance: %v", err)
	}
	if len(prov) == 0 {
		t.Fatal("expected controlProvenance to report the legacy file's controls")
	}
	for key, label := range prov {
		if label != "overlay" {
			t.Fatalf("legacy config control %q should be labeled overlay, got %q", key, label)
		}
	}
	if _, ok := prov["github.controls.actionsMustBePinnedByCommitSha"]; !ok {
		t.Fatal("expected actionsMustBePinnedByCommitSha to be reported")
	}
}
