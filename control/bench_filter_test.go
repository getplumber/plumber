package control

import "testing"

func TestIsRegoFileBenchedForProvider_allCodesBenched(t *testing.T) {
	// dependabotEcosystemsMustHaveCooldown is GitHub-benched today.
	content := []byte(`package dependabot_cooldown
deny contains finding if {
    finding := {"code": "ISSUE-902", "severity": "low"}
}`)
	if !IsRegoFileBenchedForProvider(content, "github") {
		t.Error("expected ISSUE-902-only file to be benched on GitHub")
	}
}

func TestIsRegoFileBenchedForProvider_oneShipping_keepsLoaded(t *testing.T) {
	// ISSUE-410 (securityJobsMustNotBeWeakened) is shipping. Even if a
	// bench code appears in the same file, the file must load.
	content := []byte(`package security
deny contains finding if { finding := {"code": "ISSUE-410"} }
deny contains finding if { finding := {"code": "ISSUE-902"} }`)
	if IsRegoFileBenchedForProvider(content, "github") {
		t.Error("file with at least one shipping code must load")
	}
}

func TestIsRegoFileBenchedForProvider_noCodes_keepsLoaded(t *testing.T) {
	// Helper / placeholder modules with no ISSUE codes must always
	// load — they don't produce findings, but other modules may
	// import them.
	content := []byte(`package placeholder`)
	if IsRegoFileBenchedForProvider(content, "github") {
		t.Error("code-free file must load")
	}
}

func TestIsRegoFileBenchedForProvider_unknownCode_keepsLoaded(t *testing.T) {
	// Defensive: an ISSUE-XXX not in the registry must NOT be treated
	// as benched. Better to surface a noisy unknown-code finding than
	// silently drop a real rule.
	content := []byte(`package weird
deny contains finding if { finding := {"code": "ISSUE-99999"} }`)
	if IsRegoFileBenchedForProvider(content, "github") {
		t.Error("unknown code must default to load")
	}
}

func TestIsRegoFileBenchedForProvider_perProvider(t *testing.T) {
	// The bench is keyed by provider: dependabotEcosystemsMustHaveCooldown
	// (ISSUE-902) is benched on GitHub and not on GitLab, so the same rule
	// file is skipped on GitHub and loads on GitLab. (No cross-provider
	// control is GitHub-benched any more: the eight GitLab-shaped ones that
	// were now declare GitLab only.)
	content := []byte(`package dependabot_cooldown
deny contains finding if { finding := {"code": "ISSUE-902"} }`)
	if IsRegoFileBenchedForProvider(content, "gitlab") {
		t.Error("ISSUE-902 is not benched on GitLab, must load")
	}
	if !IsRegoFileBenchedForProvider(content, "github") {
		t.Error("ISSUE-902 is benched on GitHub, must skip")
	}
}
