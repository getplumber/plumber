package configuration

import "testing"

// The GitLab plan a control or a field needs is CLI knowledge: before the
// 2026-09-22 issues-page review (ask 56, spec section 5.3) the console
// curated its own map of it, which drifted from the engine. Tier is that
// knowledge, and it is a closed set: the empty string (every plan),
// premium, or ultimate. Anything else is a typo no consumer can render.
func TestControlTier_ClosedSet(t *testing.T) {
	allowed := map[string]bool{"": true, TierPremium: true, TierUltimate: true}
	for _, e := range ControlsCatalog() {
		if !allowed[e.Tier] {
			t.Errorf("control %q has tier %q, want the empty string, %q or %q", e.Name, e.Tier, TierPremium, TierUltimate)
		}
	}
	for path, doc := range controlFieldDocs {
		if !allowed[doc.Tier] {
			t.Errorf("field %s has tier %q, want the empty string, %q or %q", path, doc.Tier, TierPremium, TierUltimate)
		}
	}
}

// The four controls and three fields GitLab gates behind a paid plan
// (ask 56): approval rules and approval settings are Premium, a security
// policy source is Ultimate, and the three merge-request settings fields
// are Premium. Every other control asserts something on Free.
func TestControlTier_TheGitLabGatedControlsAndFields(t *testing.T) {
	wantControls := map[string]string{
		"mergeRequestApprovalRulesMustRequireMinimumApprovals":   TierPremium,
		"mergeRequestApprovalRulesMustCoverAllProtectedBranches": TierPremium,
		"mergeRequestApprovalSettingsMustBeCompliant":            TierPremium,
		"projectMustHaveSecurityPolicySource":                    TierUltimate,
	}
	for name, want := range wantControls {
		meta, ok := ControlMetaFor(name)
		if !ok {
			t.Errorf("control %q is not registered", name)
			continue
		}
		if meta.Tier != want {
			t.Errorf("control %q tier = %q, want %q", name, meta.Tier, want)
		}
	}
	for _, e := range ControlsCatalog() {
		if _, gated := wantControls[e.Name]; !gated && e.Tier != "" {
			t.Errorf("control %q carries tier %q; only the gated controls of ask 56 carry one", e.Name, e.Tier)
		}
	}

	wantFields := map[string]string{
		"mergeRequestSettingsMustBeCompliant.mergePipelinesEnabled": TierPremium,
		"mergeRequestSettingsMustBeCompliant.mergeTrainsEnabled":    TierPremium,
		"branchMustBeProtected.codeOwnerApprovalRequired":           TierPremium,
	}
	for path, want := range wantFields {
		doc, ok := controlFieldDocs[path]
		if !ok {
			t.Errorf("field %s has no doc entry", path)
			continue
		}
		if doc.Tier != want {
			t.Errorf("field %s tier = %q, want %q", path, doc.Tier, want)
		}
	}
	for path, doc := range controlFieldDocs {
		if _, gated := wantFields[path]; !gated && doc.Tier != "" {
			t.Errorf("field %s carries tier %q; only the gated fields of ask 56 carry one", path, doc.Tier)
		}
	}
}

// The welded schema carries the field tier, so a consumer reading one
// control's schema sees which field its plan cannot satisfy.
func TestControlTier_WeldedOntoTheSchemaField(t *testing.T) {
	s, ok := ConfigSchemaFor("mergeRequestSettingsMustBeCompliant")
	if !ok {
		t.Fatal("mergeRequestSettingsMustBeCompliant has no schema")
	}
	byName := map[string]SchemaField{}
	for _, f := range s.Fields {
		byName[f.Name] = f
	}
	if got := byName["mergePipelinesEnabled"].Tier; got != TierPremium {
		t.Errorf("mergePipelinesEnabled tier = %q, want %q", got, TierPremium)
	}
	if got := byName["mergeMethod"].Tier; got != "" {
		t.Errorf("mergeMethod tier = %q, want the empty string", got)
	}
}
