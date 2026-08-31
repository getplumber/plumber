package configuration

import "testing"

// The exported control catalog (#440) is the single source for display
// metadata: every control the engine knows about must carry a non-empty
// docs-catalog name and one of the closed category set, or a consumer
// falls back to the raw camelCase identifier - the exact drift this table
// exists to end.
func TestControlsCatalogIsComplete(t *testing.T) {
	valid := map[string]bool{
		CategoryContainerImages: true, CategoryCICDVariables: true,
		CategoryCICDSecrets: true, CategoryPipelineComposition: true,
		CategoryAccessAndAuthorization: true, CategorySecuritySource: true,
		CategoryThirdPartyActions: true, CategoryWorkflowTriggersAndPermissions: true,
		CategoryRepositoryHygiene: true,
	}
	cat := ControlsCatalog()
	if len(cat) != len(controlsMeta) {
		t.Fatalf("catalog has %d entries, registry %d", len(cat), len(controlsMeta))
	}
	for _, e := range cat {
		if e.DisplayName == "" {
			t.Errorf("%s: empty DisplayName", e.Name)
		}
		if !valid[e.Category] {
			t.Errorf("%s: category %q is not one of the docs-catalog headings", e.Name, e.Category)
		}
		if len(e.Providers) == 0 {
			t.Errorf("%s: no providers", e.Name)
		}
	}
	// Sorted, and consistent with the single-name accessor.
	for i := 1; i < len(cat); i++ {
		if cat[i-1].Name >= cat[i].Name {
			t.Fatalf("catalog not sorted at %q", cat[i].Name)
		}
	}
	meta, ok := ControlMetaFor("branchMustBeProtected")
	if !ok || meta.DisplayName != "Branch must be protected" || meta.Category != CategoryAccessAndAuthorization {
		t.Fatalf("ControlMetaFor(branchMustBeProtected) = (%+v, %v)", meta, ok)
	}
	if _, ok := ControlMetaFor("noSuchControl"); ok {
		t.Fatal("an unknown control must not resolve")
	}
}
