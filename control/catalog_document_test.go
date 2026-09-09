package control

import "testing"

// Catalog is the single aggregate the platform imports and the catalog
// command serializes (#458): every control with its id, wording, schema and
// issue mapping, plus every issue type, in deterministic order.
func TestCatalogDocument(t *testing.T) {
	doc := Catalog("1.2.3")

	if doc.CatalogVersion != 1 || doc.CLIVersion != "1.2.3" {
		t.Fatalf("envelope = v%d cli %q, want v1 cli 1.2.3", doc.CatalogVersion, doc.CLIVersion)
	}
	if len(doc.Controls) == 0 || len(doc.IssueTypes) == 0 {
		t.Fatal("empty catalog")
	}

	byName := map[string]CatalogControl{}
	for i, c := range doc.Controls {
		byName[c.Name] = c
		if c.ID == "" || c.DisplayName == "" || c.Description == "" || c.Category == "" {
			t.Errorf("control %q missing id/display/description/category: %+v", c.Name, c)
		}
		if i > 0 && doc.Controls[i-1].Name >= c.Name {
			t.Errorf("controls not sorted by name at %q", c.Name)
		}
	}

	// Every issue type's ControlName that exists in the registry appears in
	// that control's IssueCodes (the backlink inverted).
	for _, it := range doc.IssueTypes {
		if it.Code == "" || it.Severity == "" || it.Title == "" {
			t.Errorf("issue type missing basics: %+v", it)
		}
		c, ok := byName[it.ControlName]
		if !ok {
			continue // codes for benched/unregistered controls are allowed
		}
		var found bool
		for _, code := range c.IssueCodes {
			if code == it.Code {
				found = true
			}
		}
		if !found {
			t.Errorf("issue %s not listed in control %q IssueCodes", it.Code, it.ControlName)
		}
	}

	// A control with a config block carries its schema.
	if c := byName["cicdVariablesMustBeProtected"]; c.ConfigSchema == nil {
		t.Error("cicdVariablesMustBeProtected has a config block but no schema in the catalog")
	}

	// requiresConfig is exported authored truth (#458 amendment): a
	// control that is inert without configuration (mergeRequestApproval-
	// RulesMustRequireMinimumApprovals: "unset asserts nothing") carries
	// requiresConfig true, while a control whose logic is self-contained
	// once enabled (cicdVariablesMustBeProtected: config-free beyond
	// enabled) carries requiresConfig false.
	if c := byName["mergeRequestApprovalRulesMustRequireMinimumApprovals"]; !c.RequiresConfig {
		t.Error("mergeRequestApprovalRulesMustRequireMinimumApprovals should carry requiresConfig true")
	}
	if c := byName["cicdVariablesMustBeProtected"]; c.RequiresConfig {
		t.Error("cicdVariablesMustBeProtected should carry requiresConfig false")
	}
}
