package control

import (
	"encoding/json"
	"testing"
)

// The catalog JSON is where the console reads the GitLab plan a control or
// a field needs (ask 56, spec section 5.3): requiresTier on the control,
// tier on the config-schema field, both absent when no plan is required so
// the common case stays quiet on the wire.
func TestCatalogJSONNamesTheGitLabTier(t *testing.T) {
	raw, err := json.Marshal(Catalog("1.2.3"))
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	var doc struct {
		Controls []struct {
			Name         string `json:"name"`
			RequiresTier string `json:"requiresTier"`
			ConfigSchema *struct {
				Fields []struct {
					Name string `json:"name"`
					Tier string `json:"tier"`
				} `json:"fields"`
			} `json:"configSchema"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}

	wantControls := map[string]string{
		"mergeRequestApprovalRulesMustRequireMinimumApprovals":   "premium",
		"mergeRequestApprovalRulesMustCoverAllProtectedBranches": "premium",
		"mergeRequestApprovalSettingsMustBeCompliant":            "premium",
		"projectMustHaveSecurityPolicySource":                    "ultimate",
	}
	wantFields := map[string]map[string]string{
		"mergeRequestSettingsMustBeCompliant": {
			"mergePipelinesEnabled": "premium",
			"mergeTrainsEnabled":    "premium",
		},
		"branchMustBeProtected": {
			"codeOwnerApprovalRequired": "premium",
		},
	}
	seen := 0
	for _, c := range doc.Controls {
		if got := c.RequiresTier; got != wantControls[c.Name] {
			t.Errorf("control %q requiresTier = %q, want %q", c.Name, got, wantControls[c.Name])
		}
		fields := wantFields[c.Name]
		if fields == nil || c.ConfigSchema == nil {
			continue
		}
		for _, f := range c.ConfigSchema.Fields {
			if got := f.Tier; got != fields[f.Name] {
				t.Errorf("control %q field %q tier = %q, want %q", c.Name, f.Name, got, fields[f.Name])
			}
			if fields[f.Name] != "" {
				seen++
			}
		}
	}
	if seen != 3 {
		t.Errorf("saw %d gated fields in the catalog JSON, want 3", seen)
	}

	// Absent, not empty: a control on every plan carries no requiresTier key.
	var loose struct {
		Controls []map[string]any `json:"controls"`
	}
	if err := json.Unmarshal(raw, &loose); err != nil {
		t.Fatalf("unmarshal catalog loosely: %v", err)
	}
	for _, c := range loose.Controls {
		if _, ok := c["requiresTier"]; ok && wantControls[c["name"].(string)] == "" {
			t.Errorf("control %v carries a requiresTier key with no tier to name", c["name"])
		}
	}
}
