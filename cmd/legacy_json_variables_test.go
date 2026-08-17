package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestCicdVariablesJSONBlocks locks the machine-readable legacy-JSON contract
// for the two settings-variable controls: the top-level result key, the metric
// key, and which builder each control routes to are all hand-wired and mutually
// confusable (protected vs masked). A swapped block or a copy-pasted metric key
// would silently emit the wrong shape to JSON consumers with no other guard.
func TestCicdVariablesJSONBlocks(t *testing.T) {
	// Five variables read: the JSON denominator totalVariablesChecked must
	// report that regardless of how many were flagged.
	result := &control.AnalysisResult{
		CiValid:       true,
		VariablesData: &gitlab.GitlabVariablesAnalysisData{Variables: make([]gitlab.CICDVariable, 5), Known: true},
	}

	// Protected -> cicdVariablesProtectedResult, metric unprotectedFound.
	protEntry := control.ControlEntry{ControlName: "cicdVariablesMustBeProtected"}
	protFindings := []opaengine.Finding{
		{Code: "ISSUE-201", Data: map[string]any{"variableName": "AWS_KEY", "variableType": "env_var", "environment": "*"}},
		{Code: "ISSUE-201", Data: map[string]any{"variableName": "DEPLOY", "variableType": "file", "environment": "production"}},
	}
	name, block := buildLegacyResult(protEntry, result, nil, protFindings)
	if name != "cicdVariablesProtectedResult" {
		t.Fatalf("protected block name = %q, want cicdVariablesProtectedResult (routing/copy-paste)", name)
	}
	m := block.(map[string]any)
	if metrics, ok := m["metrics"].(map[string]any); !ok || metrics["unprotectedFound"] != 2 || metrics["totalVariablesChecked"] != 5 {
		t.Errorf("protected metrics = %v, want unprotectedFound=2 totalVariablesChecked=5", m["metrics"])
	}
	issues, ok := m["issues"].([]map[string]any)
	if !ok || len(issues) != 2 {
		t.Fatalf("protected issues = %v, want 2", m["issues"])
	}
	// Settings-level findings carry the variable identity and no job key.
	if issues[0]["variableName"] == nil || issues[0]["variableType"] == nil || issues[0]["environment"] == nil {
		t.Errorf("issue must preserve variableName/variableType/environment: %v", issues[0])
	}
	if _, hasJob := issues[0]["job"]; hasJob {
		t.Errorf("settings-level finding must carry no job key: %v", issues[0])
	}

	// Masked -> cicdVariablesMaskedResult, metric unmaskedFound, and must NOT
	// leak the protected metric key.
	maskEntry := control.ControlEntry{ControlName: "cicdVariablesMustBeMasked"}
	maskFindings := []opaengine.Finding{
		{Code: "ISSUE-202", Data: map[string]any{"variableName": "PLAIN", "variableType": "env_var", "environment": "*"}},
	}
	name, block = buildLegacyResult(maskEntry, result, nil, maskFindings)
	if name != "cicdVariablesMaskedResult" {
		t.Fatalf("masked block name = %q, want cicdVariablesMaskedResult (routing/copy-paste)", name)
	}
	m = block.(map[string]any)
	metrics, ok := m["metrics"].(map[string]any)
	if !ok || metrics["unmaskedFound"] != 1 || metrics["totalVariablesChecked"] != 5 {
		t.Errorf("masked metrics = %v, want unmaskedFound=1 totalVariablesChecked=5", m["metrics"])
	}
	if _, wrong := metrics["unprotectedFound"]; wrong {
		t.Errorf("masked block leaked the protected metric key unprotectedFound: %v", metrics)
	}
}
