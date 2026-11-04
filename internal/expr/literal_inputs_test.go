package expr

import "testing"

// TestEvalLiteralInputs pins which conditions may be decided from literal
// inputs alone. A wrong False hides a step that runs, so everything
// outside inputs compared with strings stays Unknown, even where Eval
// would decide it.
func TestEvalLiteralInputs(t *testing.T) {
	f := facts{"inputs.flag": "false", "inputs.mode": "fast", "inputs.empty": "", "inputs.repo-checkout": "false", "INPUTS.flag": "false"}
	cases := []struct {
		expr string
		want Value
	}{
		{"inputs.flag != 'false'", False},
		{"inputs.flag == 'false'", True},
		{"inputs.flag == 'FALSE'", True},
		{"'false' != inputs.flag", False},
		{"${{ inputs.flag != 'false' }}", False},
		{"inputs.repo-checkout != 'false'", False},
		{"INPUTS.flag != 'false'", False},
		{"inputs.empty == ''", True},
		{"inputs.flag == inputs.mode", False},
		{"!(inputs.flag == 'false')", False},
		{"inputs.flag == 'true' || inputs.mode == 'slow'", False},
		{"inputs.flag == 'false' && inputs.mode == 'slow'", False},
		{"inputs.flag == 'true' && inputs.absent == 'x'", False},
		{"inputs.absent != 'false'", Unknown},
		{"inputs.flag == 'false' || inputs.absent == 'x'", True},

		// GitHub reads these differently from a string comparison.
		{"inputs.flag", Unknown},
		{"!inputs.flag", Unknown},
		{"inputs.flag == false", Unknown},
		{"inputs.flag == true", Unknown},
		{"inputs.flag == 1", Unknown},
		{"inputs.flag == null", Unknown},

		// Anything that reads more than inputs stays inlined.
		{"inputs.flag == 'true' && github.ref == 'refs/heads/main'", Unknown},
		{"github.ref == 'refs/heads/main'", Unknown},
		{"env.FLAG != 'false'", Unknown},
		{"steps.a.outputs.b == 'false'", Unknown},
		{"inputs.flag == 'true' && always()", Unknown},
		{"always()", Unknown},
		{"contains(inputs.flag, 'x')", Unknown},
		{"inputs['flag'] == 'true'", Unknown},
		{"inputs.a.b == 'true'", Unknown},
		{"inputs.*.b == 'true'", Unknown},
		{"inputs. == 'true'", Unknown},
		{"false", Unknown},
		{"", Unknown},
		{"${{ inputs.flag == 'true' }} && ${{ inputs.mode == 'x' }}", Unknown},
		{"inputs.flag == 'true' && (", Unknown},
	}
	for _, c := range cases {
		if got := EvalLiteralInputs(c.expr, f); got != c.want {
			t.Errorf("EvalLiteralInputs(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}
