package expr

import "testing"

type facts map[string]string

func (f facts) Resolve(ref string) (string, bool) { v, ok := f[ref]; return v, ok }

func TestEvalThreeValued(t *testing.T) {
	f := facts{"github.event_name": "pull_request_target", "github.event.label.name": "safe to test", "github.event.pull_request.labels.*.name": "bug\nsafe to test"}
	cases := []struct {
		expr string
		want Value
	}{
		{"github.event_name == 'pull_request_target'", True},
		{"${{ github.event_name == 'push' }}", False},
		{"github.event_name == 'push' || github.event.label.name == 'safe to test'", True},
		{"github.event_name == 'push' && inputs.run == 'yes'", False},
		{"github.event_name == 'pull_request_target' && inputs.run == 'yes'", Unknown},
		{"contains(github.event.pull_request.labels.*.name, 'safe to test')", True},
		{"!contains(github.event.pull_request.labels.*.name, 'ok-to-test')", True},
		{"startsWith(github.ref, 'refs/tags/')", Unknown},
		{"(github.event_name == 'push') || (unknown.thing == 'x')", Unknown},
		{"(unknown.thing == 'x') || (github.event_name == 'pull_request_target')", True},
		{"true", True},
		{"false && anything", False},
	}
	for _, c := range cases {
		if got := Eval(c.expr, f); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestRefsListsEveryReference(t *testing.T) {
	got := Refs("github.event_name == 'push' && needs.gate.outputs.run == 'true'")
	if len(got) != 2 || got[0] != "github.event_name" || got[1] != "needs.gate.outputs.run" {
		t.Errorf("Refs = %v", got)
	}
}

// TestEvalUnsupportedFragmentIsALeaf proves that a fragment the grammar
// does not model (fromJSON(...), a bare garbage token, ...) becomes an
// unknown leaf for the operand it sits in, not for the whole expression.
// A real if: condition often pairs a supported github.*/needs.* check
// with something this grammar does not cover, and the supported half
// must keep deciding instead of going dark along with the unsupported
// one.
func TestEvalUnsupportedFragmentIsALeaf(t *testing.T) {
	f := facts{"github.event_name": "pull_request_target"}
	cases := []struct {
		expr string
		want Value
	}{
		{"false && fromJSON(x).value", False},
		{"true || @@@", True},
		{"github.event_name == 'pull_request' && fromJSON(x).value", False},
	}
	for _, c := range cases {
		if got := Eval(c.expr, f); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}

	got := Refs("github.event_name == 'push' && fromJSON(x).value")
	found := false
	for _, r := range got {
		if r == "github.event_name" {
			found = true
		}
	}
	if !found {
		t.Errorf("Refs = %v, want it to still list github.event_name", got)
	}
}

func TestEvalMalformedInputsNeverPanic(t *testing.T) {
	f := facts{"github.event_name": "push"}
	cases := []struct {
		expr string
		want Value
	}{
		{"", True},
		{"   ", True},
		{"${{   }}", True},
		{"github.event_name ==", Unknown},
		{"(((", Unknown},
		{")))", Unknown},
		{"&&", Unknown},
		{"||", Unknown},
		{"==", Unknown},
		{"github.event_name = 'push'", Unknown},
		{"'unterminated", Unknown},
		{"contains(github.event_name)", Unknown},
		{"contains()", Unknown},
		{"startsWith(github.event_name, 'p', 'extra')", Unknown},
		{"github.event_name == 'push') ", Unknown},
		{"!!!", Unknown},
		{"github.event_name == 'push' &&", Unknown},
		{"() ", Unknown},
		{"github.event_name === 'push'", Unknown},
	}
	for _, c := range cases {
		got := Eval(c.expr, f)
		if got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}
