package expr

import (
	"strings"
	"testing"
)

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

// TestEvalAffixDecidesAResolvedReference pins startsWith and endsWith
// on a reference the facts resolve: True on a match, False on none,
// both compared case-insensitively as GitHub does. A job gated on one
// of them must not flip between reachable and unreachable.
func TestEvalAffixDecidesAResolvedReference(t *testing.T) {
	f := facts{"github.event_name": "pull_request_target"}
	cases := []struct {
		expr string
		want Value
	}{
		{"startsWith(github.event_name, 'pull')", True},
		{"startsWith(github.event_name, 'PULL')", True},
		{"startsWith(github.event_name, 'xyz')", False},
		{"startsWith(github.event_name, 'target')", False},
		{"endsWith(github.event_name, 'target')", True},
		{"endsWith(github.event_name, 'TARGET')", True},
		{"endsWith(github.event_name, 'pull')", False},
		{"!startsWith(github.event_name, 'pull')", False},
	}
	for _, c := range cases {
		if got := Eval(c.expr, f); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestEvalContainsASubstringOfAScalar pins contains on a plain scalar
// reference (not a fromJSON list, not a .*.name collection): substring
// membership, compared case-insensitively.
func TestEvalContainsASubstringOfAScalar(t *testing.T) {
	f := facts{"github.event_name": "pull_request_target"}
	cases := []struct {
		expr string
		want Value
	}{
		{"contains(github.event_name, 'request')", True},
		{"contains(github.event_name, 'REQUEST')", True},
		{"contains(github.event_name, 'nope')", False},
		{"!contains(github.event_name, 'request')", False},
	}
	for _, c := range cases {
		if got := Eval(c.expr, f); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestEvalContainsAFromJSONList pins the one fromJSON shape conditions use
// to name a set of events: contains(fromJSON('["a","b"]'), ref) is
// membership in that literal list, compared case-insensitively. A
// fromJSON of anything but a literal list of strings stays unknown.
func TestEvalContainsAFromJSONList(t *testing.T) {
	f := facts{"github.event_name": "pull_request_target"}
	cases := []struct {
		expr string
		want Value
	}{
		{`contains(fromJSON('["push","schedule"]'), github.event_name)`, False},
		{`contains(fromJSON('["push", "PULL_REQUEST_TARGET"]'), github.event_name)`, True},
		{`!contains(fromJSON('["push","schedule"]'), github.event_name)`, True},
		{`contains(fromJSON('["push"]'), inputs.mode)`, Unknown},
		{`contains(fromJSON('{"a":1}'), github.event_name)`, Unknown},
		{`contains(fromJSON('[1,2]'), github.event_name)`, Unknown},
		{`contains(fromJSON(inputs.list), github.event_name)`, Unknown},
	}
	for _, c := range cases {
		if got := Eval(c.expr, f); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestComparedLiteralsListsEveryComparison pins that ComparedLiterals
// reads every literal the references are compared against, in order.
func TestComparedLiteralsListsEveryComparison(t *testing.T) {
	got := ComparedLiterals("github.event.action == 'opened' || (github.event_name == 'push' && github.event.action != 'closed')", []string{"github.event.action"})
	if len(got) != 2 || got[0] != "opened" || got[1] != "closed" {
		t.Errorf("ComparedLiterals = %v", got)
	}
	if got := ComparedLiterals("github.event_name == 'push'", []string{"github.event.action"}); len(got) != 0 {
		t.Errorf("ComparedLiterals = %v, want none", got)
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

// TestEvalBareReferenceUsesItsResolvedTruth pins the idiomatic fork
// guard `if: ${{ !github.event.pull_request.head.repo.fork }}`: a bare
// reference the facts resolve is read under GitHub's truthiness (an
// empty value or the boolean false is False, anything else True), so the
// guard decides the gate instead of leaving it unknown. A reference the
// facts cannot resolve stays Unknown, negated or not.
func TestEvalBareReferenceUsesItsResolvedTruth(t *testing.T) {
	f := facts{
		"github.event.pull_request.head.repo.fork": "true",
		"github.event.pull_request.merged":         "false",
		"github.event_name":                        "pull_request_target",
		"github.event.pull_request.head.ref":       "",
	}
	cases := []struct {
		expr string
		want Value
	}{
		{"!github.event.pull_request.head.repo.fork", False},
		{"github.event.pull_request.head.repo.fork", True},
		{"github.event.pull_request.merged", False},
		{"!github.event.pull_request.merged", True},
		{"github.event_name", True},
		{"github.event.pull_request.head.ref", False},
		{"github.event.unknown.flag", Unknown},
		{"!github.event.unknown.flag", Unknown},
		{"github.event_name == 'pull_request_target' && !github.event.pull_request.head.repo.fork", False},
	}
	for _, c := range cases {
		if got := Eval(c.expr, f); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestDeeplyNestedConditionIsUnknownNotACrash pins the module's promise
// that no condition read from a scanned workflow can bring the process
// down: a condition nested past the depth the parser accepts, or longer
// than any real condition, is Unknown through every entry point. Stack
// exhaustion is fatal and cannot be recovered, so the bound must hold
// before recursion, not after.
func TestDeeplyNestedConditionIsUnknownNotACrash(t *testing.T) {
	f := facts{"github.event_name": "push"}
	huge := []string{
		strings.Repeat("!", 200000) + "true",
		strings.Repeat("(", 200000) + "true" + strings.Repeat(")", 200000),
		strings.Repeat("!(", 100000) + "github.event_name == 'push'" + strings.Repeat(")", 100000),
	}
	for _, e := range huge {
		if got := Eval(e, f); got != Unknown {
			t.Errorf("Eval(%d chars) = %v, want Unknown", len(e), got)
		}
		if refs := Refs(e); len(refs) != 0 {
			t.Errorf("Refs(%d chars) = %v, want none", len(e), refs)
		}
		if _, ok := ComparedLiteral(e, []string{"github.event_name"}); ok {
			t.Errorf("ComparedLiteral(%d chars) settled a literal, want none", len(e))
		}
		if cs := Comparisons(e, []string{"github.event_name"}); len(cs) != 0 {
			t.Errorf("Comparisons(%d chars) = %v, want none", len(e), cs)
		}
		if HasStatusCall(e) {
			t.Errorf("HasStatusCall(%d chars) = true, want false", len(e))
		}
	}
	// Realistic nesting still evaluates.
	for _, c := range []struct {
		expr string
		want Value
	}{
		{"!!true", True},
		{"((((github.event_name == 'push'))))", True},
		{strings.Repeat("!", 20) + "false", False},
		{strings.Repeat("(", 20) + "github.event_name == 'push'" + strings.Repeat(")", 20), True},
	} {
		if got := Eval(c.expr, f); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}
