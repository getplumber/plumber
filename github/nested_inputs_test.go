package github

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// workflowCalling renders a workflow with one job calling acme/gate@v1,
// the with: lines written as given, so the values go through the real
// decoders.
func workflowCalling(with ...string) string {
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/gate@v1\n")
	if len(with) > 0 {
		b.WriteString("        with:\n")
		for _, l := range with {
			b.WriteString("          " + l + "\n")
		}
	}
	return b.String()
}

func parsedJobs(t *testing.T, workflow string) []ir.Job {
	t.Helper()
	jobs, err := parseGitHubWorkflowJobs([]byte(workflow), "ci", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return jobs
}

func usesOf(job ir.Job) []string {
	out := make([]string, 0, len(job.Uses))
	for _, a := range job.Uses {
		out = append(out, a.Uses)
	}
	return out
}

// gate renders a composite with one step guarded by cond.
func gate(inputs, cond string) string {
	return inputs + "runs:\n  using: composite\n  steps:\n    - if: " + cond + "\n      uses: actions/checkout@v4\n"
}

func TestNestedStepDisabledByLiteralInput(t *testing.T) {
	const flagTrue = "inputs:\n  flag:\n    default: 'true'\n"
	const flagFalse = "inputs:\n  flag:\n    default: 'false'\n"
	const flagExpr = "inputs:\n  flag:\n    default: ${{ github.token }}\n"
	const flagBare = "inputs:\n  flag:\n    description: no default\n"
	const notFalse = "inputs.flag != 'false'"
	cases := []struct {
		name, inputs, cond string
		with               []string
		dropped            bool
	}{
		{name: "boolean false", inputs: flagTrue, cond: notFalse, with: []string{"flag: false"}, dropped: true},
		{name: "quoted false", inputs: flagTrue, cond: notFalse, with: []string{"flag: 'false'"}, dropped: true},
		{name: "capitalized False", inputs: flagTrue, cond: notFalse, with: []string{"flag: False"}, dropped: true},
		{name: "input name case", inputs: flagTrue, cond: notFalse, with: []string{"FLAG: false"}, dropped: true},
		{name: "name case in the condition", inputs: flagTrue, cond: "inputs.FLAG != 'false'", with: []string{"flag: false"}, dropped: true},
		{name: "wrapped condition", inputs: flagTrue, cond: "${{ inputs.flag != 'false' }}", with: []string{"flag: false"}, dropped: true},
		{name: "enabled by the caller", inputs: flagFalse, cond: notFalse, with: []string{"flag: 'true'"}},
		{name: "default disables", inputs: flagFalse, cond: notFalse, dropped: true},
		{name: "caller overrides a disabling default", inputs: flagFalse, cond: notFalse, with: []string{"flag: 'yes please'"}},
		{name: "default enables", inputs: flagTrue, cond: notFalse},
		{name: "empty string is a value", inputs: flagTrue, cond: "inputs.flag == 'x'", with: []string{"flag: ''"}, dropped: true},

		// The runner normalizes numbers (1.10 reaches the action as 1.1):
		// seen on a real run, these steps ran.
		{name: "float", cond: "inputs.flag != '1.10'", with: []string{"flag: 1.10"}},
		{name: "whole float", cond: "inputs.flag != '1.0'", with: []string{"flag: 1.0"}},
		{name: "hexadecimal", cond: "inputs.flag != '0x10'", with: []string{"flag: 0x10"}},
		{name: "number hides a disabling default", inputs: flagFalse, cond: notFalse, with: []string{"flag: 1.10"}},
		{name: "number default", inputs: "inputs:\n  flag:\n    default: 1.10\n", cond: "inputs.flag != '1.10'"},
		{name: "number in a quoted string", cond: "inputs.flag != '1.10'", with: []string{"flag: '1.10'"}, dropped: true},

		// YAML 1.1 booleans the runner reads as text.
		{name: "no is text", inputs: flagTrue, cond: notFalse, with: []string{"flag: no"}},
		{name: "off is text", inputs: flagTrue, cond: notFalse, with: []string{"flag: off"}},
		{name: "n is text", inputs: flagTrue, cond: notFalse, with: []string{"flag: n"}},

		// Unknown values stay inlined.
		{name: "caller expression", inputs: flagFalse, cond: notFalse, with: []string{"flag: ${{ github.ref }}"}},
		{name: "partial caller expression", inputs: flagFalse, cond: notFalse, with: []string{"flag: a-${{ github.ref }}"}},
		{name: "null caller value", inputs: flagFalse, cond: notFalse, with: []string{"flag:"}},
		{name: "list caller value", inputs: flagFalse, cond: notFalse, with: []string{"flag: [a]"}},
		{name: "expression default", inputs: flagExpr, cond: "inputs.flag == 'x'"},
		{name: "no default declared", inputs: flagBare, cond: notFalse},
		{name: "undeclared input", cond: notFalse},

		// Conditions the gate refuses stay inlined.
		{name: "bare reference", inputs: flagTrue, cond: "inputs.flag", with: []string{"flag: false"}},
		{name: "boolean literal", inputs: flagTrue, cond: "inputs.flag == true", with: []string{"flag: false"}},
		{name: "runtime context", inputs: flagTrue, cond: "inputs.flag != 'false' && github.ref == 'x'", with: []string{"flag: false"}},
		{name: "status function", inputs: flagTrue, cond: "inputs.flag != 'false' && always()", with: []string{"flag: false"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := newStub(map[string]string{"acme/gate@v1:action.yml": gate(c.inputs, c.cond)})
			p := resolveWith(t, stub, nestedScope{}, parsedJobs(t, workflowCalling(c.with...))...)
			want := []string{"acme/gate@v1", "actions/checkout@v4"}
			if c.dropped {
				want = want[:1]
			}
			if got := usesOf(p.Jobs[0]); !slices.Equal(got, want) {
				t.Errorf("uses = %v, want %v", got, want)
			}
		})
	}
}

// The composite of the issue, as published.
func TestNestedStepDisabledByLiteralInput_Govulncheck(t *testing.T) {
	stub := newStub(map[string]string{"golang/govulncheck-action@v1:action.yml": `
inputs:
  repo-checkout:
    description: Checkout the repository
    default: true
runs:
  using: composite
  steps:
    - if: inputs.repo-checkout != 'false'
      uses: actions/checkout@v6
    - uses: actions/setup-go@v5
`})
	wf := "on: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: golang/govulncheck-action@v1\n        with:\n          check-latest: true\n          repo-checkout: false\n"
	p := resolveWith(t, stub, nestedScope{}, parsedJobs(t, wf)...)
	want := []string{"golang/govulncheck-action@v1", "actions/setup-go@v5"}
	if got := usesOf(p.Jobs[0]); !slices.Equal(got, want) {
		t.Errorf("uses = %v, want %v", got, want)
	}
}

func twoLevels(forward string) map[string]string {
	return map[string]string{
		"acme/gate@v1:action.yml":  "inputs:\n  outer:\n    description: x\nruns:\n  using: composite\n  steps:\n    - uses: acme/inner@v1\n" + forward,
		"acme/inner@v1:action.yml": gate("inputs:\n  flag:\n    default: 'true'\n", "inputs.flag != 'false'"),
	}
}

func TestNestedInputsAcrossLevels(t *testing.T) {
	const forwarded = "      with:\n        flag: ${{ inputs.outer }}\n"
	inner := []string{"acme/gate@v1", "acme/inner@v1"}
	both := append(slices.Clone(inner), "actions/checkout@v4")
	cases := []struct {
		name, forward string
		with          []string
		want          []string
	}{
		{"forwarded literal disables", forwarded, []string{"outer: false"}, inner},
		{"forwarded literal enables", forwarded, []string{"outer: 'true'"}, both},
		{"forwarded unknown stays", forwarded, nil, both},
		{"forwarded expression stays", forwarded, []string{"outer: ${{ github.ref }}"}, both},
		{"composite literal disables", "      with:\n        flag: false\n", nil, inner}, {"composite literal with interpolation", "      with:\n        flag: fal${{ inputs.outer }}\n", []string{"outer: se"}, inner},
		// The workflow's with: belongs to the outer composite alone.
		{"outer inputs do not reach the inner action", "", []string{"flag: false"}, both},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := newStub(twoLevels(c.forward))
			p := resolveWith(t, stub, nestedScope{}, parsedJobs(t, workflowCalling(c.with...))...)
			if got := usesOf(p.Jobs[0]); !slices.Equal(got, c.want) {
				t.Errorf("uses = %v, want %v", got, c.want)
			}
		})
	}
}

func TestNestedSkippedStepDropsItsSubtree(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/gate@v1:action.yml":  "runs:\n  using: composite\n  steps:\n    - if: inputs.flag != 'false'\n      uses: acme/inner@v1\n    - uses: acme/after@v1\n",
		"acme/inner@v1:action.yml": composite("actions/checkout@v4"),
	})
	p := resolveWith(t, stub, nestedScope{}, parsedJobs(t, workflowCalling("flag: false"))...)
	want := []string{"acme/gate@v1", "acme/after@v1"}
	if got := usesOf(p.Jobs[0]); !slices.Equal(got, want) {
		t.Errorf("uses = %v, want %v", got, want)
	}
}

// The composite is parsed once, the condition judged per caller.
func TestNestedInputsArePerCaller(t *testing.T) {
	stub := newStub(map[string]string{"acme/gate@v1:action.yml": gate("", "inputs.flag != 'false'")})
	wf := "on: push\njobs:\n  off:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/gate@v1\n        with:\n          flag: false\n  on:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/gate@v1\n        with:\n          flag: 'true'\n"
	p := resolveWith(t, stub, nestedScope{}, parsedJobs(t, wf)...)
	got := map[string]int{}
	for _, j := range p.Jobs {
		got[j.Name] = len(j.Uses)
	}
	if len(got) != 2 || got["ci/off"] != 1 || got["ci/on"] != 2 {
		t.Errorf("entries per job = %v", got)
	}
}

// An aliased with: is not read as text, so its values stay unknown.
func TestNestedAliasedWithStaysInlined(t *testing.T) {
	stub := newStub(map[string]string{"acme/gate@v1:action.yml": gate("", "inputs.flag != 'false'")})
	wf := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/first@v1\n        with: &w\n          flag: false\n      - uses: acme/gate@v1\n        with: *w\n"
	p := resolveWith(t, stub, nestedScope{}, parsedJobs(t, wf)...)
	if got := usesOf(p.Jobs[0]); !slices.Contains(got, "actions/checkout@v4") {
		t.Errorf("uses = %v, want the checkout kept", got)
	}
}

func TestNestedSkippedStepSpendsNoBudget(t *testing.T) {
	var b strings.Builder
	b.WriteString("runs:\n  using: composite\n  steps:\n    - if: inputs.flag != 'false'\n      uses: acme/skipped@v1\n")
	for i := 0; i < MaxNestedEntriesPerJob; i++ {
		fmt.Fprintf(&b, "    - uses: acme/leaf@v%d\n", i)
	}
	stub := newStub(map[string]string{"acme/gate@v1:action.yml": b.String()})
	p := resolveWith(t, stub, nestedScope{}, parsedJobs(t, workflowCalling("flag: false"))...)
	if p.NestedEntriesOverflow != 0 {
		t.Errorf("NestedEntriesOverflow = %d, want 0", p.NestedEntriesOverflow)
	}
	if got := len(p.Jobs[0].Uses); got != MaxNestedEntriesPerJob+1 {
		t.Errorf("entries = %d, want %d", got, MaxNestedEntriesPerJob+1)
	}
}

// A malformed inputs: costs the defaults, never the expansion.
func TestNestedMalformedInputsStillExpands(t *testing.T) {
	for _, inputs := range []string{"inputs: 7\n", "inputs: [a, b]\n", "inputs:\n  flag: 7\n", "inputs:\n  flag:\n    default: [a]\n"} {
		stub := newStub(map[string]string{"acme/gate@v1:action.yml": gate(inputs, "inputs.flag != 'false'")})
		p := resolveWith(t, stub, nestedScope{}, parsedJobs(t, workflowCalling())...)
		if len(p.UnexpandedActions) != 0 {
			t.Errorf("%q: unexpanded = %v", inputs, p.UnexpandedActions)
		}
		if got := usesOf(p.Jobs[0]); !slices.Contains(got, "actions/checkout@v4") {
			t.Errorf("%q: uses = %v, want the checkout kept", inputs, got)
		}
	}
}

// The text pairs with the decoded steps only when both read the same
// ones: a mismatch would hand one step another step's inputs.
func TestWithTextPairsOnlyMatchingSteps(t *testing.T) {
	loc := jobLocations{uses: []string{"a/b@v1"}, withText: []map[string]string{{"flag": "false"}}}
	job := ir.Job{Uses: []ir.Action{{Uses: "a/b@v1"}}}
	applyJobLocations(&job, loc)
	if job.Uses[0].WithText["flag"] != "false" {
		t.Errorf("WithText = %v", job.Uses[0].WithText)
	}
	other := ir.Job{Uses: []ir.Action{{Uses: "c/d@v1"}}}
	applyJobLocations(&other, loc)
	if other.Uses[0].WithText != nil {
		t.Errorf("WithText on another step = %v", other.Uses[0].WithText)
	}
}

// Policies and reports read the serialized action: the text is only for
// the resolution stage.
func TestWithTextStaysOutOfTheSerializedAction(t *testing.T) {
	b, err := json.Marshal(ir.Action{Uses: "a/b@v1", WithText: map[string]string{"flag": "secret-spelling"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-spelling") {
		t.Errorf("serialized action carries the text: %s", b)
	}
}
