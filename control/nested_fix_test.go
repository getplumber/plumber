package control

import (
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

// nestedPath is the attack path of one ISSUE-701 finding on evil/e@main
// reached through via, on a job that writes the repository.
func nestedPath(t *testing.T, via ...any) (AttackPath, []opaengine.Finding) {
	t.Helper()
	data := map[string]any{"uses": "evil/e@main"}
	if len(via) > 0 {
		data["nested"], data["via"] = true, via
	}
	f := finding("ISSUE-701", "release", data)
	f.File, f.Line = ".github/workflows/ci.yml", 13
	sit := defaultTokenSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Impact = tokenImpacts("proven", "writes_repo")
	sit.Jobs["release"] = j
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	return paths[0], []opaengine.Finding{f}
}

// nestedPinFix is the first sentence of ISSUE-701's nested remediation, as
// something to do.
const nestedPinFix = "pin the outermost action to a commit SHA whose definition pins this reference, or vendor the chain into `./.github/actions/` and pin it there"

// TestPathFix_NestedEntryTakesTheNestedFix pins spec section 6 and the
// Task 3 round ruling L2 (whole-branch review finding 2, coordinator
// ruling 2): an attack path whose entry sits in a remote container prints
// the nested fix on its Fix line, since the user cannot edit the file that
// holds the reference. Under a local outermost composite the user owns the
// file, so the direct fix stays.
func TestPathFix_NestedEntryTakesTheNestedFix(t *testing.T) {
	p, fs := nestedPath(t, "acme/b@main", "acme/d@main")
	if got := NewPathBlock(p, fs).Fix; got != nestedPinFix {
		t.Errorf("nested Fix = %q, want %q", got, nestedPinFix)
	}
	local, lfs := nestedPath(t, "./.github/actions/x")
	direct, dfs := nestedPath(t)
	if got, want := NewPathBlock(local, lfs).Fix, NewPathBlock(direct, dfs).Fix; got != want || got == nestedPinFix {
		t.Errorf("under a local composite Fix = %q, want the direct %q", got, want)
	}
}

// TestBestFixSummary_NestedBestPathTakesTheNestedFix pins the same ruling
// on the Score block: the best fix built from a nested best path names the
// nested fix and the chain.
func TestBestFixSummary_NestedBestPathTakesTheNestedFix(t *testing.T) {
	p, _ := nestedPath(t, "acme/b@main", "acme/d@main")
	s := &PlumberScoreResult{Paths: []AttackPath{p}, BestFix: &BestFix{Code: "ISSUE-701", Subject: "evil/e@main", PathID: p.ID, PointsGained: 10, NewPoints: 90, NewLetter: "A"}}
	got := BestFixSummary(s)
	if !strings.HasPrefix(got, nestedPinFix+" (") || !strings.Contains(got, "evil/e@main via acme/b@main > acme/d@main") {
		t.Errorf("best fix = %q, want the nested fix and the chain", got)
	}
}

// TestApplyNestedActions_JobsCapHasItsOwnSentence pins SECURITY item 2 and
// R3 (whole-branch review finding 1, coordinator ruling 1): past the
// run-wide cap on appended nested jobs the run degrades like a container
// overflow, its sentence naming nested jobs and the cap, and the action
// controls err.
func TestApplyNestedActions_JobsCapHasItsOwnSentence(t *testing.T) {
	r := &AnalysisResult{CiValid: true, UnexpandedActions: []ir.UnexpandedAction{
		{Uses: "a/s/.github/workflows/w.yml@v1", Reason: ir.UnexpandedBudget}, {Uses: "a/s/.github/workflows/v.yml@v1", Reason: ir.UnexpandedBudget},
	}}
	applyNestedActions(r, &ir.NormalizedPipeline{NestedBudgetExceeded: true, NestedJobsOverflow: 2})
	want := "nested actions closure exceeded the budget of 1000 nested jobs, 2 references not expanded"
	if len(r.DegradedReasons) != 1 || r.DegradedReasons[0] != want {
		t.Fatalf("reasons = %q, want %q", r.DegradedReasons, want)
	}
	if got := StatusFor(ControlEntry{ControlName: "actionsMustBePinnedByCommitSha"}, r, 0); got != StatusError {
		t.Errorf("an action control reads error, got %s", got)
	}
}

// TestApplyNestedActions_InvalidReferencesShareTheFetchCap pins the
// re-review N2 (SECURITY item 1, coordinator ruling 4): a reference refused
// as outside GitHub's grammar gets ONE warning line, the capped fetch line
// naming the reason, so 3000 of them print at most ten lines and one
// "and N more".
func TestApplyNestedActions_InvalidReferencesShareTheFetchCap(t *testing.T) {
	one := &AnalysisResult{UnexpandedActions: []ir.UnexpandedAction{{Uses: "acme/c@v1#frag", Via: []string{"acme/b@v1"}, Reason: ir.UnexpandedFetch, Invalid: true}}}
	applyNestedActions(one, &ir.NormalizedPipeline{})
	if want := `the reference "acme/c@v1#frag" was not fetched, it is not a valid GitHub reference`; len(one.Warnings) != 1 || one.Warnings[0] != want {
		t.Fatalf("warnings = %q, want [%q]", one.Warnings, want)
	}
	many := &AnalysisResult{}
	for i := range 3000 {
		many.UnexpandedActions = append(many.UnexpandedActions, ir.UnexpandedAction{Uses: "acme/c@v1#" + strconv.Itoa(i), Reason: ir.UnexpandedFetch, Invalid: true})
	}
	applyNestedActions(many, &ir.NormalizedPipeline{})
	if len(many.Warnings) != 11 || many.Warnings[10] != "and 2990 more action definitions could not be fetched" {
		t.Fatalf("3000 invalid references print %d lines, the last %q", len(many.Warnings), many.Warnings[len(many.Warnings)-1])
	}
}

// TestNestedFixMessages_RemediationHalfTakesTheNestedFix pins spec section
// 6 (maintainer review of PR 549): a finding pulled in through a remote
// container whose message closes on a direct remediation after the
// consequence dash closes on the nested fix instead, since the user cannot
// edit the reference the direct half asks to pin. A direct finding, one
// under a local outermost composite (ruling L2), and one whose half is a
// consequence rather than a remediation stay byte-identical.
func TestNestedFixMessages_RemediationHalfTakesTheNestedFix(t *testing.T) {
	dash := " \u2014 "
	remote := []any{"acme/b@main", "acme/d@main"}
	mk := func(code, msg string, via []any) opaengine.Finding {
		f := opaengine.Finding{Code: code, Message: msg, Data: map[string]any{}}
		if via != nil {
			f.Data["via"] = via
		}
		return f
	}
	what := `job "ci" references action "evil/e@main" with a mutable ref, pulled in via acme/b@main > acme/d@main`
	direct := `job "ci" references action "evil/e@main" with a mutable ref`
	cases := []struct {
		name string
		in   opaengine.Finding
		want string
	}{
		{"nested 701", mk("ISSUE-701", what+dash+"pin by commit SHA instead", remote), what + dash + nestedPinFix},
		{"nested 713", mk("ISSUE-713", what+dash+"restrict to authorized owners", remote), what + dash + "replace the outermost action with one whose chain only pulls authorized sources, or vendor the chain into `./.github/actions/` and replace the reference there"},
		{"nested 709", mk("ISSUE-709", what+dash+"refresh to pick up upstream security fixes", remote), what + dash + "move the outermost action to a release whose chain pins a current version, or vendor the chain into `./.github/actions/` and refresh the pin there"},
		{"direct 701", mk("ISSUE-701", direct+dash+"pin by commit SHA instead", nil), direct + dash + "pin by commit SHA instead"},
		{"local outermost 701", mk("ISSUE-701", what+dash+"pin by commit SHA instead", []any{"./.github/actions/x"}), what + dash + "pin by commit SHA instead"},
		{"consequence half 703", mk("ISSUE-703", what+dash+"published advisories: GHSA-1", remote), what + dash + "published advisories: GHSA-1"},
		{"no dash 707", mk("ISSUE-707", what, remote), what},
	}
	for _, c := range cases {
		fs := []opaengine.Finding{c.in}
		NestedFixMessages(fs)
		if fs[0].Message != c.want {
			t.Errorf("%s: message = %q, want %q", c.name, fs[0].Message, c.want)
		}
	}
}

// TestNestedFixMessages_RewritesAfterTheLastDash pins the review of PR 549
// (finding 4297763494): a message quoting a user text that holds the dash
// keeps it, only the half after the last dash, the consequence separator,
// becomes the nested fix.
func TestNestedFixMessages_RewritesAfterTheLastDash(t *testing.T) {
	dash := " \u2014 "
	what := `job "ci" references action "evil/e@main # a` + dash + `b" with a mutable ref, pulled in via acme/b@main`
	fs := []opaengine.Finding{{Code: "ISSUE-701", Message: what + dash + "pin by commit SHA instead", Data: map[string]any{"via": []any{"acme/b@main"}}}}
	NestedFixMessages(fs)
	if want := what + dash + nestedPinFix; fs[0].Message != want {
		t.Errorf("message = %q, want %q", fs[0].Message, want)
	}
}

// TestNestedFixMessages_EveryRemediationHalfCodeHasANestedFix pins spec
// section 6 (maintainer review of PR 549): a code listed as closing its
// message on a remediation has a nested remediation to swap in, so the
// list can never silently do nothing.
func TestNestedFixMessages_EveryRemediationHalfCodeHasANestedFix(t *testing.T) {
	for code := range remediationHalfCodes {
		if _, ok := nestedFix(code, []string{"acme/b@main"}); !ok {
			t.Errorf("%s closes on a remediation but has no nested fix", code)
		}
	}
}

// TestEvaluatePolicies_NestedMessageClosesOnTheNestedFix pins spec section
// 6 (maintainer review of PR 549) at the engine boundary every output reads:
// the nested ISSUE-701 of the reproduction (E via B > D) closes on the
// nested fix, the direct one (B) on the direct half, byte for byte.
func TestEvaluatePolicies_NestedMessageClosesOnTheNestedFix(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfig("../.plumber.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	b, d, e := "thomasboni/nested-actions-b@main", "thomasboni/nested-actions-d@main", "thomasboni/nested-actions-e@main"
	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "thomasboni/nested-actions-a", Jobs: []ir.Job{{
		Name: "ci/nested", OriginFile: ".github/workflows/ci.yml", OriginLine: 9, Triggers: []string{"push"},
		Uses: []ir.Action{
			{Uses: b, Line: 13},
			{Uses: e, Line: 13, Nested: true, Via: []string{b, d}, DefinedIn: d + ":action.yml:8"},
		},
	}}}
	conf := &configuration.Configuration{ProjectPath: "thomasboni/nested-actions-a", PlumberConfig: pc}
	findings, _ := evaluatePolicies(logrus.NewEntry(logrus.New()), conf, "github", pipeline)
	got := map[string]string{}
	for _, f := range findings {
		if f.Code == "ISSUE-701" {
			ref, _ := f.Data["uses"].(string)
			got[ref] = f.Message
		}
	}
	if want := `job "ci/nested" references action "` + b + `" with a mutable ref` + " \u2014 pin by commit SHA instead"; got[b] != want {
		t.Errorf("direct message = %q, want %q", got[b], want)
	}
	if want := `job "ci/nested" references action "` + e + `" with a mutable ref, pulled in via ` + b + " > " + d + " \u2014 " + nestedPinFix; got[e] != want {
		t.Errorf("nested message = %q, want %q", got[e], want)
	}
}
