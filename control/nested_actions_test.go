package control

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// TestApplyNestedActions_BudgetDegradesFetchAndNoAPIWarn pins spec section 7:
// a budget overflow degrades the run (R3), no API warns once and scores
// (R6), one failed fetch warns without degrading.
func TestApplyNestedActions_BudgetDegradesFetchAndNoAPIWarn(t *testing.T) {
	over := &AnalysisResult{UnexpandedActions: []ir.UnexpandedAction{
		{Uses: "a/x@v1", Reason: ir.UnexpandedBudget}, {Uses: "a/y@v1", Reason: ir.UnexpandedBudget},
	}}
	applyNestedActions(over, &ir.NormalizedPipeline{NestedBudgetExceeded: true})
	if !over.DataCollectionDegraded || !over.NestedActionsBudgetExceeded {
		t.Fatal("a budget overflow degrades the run")
	}
	want := "nested actions closure exceeded the budget of 100 containers, 2 references not expanded"
	if len(over.DegradedReasons) != 1 || over.DegradedReasons[0] != want {
		t.Fatalf("reasons = %q, want %q", over.DegradedReasons, want)
	}

	offline := &AnalysisResult{UnexpandedActions: []ir.UnexpandedAction{{Uses: "a/b@v1", Reason: ir.UnexpandedAPIDisabled}}}
	applyNestedActions(offline, &ir.NormalizedPipeline{NestedUnresolvedCause: "the GitHub API is disabled (PLUMBER_DISABLE_GITHUB_API)"})
	if offline.DataCollectionDegraded || len(offline.Warnings) != 1 || offline.Warnings[0] != "nested actions were not resolved: the GitHub API is disabled (PLUMBER_DISABLE_GITHUB_API)" {
		t.Fatalf("R6: degraded=%v warnings=%q", offline.DataCollectionDegraded, offline.Warnings)
	}

	one := &AnalysisResult{UnexpandedActions: []ir.UnexpandedAction{{Uses: "a/c@v1", Via: []string{"a/b@v1"}, Reason: ir.UnexpandedFetch}}}
	applyNestedActions(one, &ir.NormalizedPipeline{})
	if one.DataCollectionDegraded || len(one.Warnings) != 1 || !strings.Contains(one.Warnings[0], "a/c@v1") || strings.Contains(one.Warnings[0], ";") {
		t.Fatalf("fetch: degraded=%v warnings=%q", one.DataCollectionDegraded, one.Warnings)
	}
}

// TestApplyNestedActions_OverflowWinsOverTheCause pins coordinator ruling
// L7: the cause and the overflow cannot both be set after the collector's
// first-read rule, and if they ever are, the overflow wins: the run
// degrades (R3) and the R6 warning, which would say the score stands, is
// not given.
func TestApplyNestedActions_OverflowWinsOverTheCause(t *testing.T) {
	r := &AnalysisResult{UnexpandedActions: []ir.UnexpandedAction{{Uses: "a/x@v1", Reason: ir.UnexpandedBudget}}}
	applyNestedActions(r, &ir.NormalizedPipeline{NestedBudgetExceeded: true, NestedUnresolvedCause: "the GitHub API is disabled (PLUMBER_DISABLE_GITHUB_API)"})
	if !r.DataCollectionDegraded || !r.NestedActionsBudgetExceeded || len(r.Warnings) != 0 {
		t.Fatalf("degraded=%v exceeded=%v warnings=%q", r.DataCollectionDegraded, r.NestedActionsBudgetExceeded, r.Warnings)
	}
}

// TestStatusFor_NestedBudgetErrsOnlyTheActionControls pins R3: the run is
// degraded for the action controls, an unrelated control keeps its status.
func TestStatusFor_NestedBudgetErrsOnlyTheActionControls(t *testing.T) {
	r := &AnalysisResult{CiValid: true, DegradedReasons: []string{degradedReasonNestedActionsPrefix + " of 100 containers, 1 references not expanded"}}
	if got := StatusFor(ControlEntry{ControlName: "actionsMustBePinnedByCommitSha"}, r, 0); got != StatusError {
		t.Errorf("an action control with no finding reads error, got %s", got)
	}
	if got := StatusFor(ControlEntry{ControlName: "containerImageMustNotUseForbiddenTags"}, r, 0); got != StatusPassed {
		t.Errorf("an unrelated control keeps passed, got %s", got)
	}
}

// TestNestedRemediation_Wording pins spec section 6: the ten codes carry a
// nested variant, selected only for a nested finding, in house prose.
func TestNestedRemediation_Wording(t *testing.T) {
	codes := []ErrorCode{CodeActionUnpinned, CodeActionUnauthorizedSource, CodeActionArchivedRepo, CodeKnownVulnerableAction, CodeImpostorCommit, CodeStaleActionRef, CodeActionMutableRemoteExec, CodeActionObfuscatedRemoteExec, CodeActionRemoteExecUnverified, CodeRefConfusion}
	for _, c := range codes {
		info := LookupCode(c)
		if info.NestedRemediation == "" || strings.ContainsAny(info.NestedRemediation, ";\u2014\u2013") {
			t.Errorf("%s: nested remediation %q", c, info.NestedRemediation)
		}
		if info.RemediationFor(false) != info.Remediation || info.RemediationFor(true) != info.NestedRemediation || info.NestedRemediation == info.Remediation {
			t.Errorf("%s: RemediationFor does not select the variant", c)
		}
	}
	want := map[ErrorCode]bool{}
	for _, c := range codes {
		want[c] = true
	}
	for c, info := range errorCodeRegistry {
		if (info.NestedRemediation != "") != want[c] {
			t.Errorf("%s: nested remediation %q, only the ten codes of spec section 6 carry one", c, info.NestedRemediation)
		}
	}
}

// TestAggregateGitHubStats_CountsNestedEntries pins spec section 8.
func TestAggregateGitHubStats_CountsNestedEntries(t *testing.T) {
	p := &ir.NormalizedPipeline{Jobs: []ir.Job{{Name: "ci/build", Uses: []ir.Action{
		{Uses: "a/b@v1"}, {Uses: "a/c@v1", Nested: true, Via: []string{"a/b@v1"}},
	}}}}
	if s := AggregateGitHubStats(p, nil); s.ActionRefsNested != 1 {
		t.Fatalf("ActionRefsNested = %d, want 1", s.ActionRefsNested)
	}
}

// TestNestedRemediationApplies_OnlyUnderARemoteContainer pins the Task 3
// round ruling L2: the nested remediation is selected only when the
// outermost reference of the chain is remote. Under a local composite
// (./...) the user owns the file that holds the reference, so the direct
// remediation applies, the message still carrying the chain.
func TestNestedRemediationApplies_OnlyUnderARemoteContainer(t *testing.T) {
	cases := []struct {
		via  []string
		want bool
	}{
		{nil, false},
		{[]string{"acme/b@v1"}, true},
		{[]string{"acme/b@v1", "./.github/actions/x"}, true},
		{[]string{"./.github/actions/setup"}, false},
		{[]string{"./.github/actions/setup", "acme/b@v1"}, false},
	}
	for _, tc := range cases {
		if got := NestedRemediationApplies(tc.via); got != tc.want {
			t.Errorf("NestedRemediationApplies(%q) = %v, want %v", tc.via, got, tc.want)
		}
	}
}

// TestApplyNestedActions_PerJobEntryOverflowHasItsOwnSentence pins the
// Task 3 round ruling L5 (plan ruling 5): the per-job entry bound degrades
// like the container budget, in its own words, and the action controls err.
func TestApplyNestedActions_PerJobEntryOverflowHasItsOwnSentence(t *testing.T) {
	r := &AnalysisResult{CiValid: true, UnexpandedActions: []ir.UnexpandedAction{
		{Uses: "a/x@v1", Reason: ir.UnexpandedBudget}, {Uses: "a/y@v1", Reason: ir.UnexpandedBudget},
	}}
	applyNestedActions(r, &ir.NormalizedPipeline{NestedBudgetExceeded: true, NestedEntriesOverflow: 2})
	want := "one job's nested closure exceeded 1000 entries, 2 references not expanded"
	if len(r.DegradedReasons) != 1 || r.DegradedReasons[0] != want {
		t.Fatalf("reasons = %q, want %q", r.DegradedReasons, want)
	}
	if got := StatusFor(ControlEntry{ControlName: "actionsMustBePinnedByCommitSha"}, r, 0); got != StatusError {
		t.Errorf("an action control reads error, got %s", got)
	}
	if got := StatusFor(ControlEntry{ControlName: "containerImageMustNotUseForbiddenTags"}, r, 0); got != StatusPassed {
		t.Errorf("an unrelated control keeps passed, got %s", got)
	}

	one := &AnalysisResult{UnexpandedActions: []ir.UnexpandedAction{{Uses: "a/x@v1", Reason: ir.UnexpandedBudget}}}
	applyNestedActions(one, &ir.NormalizedPipeline{NestedBudgetExceeded: true})
	if want := "nested actions closure exceeded the budget of 100 containers, 1 reference not expanded"; len(one.DegradedReasons) != 1 || one.DegradedReasons[0] != want {
		t.Fatalf("reasons = %q, want %q", one.DegradedReasons, want)
	}
}

// TestApplyNestedActions_ThreeBoundsPartitionTheBudgetCount pins R3
// (review of PR 549): when the container budget, the per-job entry bound
// and the nested jobs cap all trip in one run, each sentence counts its
// own references and the three counts sum to the budget-listed ones.
func TestApplyNestedActions_ThreeBoundsPartitionTheBudgetCount(t *testing.T) {
	r := &AnalysisResult{CiValid: true}
	for i := range 6 {
		r.UnexpandedActions = append(r.UnexpandedActions, ir.UnexpandedAction{Uses: "a/x" + strconv.Itoa(i) + "@v1", Reason: ir.UnexpandedBudget})
	}
	applyNestedActions(r, &ir.NormalizedPipeline{NestedBudgetExceeded: true, NestedEntriesOverflow: 2, NestedJobsOverflow: 3})
	want := []string{
		"nested actions closure exceeded the budget of 100 containers, 1 reference not expanded",
		"nested actions closure exceeded the budget of 1000 nested jobs, 3 references not expanded",
		"one job's nested closure exceeded 1000 entries, 2 references not expanded",
	}
	if !slices.Equal(r.DegradedReasons, want) {
		t.Fatalf("reasons:\n got %q\nwant %q", r.DegradedReasons, want)
	}
	if !r.NestedActionsBudgetExceeded {
		t.Errorf("the run records the overflow")
	}
}

// TestApplyNestedActions_FetchWarningsAreCapped pins the Task 3 round
// ruling L6: at most ten fetch warnings, then one line for the rest.
func TestApplyNestedActions_FetchWarningsAreCapped(t *testing.T) {
	r := &AnalysisResult{}
	for i := range 13 {
		r.UnexpandedActions = append(r.UnexpandedActions, ir.UnexpandedAction{Uses: "a/x" + strconv.Itoa(i) + "@v1", Reason: ir.UnexpandedFetch})
	}
	applyNestedActions(r, &ir.NormalizedPipeline{})
	if len(r.Warnings) != 11 || r.Warnings[10] != "and 3 more action definitions could not be fetched" {
		t.Fatalf("warnings = %q", r.Warnings)
	}
}

// TestApplyNestedActions_DefaultFetchWarningBoundsTheReference pins the
// review of PR 549: the default branch (reason fetch, u.Invalid false)
// bounds the untrusted reference it quotes the same way the sibling
// u.Invalid branch does, so an attacker-controlled reference of unbounded
// length cannot be embedded verbatim in result.Warnings.
func TestApplyNestedActions_DefaultFetchWarningBoundsTheReference(t *testing.T) {
	long := "a/" + strings.Repeat("x", 400) + "@main"
	r := &AnalysisResult{UnexpandedActions: []ir.UnexpandedAction{{Uses: long, Reason: ir.UnexpandedFetch}}}
	applyNestedActions(r, &ir.NormalizedPipeline{})
	if len(r.Warnings) != 1 {
		t.Fatalf("warnings = %q, want one", r.Warnings)
	}
	if strings.Contains(r.Warnings[0], long) {
		t.Fatalf("warning quotes the full 400-rune reference unbounded: %q", r.Warnings[0])
	}
	quoted := strings.TrimSuffix(strings.TrimPrefix(r.Warnings[0], "the definition of "), " could not be fetched, the actions it pulls in were not expanded")
	if n := len([]rune(quoted)); n > maxWarnedReference {
		t.Fatalf("quoted reference is %d runes, want at most %d", n, maxWarnedReference)
	}
}

// TestNewPathBlock_NestedEntryNamesItsChain pins spec section 8 and R5
// (Task 3 round M1): an attack path anchored on a nested reference prints
// the reference with its chain on the Entry line, in the headline and on
// the finding line under the block, since the workflow line it sits at
// names only the outermost action.
func TestNewPathBlock_NestedEntryNamesItsChain(t *testing.T) {
	f := finding("ISSUE-701", "release", map[string]any{"uses": "evil/e@main", "nested": true,
		"via": []any{"acme/b@main", "acme/d@main"}, "definedIn": "acme/d@main:action.yml:8"})
	f.File, f.Line = ".github/workflows/ci.yml", 13
	sit := defaultTokenSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Impact = tokenImpacts("proven", "writes_repo")
	sit.Jobs["release"] = j
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	const chain = "evil/e@main via acme/b@main > acme/d@main"
	b := NewPathBlock(paths[0], []opaengine.Finding{f})
	if !strings.Contains(b.Entry, chain) {
		t.Errorf("Entry = %q, want it to name %q", b.Entry, chain)
	}
	if got := PathSentence(paths[0]); !strings.Contains(got, "pulled in via `acme/b@main > acme/d@main`") {
		t.Errorf("headline = %q, want the chain", got)
	}
	if len(b.Findings) != 1 || !strings.Contains(b.Findings[0].Location, chain) {
		t.Errorf("finding lines = %+v, want the chain on the 701 line", b.Findings)
	}
	direct := finding("ISSUE-701", "release", map[string]any{"uses": "evil/e@main"})
	if b := NewPathBlock(assemblePaths([]opaengine.Finding{direct}, sit)[0], []opaengine.Finding{direct}); strings.Contains(b.Entry, " via ") {
		t.Errorf("a direct entry names no chain, got %q", b.Entry)
	}
}

// TestNestedActionControls_KeysAreRegisteredControls pins R3 (review of PR
// 549): every key of nestedActionControls must be a real control name in
// the configuration registry. A typo'd or renamed key would silently stop
// degrading that control on a nested-actions budget run (it would read
// "passed" instead of StatusError) with no test catching the drift.
func TestNestedActionControls_KeysAreRegisteredControls(t *testing.T) {
	for name := range nestedActionControls {
		if _, ok := configuration.ControlMetaFor(name); !ok {
			t.Errorf("nestedActionControls key %q is not a registered control name", name)
		}
	}
}

// TestStatusFor_NestedBudgetErrsEveryActionControl pins R3 (review of PR
// 549): StatusFor must degrade EVERY control named in nestedActionControls
// on a nested-actions budget reason, not just the one or two names the
// older tests happened to cover. A control dropped from (or never added
// to) the map would read "passed" on a run whose nested closure was cut
// off by the budget, which is exactly the silent false-green this status
// field exists to eliminate. The one unrelated control pins the negative:
// the degraded reason does not blanket every control.
func TestStatusFor_NestedBudgetErrsEveryActionControl(t *testing.T) {
	names := make([]string, 0, len(nestedActionControls))
	for name := range nestedActionControls {
		names = append(names, name)
	}
	slices.Sort(names)

	r := &AnalysisResult{CiValid: true, DegradedReasons: []string{degradedReasonNestedActionsPrefix + " of 100 containers, 1 references not expanded"}}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if got := StatusFor(ControlEntry{ControlName: name}, r, 0); got != StatusError {
				t.Errorf("StatusFor(%s) = %s, want %s", name, got, StatusError)
			}
		})
	}
	if got := StatusFor(ControlEntry{ControlName: "containerImageMustNotUseForbiddenTags"}, r, 0); got != StatusPassed {
		t.Errorf("an unrelated control keeps passed, got %s", got)
	}
}
