package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	githubpkg "github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
)

// TestLocationLinker_NestedFindingLinksTheContainer pins spec section 6
// and R9: the URL is the container's line, File and Line stay the step's.
func TestLocationLinker_NestedFindingLinksTheContainer(t *testing.T) {
	l := &locationLinker{provider: "github", serverURL: "https://github.com", repo: "thomasboni/nested-actions-a", ref: "main", useRemote: true}
	fs := []opaengine.Finding{
		{Code: "ISSUE-701", File: ".github/workflows/ci.yml", Line: 13},
		{Code: "ISSUE-701", File: ".github/workflows/ci.yml", Line: 13, Data: map[string]any{"definedIn": "thomasboni/nested-actions-d@main:action.yml:8"}},
	}
	l.Annotate(fs)
	if fs[0].URL != "https://github.com/thomasboni/nested-actions-a/blob/main/.github/workflows/ci.yml#L13" {
		t.Errorf("direct URL = %q", fs[0].URL)
	}
	if fs[1].URL != "https://github.com/thomasboni/nested-actions-d/blob/main/action.yml#L8" {
		t.Errorf("nested URL = %q", fs[1].URL)
	}
	if fs[1].File != ".github/workflows/ci.yml" || fs[1].Line != 13 {
		t.Errorf("the location stays the workflow step: %s:%d", fs[1].File, fs[1].Line)
	}
}

// TestLocationLinker_NestedFindingInLocalCompositeLinksTheScannedRepo pins
// spec section 6 and R9 (review of PR 549): a nested finding defined in a
// local composite (definedIn has no "owner/repo@ref" prefix) links to the
// scanned repository's own blob URL, not github.com with an empty owner.
func TestLocationLinker_NestedFindingInLocalCompositeLinksTheScannedRepo(t *testing.T) {
	l := &locationLinker{provider: "github", serverURL: "https://github.com", repo: "acme/app", ref: "main", useRemote: true}
	fs := []opaengine.Finding{
		{Code: "ISSUE-701", File: ".github/workflows/ci.yml", Line: 13, Data: map[string]any{"definedIn": "./.github/actions/setup/action.yml:5"}},
	}
	l.Annotate(fs)
	if want := "https://github.com/acme/app/blob/main/.github/actions/setup/action.yml#L5"; fs[0].URL != want {
		t.Errorf("local composite URL = %q, want %q", fs[0].URL, want)
	}
}

// TestRenderUnexpandedActions_CapsAtThree pins spec section 7, the chain
// set apart in backticks and dim (round 11).
func TestRenderUnexpandedActions_CapsAtThree(t *testing.T) {
	var b bytes.Buffer
	renderUnexpandedActions(&b, []ir.UnexpandedAction{
		{Uses: "a/1@v1", Reason: ir.UnexpandedBudget}, {Uses: "a/2@v1", Via: []string{"a/b@v1"}, Reason: ir.UnexpandedFetch},
		{Uses: "${{ inputs.x }}", Via: []string{"a/b@v1"}, Reason: ir.UnexpandedExpression}, {Uses: "a/4@v1", Reason: ir.UnexpandedAPIDisabled},
		{Uses: "a/5@v1", Reason: ir.UnexpandedAPIDisabled},
	})
	out := b.String()
	if !strings.Contains(out, "5 action references could not be expanded:") || !strings.Contains(out, "a/2@v1 via "+colorDim+"`a/b@v1`"+colorReset) || !strings.Contains(out, "and 2 more") || strings.Contains(out, "a/4@v1") {
		t.Fatalf("output:\n%s", out)
	}
	if strings.Contains(out, ";") {
		t.Fatalf("no semicolon in a user-facing line:\n%s", out)
	}
}

// TestNestedDetailLines_StepContainerAndFix pins spec section 6: the human
// rendering shows the user's step, the container line and the nested fix.
func TestNestedDetailLines_StepContainerAndFix(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-701", File: ".github/workflows/ci.yml", Line: 13, Data: map[string]any{
		"definedIn": "thomasboni/nested-actions-d@main:action.yml:8", "via": []any{"thomasboni/nested-actions-b@main", "thomasboni/nested-actions-d@main"},
	}}
	got := strings.Join(detailLinesFromFinding(f), "\n")
	for _, want := range []string{"pulled in by your step at .github/workflows/ci.yml:13", "defined in thomasboni/nested-actions-d@main, action.yml line 8", "fix: pin the outermost action"} {
		if !strings.Contains(got, want) {
			t.Errorf("detail lines lack %q:\n%s", want, got)
		}
	}
	if lines := detailLinesFromFinding(opaengine.Finding{Code: "ISSUE-701"}); lines != nil {
		t.Errorf("a direct finding has no nested lines, got %q", lines)
	}
}

// nestedE is the reproduction's E finding (E via B > D) as the engine
// boundary hands it to every writer: its message closes on the nested fix
// (control.NestedFixMessages) and its URL is the container line.
func nestedE() opaengine.Finding {
	via := []any{"thomasboni/nested-actions-b@main", "thomasboni/nested-actions-d@main"}
	f := opaengine.Finding{
		Code: "ISSUE-701", Severity: "high", File: ".github/workflows/ci.yml", Line: 13, Job: "ci/nested",
		Message: `job "ci/nested" references action "thomasboni/nested-actions-e@main" with a mutable ref, pulled in via thomasboni/nested-actions-b@main > thomasboni/nested-actions-d@main` + " \u2014 pin by commit SHA instead",
		URL:     "https://github.com/thomasboni/nested-actions-d/blob/main/action.yml#L8",
		Data:    map[string]any{"nested": true, "via": via, "definedIn": "thomasboni/nested-actions-d@main:action.yml:8", "uses": "thomasboni/nested-actions-e@main"},
	}
	fs := []opaengine.Finding{f}
	control.NestedFixMessages(fs)
	return fs[0]
}

// nestedDirectB is the reproduction's direct B finding.
func nestedDirectB() opaengine.Finding {
	return opaengine.Finding{
		Code: "ISSUE-701", Severity: "high", File: ".github/workflows/ci.yml", Line: 13, Job: "ci/nested",
		Message: `job "ci/nested" references action "thomasboni/nested-actions-b@main" with a mutable ref` + " \u2014 pin by commit SHA instead",
		URL:     "https://github.com/thomasboni/nested-actions-a/blob/main/.github/workflows/ci.yml#L13",
		Data:    map[string]any{"uses": "thomasboni/nested-actions-b@main"},
	}
}

// TestNestedDetailLines_SoLineCarriesTheFixOnce pins spec section 6
// (maintainer review of PR 549): when the message already closes on the
// nested fix, the explain view prints it once, on the So line the message
// half feeds, and drops the fix detail line that would repeat it.
func TestNestedDetailLines_SoLineCarriesTheFixOnce(t *testing.T) {
	f := nestedE()
	got := strings.Join(detailLinesFromFinding(f), "\n")
	if strings.Contains(got, "fix:") {
		t.Errorf("the fix detail line repeats the So line:\n%s", got)
	}
	_, so := findingBranch(detailedFinding{Code: control.ErrorCode(f.Code), Message: f.Message, File: f.File, Job: f.Job})
	if !strings.HasPrefix(so, "pin the outermost action to a commit SHA whose definition pins this reference") {
		t.Errorf("So = %q, want the nested fix", so)
	}
}

// TestGLSAST_NestedSolutionIsTheNestedRemediation pins spec section 6
// (maintainer review of PR 549): a nested finding's GitLab SAST solution is
// its code's nested remediation, a direct finding's stays the direct one.
func TestGLSAST_NestedSolutionIsTheNestedRemediation(t *testing.T) {
	info := control.LookupCode(control.CodeActionUnpinned)
	report := buildGLSAST([]opaengine.Finding{nestedDirectB(), nestedE()}, "github")
	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %d", len(report.Vulnerabilities))
	}
	if got := report.Vulnerabilities[0].Solution; got != info.Remediation {
		t.Errorf("direct solution = %q, want %q", got, info.Remediation)
	}
	if got := report.Vulnerabilities[1].Solution; got != info.NestedRemediation {
		t.Errorf("nested solution = %q, want %q", got, info.NestedRemediation)
	}
}

// TestBuildSARIF_NestedResultRelatesTheContainer pins spec section 6
// (maintainer review of PR 549): a nested result keeps its primary location
// on the workflow step (one location-less result rejects the whole Code
// Scanning upload) and gains one related location at the container line,
// an absolute blob URL with its region. A direct result has none.
func TestBuildSARIF_NestedResultRelatesTheContainer(t *testing.T) {
	log := buildSARIF([]opaengine.Finding{nestedDirectB(), nestedE()}, ".github/workflows", "github")
	rs := log.Runs[0].Results
	if len(rs) != 2 {
		t.Fatalf("results = %d", len(rs))
	}
	if rs[0].RelatedLocations != nil {
		t.Errorf("a direct result has no related location: %+v", rs[0].RelatedLocations)
	}
	e := rs[1]
	if len(e.Locations) != 1 || e.Locations[0].PhysicalLocation.ArtifactLocation.URI != ".github/workflows/ci.yml" || e.Locations[0].PhysicalLocation.Region == nil || e.Locations[0].PhysicalLocation.Region.StartLine != 13 {
		t.Fatalf("primary location = %+v, want the workflow step", e.Locations)
	}
	if len(e.RelatedLocations) != 1 {
		t.Fatalf("related locations = %+v, want one", e.RelatedLocations)
	}
	rel := e.RelatedLocations[0]
	if rel.PhysicalLocation.ArtifactLocation.URI != "https://github.com/thomasboni/nested-actions-d/blob/main/action.yml" {
		t.Errorf("related uri = %q", rel.PhysicalLocation.ArtifactLocation.URI)
	}
	if rel.PhysicalLocation.Region == nil || rel.PhysicalLocation.Region.StartLine != 8 {
		t.Errorf("related region = %+v, want line 8", rel.PhysicalLocation.Region)
	}
	if rel.Message == nil || rel.Message.Text != "defined in thomasboni/nested-actions-d@main, action.yml line 8" {
		t.Errorf("related message = %+v", rel.Message)
	}
}

// TestPlatformCollectionFor_ActionsClosure pins spec section 7: a budget
// overflow names actions_closure among the missing fields of a push.
func TestPlatformCollectionFor_ActionsClosure(t *testing.T) {
	conf := &configuration.Configuration{PlatformRun: &platform.RunContext{
		Context: &platform.ProjectContext{Snapshot: platform.Snapshot{Data: &platform.SnapshotData{MergedYaml: "a: 1\n"}}},
	}}
	got := platformCollectionFor(conf, &control.AnalysisResult{NestedActionsBudgetExceeded: true, DataCollectionDegraded: true})
	if strings.Join(got.MissingFields, ",") != "actions_closure,branch_protection,mr_approvals,variables" {
		t.Fatalf("missing fields = %v", got.MissingFields)
	}
}

// TestNestedDetailLines_LocalCompositeKeepsTheDirectFix pins the Task 3
// round ruling L2: under a local composite (outermost via ./...) the user
// owns the file that holds the reference, so no nested fix is printed (the
// control's own fix applies), while the container line is still shown.
func TestNestedDetailLines_LocalCompositeKeepsTheDirectFix(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-701", File: ".github/workflows/ci.yml", Line: 13, Data: map[string]any{
		"definedIn": "./.github/actions/setup/action.yml:5", "via": []any{"./.github/actions/setup"},
	}}
	got := strings.Join(detailLinesFromFinding(f), "\n")
	if !strings.Contains(got, "defined in this repository, .github/actions/setup/action.yml line 5") {
		t.Errorf("detail lines lack the container line:\n%s", got)
	}
	if strings.Contains(got, "fix:") {
		t.Errorf("a local composite takes the direct remediation, got:\n%s", got)
	}
}

// TestRenderUnexpandedActions_NeverHardCodesTheBudget pins the Task 3
// round ruling L5: the budget numbers come from the github package, so the
// terminal line for a budget reference names no number of its own.
func TestRenderUnexpandedActions_NeverHardCodesTheBudget(t *testing.T) {
	var b bytes.Buffer
	renderUnexpandedActions(&b, []ir.UnexpandedAction{{Uses: "a/1@v1", Reason: ir.UnexpandedBudget}})
	if out := b.String(); !strings.Contains(out, "a/1@v1 (past the nested resolution budget)") || strings.Contains(out, "100") {
		t.Fatalf("output:\n%s", out)
	}
}

// TestRenderWarnings_NoTokenHintUnderTheOfflineSwitch pins the Task 3
// round ruling L6: a token cannot help a run with the GitHub API switched
// off, so the warnings block does not point at PLUMBER_METADATA_TOKEN.
func TestRenderWarnings_NoTokenHintUnderTheOfflineSwitch(t *testing.T) {
	warnings := []string{"nested actions were not resolved: the GitHub API is disabled (PLUMBER_DISABLE_GITHUB_API)"}
	var off, on bytes.Buffer
	t.Setenv(githubpkg.EnvDisableGitHubAPI, "1")
	renderWarningsTo(&off, warnings)
	if strings.Contains(off.String(), "PLUMBER_METADATA_TOKEN") || !strings.Contains(off.String(), "nested actions were not resolved") {
		t.Errorf("offline:\n%s", off.String())
	}
	t.Setenv(githubpkg.EnvDisableGitHubAPI, "")
	renderWarningsTo(&on, warnings)
	if !strings.Contains(on.String(), "PLUMBER_METADATA_TOKEN") {
		t.Errorf("online:\n%s", on.String())
	}
}
