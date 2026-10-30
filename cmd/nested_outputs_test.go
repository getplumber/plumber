package cmd

import (
	"bytes"
	"encoding/json"
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

// TestBuildSARIF_NestedResultNamesTheContainerInTheMessage pins spec
// section 6 as amended on 2026-10-30 (invoke-ai/InvokeAI run 41127816328):
// Code Scanning rejects the WHOLE upload when any location, related ones
// included, carries a URI whose scheme is not the checkout's ("SARIF URI
// scheme "https" did not match the checkout URI scheme "file""). So a nested
// result keeps its one primary location on the workflow step, carries no
// related location, and names the container line in its message as an
// embedded link to the blob URL. A direct result's message is unchanged.
func TestBuildSARIF_NestedResultNamesTheContainerInTheMessage(t *testing.T) {
	log := buildSARIF([]opaengine.Finding{nestedDirectB(), nestedE()}, ".github/workflows", "github")
	rs := log.Runs[0].Results
	if len(rs) != 2 {
		t.Fatalf("results = %d", len(rs))
	}
	if strings.Contains(rs[0].Message.Text, "defined in") {
		t.Errorf("a direct result names no container:\n%s", rs[0].Message.Text)
	}
	e := rs[1]
	if len(e.Locations) != 1 || e.Locations[0].PhysicalLocation.ArtifactLocation.URI != ".github/workflows/ci.yml" || e.Locations[0].PhysicalLocation.Region == nil || e.Locations[0].PhysicalLocation.Region.StartLine != 13 {
		t.Fatalf("primary location = %+v, want the workflow step", e.Locations)
	}
	want := " (defined in [thomasboni/nested-actions-d@main, action.yml line 8](https://github.com/thomasboni/nested-actions-d/blob/main/action.yml#L8))"
	if !strings.HasSuffix(e.Message.Text, want) {
		t.Errorf("nested message = %q, want the container link as its tail %q", e.Message.Text, want)
	}
	raw, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("relatedLocations")) {
		t.Errorf("the SARIF carries a related location; Code Scanning rejects a URI outside the checkout:\n%s", raw)
	}
	for _, uri := range sarifLocationURIs(t, raw) {
		if strings.Contains(uri, "://") {
			t.Errorf("location uri %q is not repository-relative; Code Scanning rejects the whole upload", uri)
		}
	}
}

// sarifLocationURIs lists every artifactLocation.uri in a serialized SARIF
// log, wherever it sits (primary, related, or any future location kind).
func sarifLocationURIs(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var uris []string
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				if key == "artifactLocation" && k == "uri" {
					if s, ok := vv.(string); ok {
						uris = append(uris, s)
					}
				}
				walk(vv, k)
			}
		case []any:
			for _, vv := range x {
				walk(vv, key)
			}
		}
	}
	walk(doc, "")
	return uris
}

// TestBuildSARIF_NestedAnchorKeepsTheContainerBeforeTheExplanation pins
// the order of the two message tails on a nested finding that also anchors
// an attack path in a v4 run (control.AnnotateFindingsV4 writes the
// explanation on any anchor, nested or not): the container link comes first,
// the explanation block after its blank line, neither lost (bot review of PR
// 583, test coverage).
func TestBuildSARIF_NestedAnchorKeepsTheContainerBeforeTheExplanation(t *testing.T) {
	f := nestedE()
	f.Data["explanation"] = "A new version of `thomasboni/nested-actions-e@main` runs inside `ci/nested`."
	f.Data["baseSeverity"] = "high"
	f.Data["role"] = "Entry of path 1"
	log := buildSARIF([]opaengine.Finding{f}, ".github/workflows", "github")
	got := log.Runs[0].Results[0].Message.Text
	note := " (defined in [thomasboni/nested-actions-d@main, action.yml line 8](https://github.com/thomasboni/nested-actions-d/blob/main/action.yml#L8))"
	expl := "\n\nA new version of `thomasboni/nested-actions-e@main` runs inside `ci/nested`."
	if !strings.HasSuffix(got, note+expl) {
		t.Errorf("message = %q, want the container link then the explanation as its tail", got)
	}
	if strings.Count(got, "defined in [") != 1 {
		t.Errorf("the container link must appear exactly once:\n%s", got)
	}
}

// TestBuildSARIF_NestedContainerLinkStaysWellFormed pins the escaping of the
// container link (bot review of PR 583): a container path may carry the
// characters SARIF reserves in an embedded link (section 3.11.6), so the link
// text escapes brackets like the message body does and the link target
// percent-encodes the parentheses that would close it early, leaving the URL
// valid.
func TestBuildSARIF_NestedContainerLinkStaysWellFormed(t *testing.T) {
	f := nestedE()
	f.Data["definedIn"] = "thomasboni/nested-actions-d@main:dir(x)/action[y].yml:8"
	f.URL = "https://github.com/thomasboni/nested-actions-d/blob/main/dir(x)/action[y].yml#L8"
	log := buildSARIF([]opaengine.Finding{f}, ".github/workflows", "github")
	got := log.Runs[0].Results[0].Message.Text
	want := ` (defined in [thomasboni/nested-actions-d@main, dir(x)/action\[y\].yml line 8](https://github.com/thomasboni/nested-actions-d/blob/main/dir%28x%29/action[y].yml#L8))`
	if !strings.HasSuffix(got, want) {
		t.Errorf("message = %q, want the tail %q", got, want)
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
