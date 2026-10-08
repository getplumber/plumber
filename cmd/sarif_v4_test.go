package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// Under scoring-v4, AnnotateFindingsV4 (control/annotate.go) stamps every
// finding's Data["baseSeverity"] with the registered severity and overwrites
// f.Severity with the contextual one. That stamp is the gate SARIF reads: a
// finding carrying Data["baseSeverity"] uses f.Severity for its result level;
// one without it (a v3 run, or a v4 request that fell back to v3) keeps the
// registry override exactly as before. ISSUE-307 is registered Low, so
// stamping it contextual Critical makes the difference visible: registry
// would give "note", contextual gives "error".
func TestSarifResultLevelUsesContextualSeverityUnderV4(t *testing.T) {
	findings := []opaengine.Finding{
		{
			Code:     "ISSUE-307",
			Severity: "critical", // contextual, written by AnnotateFindingsV4
			Message:  "checkout persists credentials",
			File:     ".github/workflows/release.yml",
			Line:     12,
			Data: map[string]any{
				"baseSeverity": "low",
				"role":         "Entry of path p1",
				"pathIds":      []string{"p1"},
				"explanation":  "A new version of `some/action@v1` runs inside `release`.",
			},
		},
	}

	doc := buildSARIF(findings, "", "github")
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)

	res := doc.Runs[0].Results[0]
	if res.Level != "error" {
		t.Errorf("level = %q, want error (contextual critical, not registry low -> note)", res.Level)
	}

	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if got, _ := rule.Properties["security-severity"].(string); got != "9.5" {
		t.Errorf("rule security-severity = %q, want 9.5 (contextual critical)", got)
	}

	if res.Properties["plumber/role"] != "Entry of path p1" {
		t.Errorf("properties[plumber/role] = %v, want %q", res.Properties["plumber/role"], "Entry of path p1")
	}
	if res.Properties["plumber/baseSeverity"] != "low" {
		t.Errorf("properties[plumber/baseSeverity] = %v, want low", res.Properties["plumber/baseSeverity"])
	}
	ids, ok := res.Properties["plumber/pathIds"].([]string)
	if !ok || len(ids) != 1 || ids[0] != "p1" {
		t.Errorf("properties[plumber/pathIds] = %v, want [p1]", res.Properties["plumber/pathIds"])
	}

	if !strings.Contains(res.Message.Text, "\n\nA new version of") {
		t.Errorf("message does not carry the appended explanation:\n%s", res.Message.Text)
	}

	for _, want := range []string{`"level":"error"`, `"security-severity":"9.5"`, "plumber/role", "A new version of"} {
		if !strings.Contains(s, want) {
			t.Errorf("SARIF lacks %s:\n%s", want, s)
		}
	}
}

// A role that is not "Entry of path <id>" (a privilege/gate finding, walked
// on a path rather than anchoring it) carries baseSeverity/role/pathIds but
// no explanation: AnnotateFindingsV4 only writes one for the anchor.
func TestSarifResultNoExplanationWhenRoleIsNotAnAnchor(t *testing.T) {
	findings := []opaengine.Finding{
		{
			Code:     "ISSUE-102",
			Severity: "high",
			Message:  "job has write permission",
			Data: map[string]any{
				"baseSeverity": "medium",
				"role":         "Privilege: on path p1",
				"pathIds":      []string{"p1"},
			},
		},
	}
	doc := buildSARIF(findings, "", "github")
	res := doc.Runs[0].Results[0]
	if strings.Contains(res.Message.Text, "\n\n") {
		t.Errorf("message carries an unexpected appended block: %q", res.Message.Text)
	}
	if res.Properties["plumber/role"] != "Privilege: on path p1" {
		t.Errorf("properties[plumber/role] = %v", res.Properties["plumber/role"])
	}
}

// The rule's security-severity (and default level) is a
// rule-level property, but one run can carry several results for the same
// code at different contextual severities (the same control firing on
// several attack paths). The rule must carry the HIGHEST contextual
// severity among this run's results for that code, so Code Scanning's
// severity filter never hides a critical path behind a low twin sharing the
// same rule.
func TestSarifRuleCarriesHighestContextualSeverityAmongItsResults(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-307", Severity: "medium", Message: "a", Data: map[string]any{"baseSeverity": "low"}},
		{Code: "ISSUE-307", Severity: "critical", Message: "b", Data: map[string]any{"baseSeverity": "low"}},
	}
	doc := buildSARIF(findings, "", "github")

	if len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("rules = %d, want 1 (one distinct code)", len(doc.Runs[0].Tool.Driver.Rules))
	}
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if got, _ := rule.Properties["security-severity"].(string); got != "9.5" {
		t.Errorf("rule security-severity = %q, want 9.5 (max of medium and critical)", got)
	}

	// Each result still carries its OWN contextual level, independent of the
	// rule-level aggregate. Results preserve finding order, so index 0 is
	// the medium one and index 1 the critical one.
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("results = %d, want 2", len(doc.Runs[0].Results))
	}
	if got := doc.Runs[0].Results[0].Level; got != "warning" { // medium
		t.Errorf("result a level = %q, want warning", got)
	}
	if got := doc.Runs[0].Results[1].Level; got != "error" { // critical
		t.Errorf("result b level = %q, want error", got)
	}
}

// v3 (and a v4 request that fell back to v3: AnnotateFindingsV4 never ran,
// so no finding carries Data["baseSeverity"]) must be byte-identical to
// before this change: the registry severity overrides f.Severity exactly as
// it did pre-v4, and none of the plumber/* v4 properties appear.
func TestSarifV3UnaffectedByContextualOverride(t *testing.T) {
	findings := []opaengine.Finding{
		// Registered Low (ISSUE-307), but f.Severity carries a stale/unrelated
		// value the way an un-annotated finding might; the registry must win
		// because there is no Data["baseSeverity"] gate present.
		{Code: "ISSUE-307", Severity: "critical", Message: "checkout persists credentials"},
	}
	doc := buildSARIF(findings, "", "github")
	res := doc.Runs[0].Results[0]
	if res.Level != "note" {
		t.Errorf("level = %q, want note (registry low, v3 behavior)", res.Level)
	}
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if got, _ := rule.Properties["security-severity"].(string); got != "2.0" {
		t.Errorf("rule security-severity = %q, want 2.0 (registry low)", got)
	}
	if res.Properties != nil {
		if _, ok := res.Properties["plumber/baseSeverity"]; ok {
			t.Errorf("v3 result must not carry plumber/baseSeverity")
		}
		if _, ok := res.Properties["plumber/role"]; ok {
			t.Errorf("v3 result must not carry plumber/role")
		}
	}
	if strings.Contains(res.Message.Text, "\n\n") {
		t.Errorf("v3 message must not carry an appended explanation: %q", res.Message.Text)
	}
}

// TestSarifResultKeepsURLAlongsideEveryContextualProperty pins the nil-
// checked Properties accumulation buildSARIF switched to in this PR
// (res.Properties[...] = ... inserts, not the old res.Properties =
// map[string]any{...} overwrite): a finding carrying both f.URL (set by
// the location linker on real CI findings) and every v4 Data key must keep
// url and all plumber/* properties together, and the platform policies
// union (spec s5) must survive alongside them too. Every existing v4 SARIF
// test leaves f.URL empty and none sets Policies, so this combination
// never ran: a regression back to the overwrite form would clobber
// plumber/* on exactly this common finding with every other test still
// green.
func TestSarifResultKeepsURLAlongsideEveryContextualProperty(t *testing.T) {
	findings := []opaengine.Finding{
		{
			Code:     "ISSUE-307",
			Severity: "critical",
			Message:  "checkout persists credentials",
			URL:      "https://github.com/acme/repo/blob/abc123/.github/workflows/release.yml#L12",
			Policies: []string{"policy-a", "policy-b"},
			Data: map[string]any{
				"baseSeverity": "low",
				"role":         "Entry of path p1",
				"pathIds":      []string{"p1"},
			},
		},
	}
	doc := buildSARIF(findings, "", "github")
	res := doc.Runs[0].Results[0]
	if res.Properties["url"] != findings[0].URL {
		t.Errorf("properties[url] = %v, want %q", res.Properties["url"], findings[0].URL)
	}
	if res.Properties["plumber/role"] != "Entry of path p1" {
		t.Errorf("properties[plumber/role] = %v, want %q", res.Properties["plumber/role"], "Entry of path p1")
	}
	if res.Properties["plumber/baseSeverity"] != "low" {
		t.Errorf("properties[plumber/baseSeverity] = %v, want low", res.Properties["plumber/baseSeverity"])
	}
	ids, ok := res.Properties["plumber/pathIds"].([]string)
	if !ok || len(ids) != 1 || ids[0] != "p1" {
		t.Errorf("properties[plumber/pathIds] = %v, want [p1]", res.Properties["plumber/pathIds"])
	}
	policies, ok := res.Properties["policies"].([]string)
	if !ok || len(policies) != 2 {
		t.Errorf("properties[policies] = %v, want the two-policy union", res.Properties["policies"])
	}
}

// Same gate, GitLab SAST report: the `severity` field follows f.Severity
// when Data["baseSeverity"] is present, and the registry override exactly
// as today otherwise.
func TestGLSASTSeverityUsesContextualSeverityUnderV4(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-307", Severity: "critical", Message: "annotated", Data: map[string]any{"baseSeverity": "low"}},
		{Code: "ISSUE-307", Severity: "critical", Message: "not annotated"},
	}
	rep := buildGLSAST(findings, "github")
	if len(rep.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %d, want 2", len(rep.Vulnerabilities))
	}
	sevByMessage := map[string]string{}
	for _, v := range rep.Vulnerabilities {
		sevByMessage[v.Message] = v.Severity
	}
	if sevByMessage["annotated"] != "Critical" {
		t.Errorf("annotated severity = %q, want Critical (contextual)", sevByMessage["annotated"])
	}
	if sevByMessage["not annotated"] != "Low" {
		t.Errorf("not-annotated severity = %q, want Low (registry, v3 behavior)", sevByMessage["not annotated"])
	}
}

// Spec section 4: the GitLab SAST report appends the path sentence to the
// vulnerability description, as SARIF appends it to the message. A finding
// with no explanation (v3, or not an anchor) is unchanged.
func TestGLSASTDescriptionCarriesThePathSentenceUnderV4(t *testing.T) {
	const sentence = "Anyone who can open a pull request or push a commit controls `github.event.pull_request.title`, which `ci/build` passes to a shell."
	findings := []opaengine.Finding{
		{Code: "ISSUE-207", Severity: "medium", Message: "anchored", Data: map[string]any{"baseSeverity": "critical", "explanation": sentence}},
		{Code: "ISSUE-207", Severity: "critical", Message: "plain"},
	}
	rep := buildGLSAST(findings, "github")
	byMessage := map[string]string{}
	for _, v := range rep.Vulnerabilities {
		byMessage[v.Message] = v.Description
	}
	if want := "\n\nFinding: anchored\n\n" + sentence; !strings.HasSuffix(byMessage["anchored"], want) {
		t.Errorf("description = %q, want it to end with %q", byMessage["anchored"], want)
	}
	if !strings.HasSuffix(byMessage["plain"], "\n\nFinding: plain") {
		t.Errorf("a finding with no explanation must keep its description, got %q", byMessage["plain"])
	}
}
