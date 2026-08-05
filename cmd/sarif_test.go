package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func TestBuildSARIF_PartialFingerprints(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned", File: ".github/workflows/ci.yml", Line: 28, Fingerprint: "deadbeefcafef00d"},
	}
	doc := buildSARIF(findings, ".plumber.yaml", "github")
	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want 1", len(doc.Runs[0].Results))
	}
	if got := doc.Runs[0].Results[0].PartialFingerprints["plumber/v1"]; got != "deadbeefcafef00d" {
		t.Errorf("partialFingerprints[plumber/v1] = %q, want deadbeefcafef00d", got)
	}
}

func TestBuildSARIF_ShapeAndSeverityMapping(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned action", File: ".github/workflows/ci.yml", Line: 28},
		{Code: "ISSUE-203", Severity: "critical", Message: "debug trace", File: "./.github/workflows/ci.yml", Line: 11},
		{Code: "ISSUE-501", Severity: "critical", Message: "branch not protected"}, // repo-level, no file
	}

	doc := buildSARIF(findings, ".plumber.yaml", "gitlab")

	// Must serialize to valid JSON.
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("SARIF does not marshal: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]

	if run.Tool.Driver.Name != "Plumber" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	// Three distinct codes -> three rules.
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(run.Tool.Driver.Rules))
	}

	// Severity -> level mapping.
	levels := map[string]string{}
	for _, r := range run.Results {
		levels[r.RuleID] = r.Level
	}
	if levels["ISSUE-701"] != "error" { // high
		t.Errorf("ISSUE-701 level = %q, want error", levels["ISSUE-701"])
	}
	if levels["ISSUE-501"] != "error" { // critical
		t.Errorf("ISSUE-501 level = %q, want error", levels["ISSUE-501"])
	}

	// File/line location present and "./" stripped; region carries the line.
	// Every result must carry at least one location (GitHub Code Scanning
	// rejects location-less results); repo-level findings fall back to the
	// config file with no region.
	for _, r := range run.Results {
		if len(r.Locations) == 0 {
			t.Errorf("%s has no location; Code Scanning requires one", r.RuleID)
		}
		switch r.RuleID {
		case "ISSUE-701":
			loc := r.Locations[0].PhysicalLocation
			if loc.ArtifactLocation.URI != ".github/workflows/ci.yml" {
				t.Errorf("uri = %q", loc.ArtifactLocation.URI)
			}
			if loc.Region == nil || loc.Region.StartLine != 28 {
				t.Errorf("region = %+v, want startLine 28", loc.Region)
			}
		case "ISSUE-203":
			if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != ".github/workflows/ci.yml" {
				t.Errorf("ISSUE-203 './' not stripped: %q", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
			}
		case "ISSUE-501":
			// Repo-level: anchored to the fallback (config) file, no region.
			loc := r.Locations[0].PhysicalLocation
			if loc.ArtifactLocation.URI != ".plumber.yaml" {
				t.Errorf("ISSUE-501 should fall back to .plumber.yaml, got %q", loc.ArtifactLocation.URI)
			}
			if loc.Region != nil {
				t.Errorf("ISSUE-501 fallback location should have no region, got %+v", loc.Region)
			}
		}
	}

	// Rules carry helpUri + security-severity from the codes registry.
	for _, r := range run.Tool.Driver.Rules {
		if r.HelpURI == "" {
			t.Errorf("rule %s missing helpUri", r.ID)
		}
		if _, ok := r.Properties["security-severity"]; !ok {
			t.Errorf("rule %s missing security-severity", r.ID)
		}
	}

	// Rules also carry controlName, and it resolves to the correct
	// .plumber.yaml control key.
	for _, r := range run.Tool.Driver.Rules {
		if _, ok := r.Properties["controlName"]; !ok {
			t.Errorf("rule %s missing controlName", r.ID)
		}
		if r.ID == "ISSUE-701" {
			if got := r.Properties["controlName"]; got != "actionsMustBePinnedByCommitSha" {
				t.Errorf("ISSUE-701 controlName = %v, want actionsMustBePinnedByCommitSha", got)
			}
		}
	}
}

func TestBuildSARIF_AllCodedFindingsBecomeResults(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "a"},
		{Code: "", Severity: "high", Message: "skipped"},
		{Code: "ISSUE-203", Severity: "critical", Message: "b"},
	}
	doc := buildSARIF(findings, ".plumber.yaml", "gitlab")
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("results = %d, want 2 (empty code omitted)", len(doc.Runs[0].Results))
	}
}

func TestBuildSARIF_CleanRunIsValidEmpty(t *testing.T) {
	doc := buildSARIF(nil, ".plumber.yaml", "gitlab")
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("clean SARIF malformed: %+v", doc)
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("clean run should have 0 results, got %d", len(doc.Runs[0].Results))
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("clean SARIF does not marshal: %v", err)
	}
}

// Finding results carry an explicit kind: fail (the spec default, stated
// so intent is visible) and NOTHING ELSE: synthetic per-control status
// results (kind pass / notApplicable / open) were verified 2026-07-31 to
// flood GitHub Code Scanning with one junk alert per result -- Code
// Scanning ignores result.kind and alerts on every result (see the
// comment in buildSARIF). Status lives in the JSON report only.
func TestBuildSARIF_OnlyFindingResultsAllKindFail(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned", File: "wf.yml", Line: 3},
		{Code: "ISSUE-203", Severity: "critical", Message: "debug trace"},
	}
	doc := buildSARIF(findings, ".plumber.yaml", "github")
	run := doc.Runs[0]
	if len(run.Results) != len(findings) {
		t.Fatalf("results = %d, want exactly one per finding (no synthetic status results)", len(run.Results))
	}
	for _, r := range run.Results {
		if r.Kind != "fail" {
			t.Errorf("%s kind = %q, want fail (non-fail kinds create junk Code Scanning alerts)", r.RuleID, r.Kind)
		}
	}
}

// #352 review: writeSARIFToFile must not anchor a repo-level (file-less)
// finding to a config path that does not exist on disk. A zero-config run
// loads the embedded default and writes no .plumber.yaml, so anchoring to
// that phantom path would emit a Code Scanning URI mapping to no committed
// file. With no real config present the finding gets no physical location;
// with one present it anchors to it (unchanged behaviour).
func TestWriteSARIFToFile_FilelessAnchorGuardedOnConfigExistence(t *testing.T) {
	result := &control.AnalysisResult{Findings: []opaengine.Finding{
		{Code: "ISSUE-501", Severity: "critical", Message: "branch not protected"}, // no File
	}}
	orig := configFile
	defer func() { configFile = orig }()

	t.Run("absent config -> no phantom location", func(t *testing.T) {
		dir := t.TempDir()
		configFile = filepath.Join(dir, ".plumber.yaml") // does not exist
		out := filepath.Join(dir, "out.sarif")
		if err := writeSARIFToFile(result, out, "github"); err != nil {
			t.Fatalf("writeSARIFToFile: %v", err)
		}
		if sb := mustRead(t, out); strings.Contains(sb, "artifactLocation") {
			t.Errorf("file-less finding must not anchor to a non-existent config:\n%s", sb)
		}
	})

	t.Run("present config -> anchored to it", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, ".plumber.yaml")
		if err := os.WriteFile(cfg, []byte("version: \"2.0\"\n"), 0o644); err != nil {
			t.Fatalf("write cfg: %v", err)
		}
		configFile = cfg
		out := filepath.Join(dir, "out.sarif")
		if err := writeSARIFToFile(result, out, "github"); err != nil {
			t.Fatalf("writeSARIFToFile: %v", err)
		}
		if sb := mustRead(t, out); !strings.Contains(sb, "artifactLocation") {
			t.Errorf("file-less finding should anchor to the existing config:\n%s", sb)
		}
	})
}

// Issue #372: a GHAS inline PR comment must let a reader identify which Plumber
// issue fired and reach its documentation. Code Scanning does not surface
// ruleId prominently and ignores helpUri in that view, so the code goes in the
// message and the doc link goes in help.markdown, which Code Scanning renders
// in place of help.text.
func TestBuildSARIF_AlertCarriesIssueCodeAndDocLink(t *testing.T) {
	code := "ISSUE-701"
	info := control.LookupCode(control.ErrorCode(code))
	if info == nil {
		t.Fatalf("test prerequisite: %s must be registered", code)
		return // unreachable, but staticcheck does not treat Fatalf as terminating
	}

	doc := buildSARIF([]opaengine.Finding{
		{Code: code, Severity: "high", Message: "unpinned action", File: "ci.yml", Line: 3},
	}, ".plumber.yaml", "github")

	res := doc.Runs[0].Results[0]
	if !strings.HasPrefix(res.Message.Text, "["+code+"](") {
		t.Errorf("message = %q, want it to open with the code as an embedded link so the code is visible and clickable in the comment", res.Message.Text)
	}
	if !strings.Contains(res.Message.Text, "unpinned action") {
		t.Errorf("message = %q, want the finding detail preserved", res.Message.Text)
	}

	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if rule.Help == nil {
		t.Fatal("rule.help missing; Code Scanning renders help.markdown next to the alert")
	}
	help := *rule.Help
	if help.Markdown == "" {
		t.Fatal("rule.help.markdown missing; Code Scanning renders it in place of help.text")
	}
	if !strings.Contains(help.Markdown, code) {
		t.Errorf("help.markdown %q does not name the issue code", help.Markdown)
	}
	if !strings.Contains(help.Markdown, "("+info.DocURL+")") {
		t.Errorf("help.markdown %q lacks a markdown link to %s", help.Markdown, info.DocURL)
	}
	if info.Remediation != "" && !strings.Contains(help.Markdown, info.Remediation) {
		t.Errorf("help.markdown %q lacks the remediation", help.Markdown)
	}
	// help.text must carry the same facts for consumers that do not render Markdown.
	if !strings.Contains(help.Text, code) || !strings.Contains(help.Text, info.DocURL) {
		t.Errorf("help.text %q must also carry the code and doc URL", help.Text)
	}
}

// Code Scanning reads ONLY partialFingerprints.primaryLocationLineHash; any
// other key is ignored, and without it GitHub falls back to hashing the
// surrounding source, so a dismissal is lost the moment the line drifts.
func TestBuildSARIF_EmitsPrimaryLocationLineHash(t *testing.T) {
	doc := buildSARIF([]opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "x", File: "ci.yml", Line: 3, Fingerprint: "deadbeefcafef00d"},
	}, ".plumber.yaml", "github")

	fp := doc.Runs[0].Results[0].PartialFingerprints
	if got := fp["primaryLocationLineHash"]; got != "deadbeefcafef00d" {
		t.Errorf("primaryLocationLineHash = %q, want the stable fingerprint; Code Scanning ignores every other key", got)
	}
	if got := fp["plumber/v1"]; got != "deadbeefcafef00d" {
		t.Errorf("plumber/v1 = %q, want the same value under the self-describing name", got)
	}
}

// Two findings that differ only by line must share an alert identity, so an
// edit above a finding does not resurrect a dismissed alert.
func TestBuildSARIF_FingerprintSurvivesLineDrift(t *testing.T) {
	mk := func(line int) sarifLog {
		return buildSARIF([]opaengine.Finding{
			{Code: "ISSUE-701", Severity: "high", Message: "x", File: "ci.yml", Line: line, Fingerprint: "stablefingerprint"},
		}, ".plumber.yaml", "github")
	}
	a := mk(3).Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	b := mk(400).Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	if a != b {
		t.Errorf("alert identity changed on line drift: %q vs %q", a, b)
	}
}

// The inline PR comment contains only the rule title, the message, and GitHub's
// own "Show more details" link, which 404s for a reader without security-events
// access. So the message must carry the doc URL itself, or such a reader has no
// working path to the documentation.
func TestBuildSARIF_MessageCarriesDocURLForReadersWithoutAlertAccess(t *testing.T) {
	code := "ISSUE-701"
	info := control.LookupCode(control.ErrorCode(code))
	if info == nil {
		t.Fatalf("test prerequisite: %s must be registered", code)
		return // unreachable, but staticcheck does not treat Fatalf as terminating
	}

	doc := buildSARIF([]opaengine.Finding{
		{Code: code, Severity: "high", Message: "unpinned action", File: "ci.yml", Line: 3},
	}, ".plumber.yaml", "github")

	msg := doc.Runs[0].Results[0].Message.Text
	if !strings.Contains(msg, info.DocURL) {
		t.Errorf("message %q does not carry the doc URL %q", msg, info.DocURL)
	}
	// The URL is attached to the issue code as a SARIF embedded link (§3.11.6)
	// rather than trailing the message as a bare URL, so the comment reads as
	// one sentence. Embedded links are plain-text message syntax, not Markdown.
	if !strings.Contains(msg, "["+code+"]("+info.DocURL+")") {
		t.Errorf("message %q does not link the issue code to %s", msg, info.DocURL)
	}
}

// A finding detail carrying brackets of its own must not be readable as link
// syntax once the message contains an embedded link (SARIF §3.11.6).
func TestBuildSARIF_MessageEscapesBracketsInFindingDetail(t *testing.T) {
	doc := buildSARIF([]opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: `step "build[0]" uses \x`, File: "ci.yml", Line: 3},
	}, ".plumber.yaml", "github")

	msg := doc.Runs[0].Results[0].Message.Text
	if !strings.Contains(msg, `build\[0\]`) {
		t.Errorf("message %q does not escape the brackets in the finding detail", msg)
	}
	if !strings.Contains(msg, `\\x`) {
		t.Errorf("message %q does not escape the backslash in the finding detail", msg)
	}
}

// PR #394 review: a job name reads better as a code span than as quoted prose
// in the inline comment. The rewrite happens at render time, so the message the
// fingerprint is computed from (and every non-Markdown output) is unchanged.
func TestBuildSARIF_JobNameRendersAsCodeSpan(t *testing.T) {
	for _, tc := range []struct{ name, message string }{
		{"double quoted", `job "wf/injection" writes to $GITHUB_ENV`},
		{"single quoted", `Job 'wf/injection' script: curl x | bash`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := buildSARIF([]opaengine.Finding{
				{Code: "ISSUE-701", Severity: "high", Message: tc.message, Job: "wf/injection", File: "ci.yml", Line: 3},
			}, ".plumber.yaml", "github")

			msg := doc.Runs[0].Results[0].Message.Text
			if !strings.Contains(msg, "`wf/injection`") {
				t.Errorf("message %q does not render the job name as a code span", msg)
			}
			if strings.Contains(msg, `"wf/injection"`) || strings.Contains(msg, `'wf/injection'`) {
				t.Errorf("message %q still quotes the job name as prose", msg)
			}
		})
	}
}

// Only the job name is re-quoted. A quoted value that is not the job (an image
// ref, a variable, a tag) keeps the rule's own punctuation.
func TestBuildSARIF_CodeSpanLeavesOtherQuotedValuesAlone(t *testing.T) {
	doc := buildSARIF([]opaengine.Finding{
		{Code: "ISSUE-102", Severity: "high", Job: "wf/build", File: "ci.yml", Line: 3,
			Message: `job "wf/build" uses forbidden tag 'latest' (image: "alpine:latest")`},
	}, ".plumber.yaml", "github")

	msg := doc.Runs[0].Results[0].Message.Text
	if !strings.Contains(msg, "`wf/build`") {
		t.Errorf("message %q does not render the job name as a code span", msg)
	}
	if !strings.Contains(msg, `'latest'`) || !strings.Contains(msg, `"alpine:latest"`) {
		t.Errorf("message %q rewrote a quoted value that is not the job name", msg)
	}
}

// A finding with no job (repository-level controls: branch protection, repo
// settings) must pass through untouched.
func TestBuildSARIF_CodeSpanNoopWithoutJob(t *testing.T) {
	doc := buildSARIF([]opaengine.Finding{
		{Code: "ISSUE-501", Severity: "critical", Message: `branch "main" is not protected`},
	}, ".plumber.yaml", "github")

	if msg := doc.Runs[0].Results[0].Message.Text; !strings.Contains(msg, `branch "main" is not protected`) {
		t.Errorf("message %q altered a finding that has no job", msg)
	}
}

// A code span renders verbatim, so it cannot carry the backslash escapes SARIF
// requires for [ ] and \ in a message that holds an embedded link. A job name
// containing any of them keeps the rule's own quoting instead, where Markdown
// does apply the escapes. The invariant: a backslash must never appear inside
// a code span. The bracket and backslash cases are the names a GitHub scan
// really produces, since a job is namespaced by its workflow FILE base name
// (verified: ci[nightly].yml yields "ci[nightly]/build"); a GitLab job name is
// a free-form YAML key and can hold the same characters directly.
func TestBuildSARIF_CodeSpanJobNameWithReservedChars(t *testing.T) {
	for _, tc := range []struct {
		name, job string
		wantSpan  bool
	}{
		{"brackets from workflow filename", `ci[nightly]/build`, false},
		{"backslash from workflow filename", `back\slash/build`, false},
		{"backtick", "job`name", false},
		{"plain name still spanned", `wf/build`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := buildSARIF([]opaengine.Finding{
				{Code: "ISSUE-701", Severity: "high", Job: tc.job, File: "ci.yml", Line: 3,
					Message: `job "` + tc.job + `" fails`},
			}, ".plumber.yaml", "github")
			msg := doc.Runs[0].Results[0].Message.Text

			if got := strings.Contains(msg, "`"+tc.job+"`"); got != tc.wantSpan {
				t.Errorf("message %q: code-spanned = %v, want %v", msg, got, tc.wantSpan)
			}
			if inCodeSpan(msg, '\\') {
				t.Errorf("message %q has a backslash inside a code span; it renders literally", msg)
			}
		})
	}
}

// inCodeSpan reports whether r appears between an odd and the following
// backtick, i.e. inside a Markdown code span.
func inCodeSpan(s string, r rune) bool {
	open := false
	for _, c := range s {
		switch {
		case c == '`':
			open = !open
		case open && c == r:
			return true
		}
	}
	return false
}

// buildSARIF accepts a finding whose code is not in the registry (it falls back
// to the finding's own severity for those), so sarifMessage runs with info nil
// and derives the doc URL from the code instead. That derivation is the only
// route by which such a finding reaches its documentation, because the rule
// carries no help block without registry metadata.
func TestBuildSARIF_UnregisteredCodeStillLinksToDocs(t *testing.T) {
	const code = "ISSUE-000"
	if control.LookupCode(control.ErrorCode(code)) != nil {
		t.Fatalf("test prerequisite: %s must NOT be registered", code)
	}

	doc := buildSARIF([]opaengine.Finding{
		{Code: code, Severity: "high", Message: "something unregistered", File: "ci.yml", Line: 3},
	}, ".plumber.yaml", "github")

	want := "[" + code + "](https://getplumber.io/docs/cli/issues/" + code + ")"
	if msg := doc.Runs[0].Results[0].Message.Text; !strings.HasPrefix(msg, want) {
		t.Errorf("message = %q, want it to open with %q", msg, want)
	}
	// Documents the consequence: without registry metadata there is no
	// help block, so the message link is the reader's only path to the docs.
	if rule := doc.Runs[0].Tool.Driver.Rules[0]; rule.Help != nil || rule.HelpURI != "" {
		t.Errorf("rule for an unregistered code should carry no help block, got help=%+v helpUri=%q", rule.Help, rule.HelpURI)
	}
}
