package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestRenderFindingBlockPrintsTheInertReasonAfterTheLocation pins that a
// finding on a job MarkInert could never run prints "cannot run: <reason>"
// right after the location line, so a reader sees why the finding's path
// is theoretical rather than live.
func TestRenderFindingBlockPrintsTheInertReasonAfterTheLocation(t *testing.T) {
	var buf bytes.Buffer
	f := detailedFinding{
		Code:     control.CodeArtipacked,
		Message:  "boom",
		Location: ".github/workflows/ci.yml:7",
		Job:      "ci/build",
		Inert:    "no trigger",
	}
	renderFindingBlock(&buf, f, "  ", "")
	out := buf.String()
	locIdx := strings.Index(out, ".github/workflows/ci.yml:7")
	inertIdx := strings.Index(out, "cannot run: no trigger")
	if locIdx < 0 {
		t.Fatalf("location line missing: %s", out)
	}
	if inertIdx < 0 {
		t.Fatalf("inert reason missing: %s", out)
	}
	if inertIdx < locIdx {
		t.Errorf("the inert reason must print after the location line: %s", out)
	}
}

// TestRenderFindingBlockOmitsTheInertLineWhenEmpty pins that a healthy
// job's finding never prints a "cannot run" line at all.
func TestRenderFindingBlockOmitsTheInertLineWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	f := detailedFinding{Code: control.CodeArtipacked, Message: "boom", Location: ".github/workflows/ci.yml:7", Job: "ci/build"}
	renderFindingBlock(&buf, f, "  ", "")
	if strings.Contains(buf.String(), "cannot run") {
		t.Errorf("unexpected inert line on a healthy finding: %s", buf.String())
	}
}

// TestFindingsToItemsCarriesTheInertReasonByJobName pins that
// findingsToItems looks up the finding's job in the situation and
// copies its Inert reason onto the detailedFinding, the simplest path
// from MarkInert's per-job fact to the terminal report.
func TestFindingsToItemsCarriesTheInertReasonByJobName(t *testing.T) {
	sit := &control.Situation{Jobs: map[string]control.JobSituation{
		"ci/off": {Inert: "workflow disabled (disabled_manually)"},
		"ci/on":  {},
	}}
	findings := []opaengine.Finding{
		{Code: "ISSUE-1", Job: "ci/off"},
		{Code: "ISSUE-1", Job: "ci/on"},
		{Code: "ISSUE-1", Job: ""},
	}
	_, items := findingsToItems(findings, nil, false, "", sit)
	if items[0].Inert != "workflow disabled (disabled_manually)" {
		t.Errorf("ci/off: Inert = %q", items[0].Inert)
	}
	if items[1].Inert != "" {
		t.Errorf("ci/on: Inert = %q, want empty", items[1].Inert)
	}
	if items[2].Inert != "" {
		t.Errorf("job-less finding: Inert = %q, want empty", items[2].Inert)
	}
}
