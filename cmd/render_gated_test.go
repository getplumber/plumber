package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestGatedFindingPrintsItsNoteAfterTheLocation pins that a finding whose
// job no outsider can make run (control.MarkGatedFindings, Data
// "gateNote") carries the note onto its item and prints it right after
// the location line, so a reader sees why it anchors no path.
func TestGatedFindingPrintsItsNoteAfterTheLocation(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-804", Job: "ci/automerge", Data: map[string]any{"gateNote": "gated to the repository's own branches"}},
		{Code: "ISSUE-804", Job: "ci/open"},
	}
	_, items := findingsToItems(findings, nil, false, "", nil)
	if items[0].GateNote != "gated to the repository's own branches" || items[1].GateNote != "" {
		t.Fatalf("notes = %q, %q", items[0].GateNote, items[1].GateNote)
	}
	var buf bytes.Buffer
	f := items[0]
	f.Location = ".github/workflows/automerge.yml:9"
	renderFindingBlock(&buf, f, "  ", "")
	out := buf.String()
	loc, note := strings.Index(out, ".github/workflows/automerge.yml:9"), strings.Index(out, "gated to the repository's own branches")
	if loc < 0 || note < loc {
		t.Errorf("the note must print after the location line: %s", out)
	}
	buf.Reset()
	renderFindingBlock(&buf, detailedFinding{Code: control.CodePullRequestTargetWithHeadCheckout, Message: "boom"}, "  ", "")
	if strings.Contains(buf.String(), "gated to") {
		t.Errorf("unexpected note: %s", buf.String())
	}
}
