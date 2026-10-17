package opa

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestEnrichFindings_NestedJobAnchorsOnTheCaller pins R9 for a job
// appended from another repository's workflow: its finding sits on the
// calling job's file and line and links the callee's line (definedIn).
func TestEnrichFindings_NestedJobAnchorsOnTheCaller(t *testing.T) {
	p := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9},
		{Name: "ci/call/build", Nested: true, Via: []string{"acme/shared/.github/workflows/build.yml@v1"},
			OriginFile: "acme/shared/.github/workflows/build.yml@v1", OriginLine: 4,
			Callers: []ir.ReusableCaller{{Job: "ci/call"}}},
	}}
	fs := []Finding{{Code: "ISSUE-803", Job: "ci/call/build"}}
	enrichFindingsWithJobLocation(fs, p)
	if fs[0].File != ".github/workflows/ci.yml" || fs[0].Line != 9 {
		t.Fatalf("location = %s:%d, want the calling job's", fs[0].File, fs[0].Line)
	}
	if fs[0].Data["definedIn"] != "acme/shared@v1:.github/workflows/build.yml:4" || fs[0].Data["nested"] != true {
		t.Fatalf("data = %v", fs[0].Data)
	}
	via, _ := fs[0].Data["via"].([]any)
	if len(via) != 1 || via[0] != "acme/shared/.github/workflows/build.yml@v1" {
		t.Fatalf("via = %v", fs[0].Data["via"])
	}
}

// TestEnrichFindings_NestedJobWithoutCallersAnchorsOnItsNamePrefix pins
// R9 (review M3 ruling): with no Callers recorded, a nested job's finding
// still lands in the scanned repository, on the job its name nests under.
func TestEnrichFindings_NestedJobWithoutCallersAnchorsOnItsNamePrefix(t *testing.T) {
	p := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9},
		{Name: "ci/call/x", Nested: true, OriginFile: "acme/shared/.github/workflows/x.yml@v1", OriginLine: 4},
		{Name: "ci/call/x/y", Nested: true, OriginFile: "acme/other/.github/workflows/y.yml@v1", OriginLine: 3},
	}}
	fs := []Finding{{Code: "ISSUE-803", Job: "ci/call/x/y"}}
	enrichFindingsWithJobLocation(fs, p)
	if fs[0].File != ".github/workflows/ci.yml" || fs[0].Line != 9 {
		t.Fatalf("location = %s:%d, want the scanned job's", fs[0].File, fs[0].Line)
	}
}
