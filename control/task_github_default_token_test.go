package control

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestEnrichGitHubDefaultTokenSetsPipelineFields checks that a
// resolved write/source threads straight onto the pipeline: "true" and
// "log" both set.
func TestEnrichGitHubDefaultTokenSetsPipelineFields(t *testing.T) {
	orig := fetchGitHubDefaultTokenWrite
	t.Cleanup(func() { fetchGitHubDefaultTokenWrite = orig })
	fetchGitHubDefaultTokenWrite = func(host, owner, repo, defaultBranch string, declaresContentsWrite bool, eligible func(string) bool) (string, string) {
		return "true", "log"
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "build"}}}
	enrichGitHubDefaultToken(p, "", "acme", "widget")
	if p.DefaultTokenWrite != "true" || p.DefaultTokenSource != "log" {
		t.Fatalf("DefaultTokenWrite/Source = %q/%q, want true/log", p.DefaultTokenWrite, p.DefaultTokenSource)
	}
}

// TestEnrichGitHubDefaultTokenLeavesFieldsAbsentOnUnknown checks the IR
// contract directly: "unknown"/"unknown" from the lookup must leave
// both fields unset (absent means unknown), never write the literal
// string "unknown" into the pipeline.
func TestEnrichGitHubDefaultTokenLeavesFieldsAbsentOnUnknown(t *testing.T) {
	orig := fetchGitHubDefaultTokenWrite
	t.Cleanup(func() { fetchGitHubDefaultTokenWrite = orig })
	fetchGitHubDefaultTokenWrite = func(host, owner, repo, defaultBranch string, declaresContentsWrite bool, eligible func(string) bool) (string, string) {
		return "unknown", "unknown"
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "build"}}}
	enrichGitHubDefaultToken(p, "", "acme", "widget")
	if p.DefaultTokenWrite != "" || p.DefaultTokenSource != "" {
		t.Fatalf("DefaultTokenWrite/Source = %q/%q, want both absent", p.DefaultTokenWrite, p.DefaultTokenSource)
	}
}

// TestEnrichGitHubDefaultTokenSkipsTheLaneWhenNoJobIsEligible checks
// the gate: a pipeline where every job declares its own permissions
// has nothing for the repository default to govern, so the lookup
// must never run at all.
func TestEnrichGitHubDefaultTokenSkipsTheLaneWhenNoJobIsEligible(t *testing.T) {
	orig := fetchGitHubDefaultTokenWrite
	t.Cleanup(func() { fetchGitHubDefaultTokenWrite = orig })
	fetchGitHubDefaultTokenWrite = func(host, owner, repo, defaultBranch string, declaresContentsWrite bool, eligible func(string) bool) (string, string) {
		t.Fatal("must not be called when every job declares its own permissions")
		return "unknown", "unknown"
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "build", Permissions: map[string]any{"contents": "read"}},
		{Name: "release", Permissions: "write-all"},
	}}
	enrichGitHubDefaultToken(p, "", "acme", "widget")
	if p.DefaultTokenWrite != "" || p.DefaultTokenSource != "" {
		t.Fatalf("DefaultTokenWrite/Source = %q/%q, want both absent (lane skipped)", p.DefaultTokenWrite, p.DefaultTokenSource)
	}
}

// TestEnrichGitHubDefaultTokenWithoutOwnerRepoNeverCalls checks that an
// unaddressable project path never reaches the lookup.
func TestEnrichGitHubDefaultTokenWithoutOwnerRepoNeverCalls(t *testing.T) {
	orig := fetchGitHubDefaultTokenWrite
	t.Cleanup(func() { fetchGitHubDefaultTokenWrite = orig })
	fetchGitHubDefaultTokenWrite = func(host, owner, repo, defaultBranch string, declaresContentsWrite bool, eligible func(string) bool) (string, string) {
		t.Fatal("must not be called without an owner and a repo")
		return "unknown", "unknown"
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "build"}}}
	enrichGitHubDefaultToken(p, "", "", "widget")
}

// TestEligibleDefaultTokenWorkflowMatchesByNormalizedPath checks that
// eligibility reads off the job with no declared permissions, keyed by
// its workflow path normalized the same way the workflow-states lane
// keys its own map (ir.WorkflowStateKey): a local scan's absolute
// OriginFile and a remote scan's already repo-relative one both match.
func TestEligibleDefaultTokenWorkflowMatchesByNormalizedPath(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		// ci.yml: EVERY job must have nil Permissions; lint declares its
		// own, so the run's first job (whichever GitHub returns) could
		// be lint, and its declaration must never be misread as the
		// repository default.
		{Name: "lint", OriginFile: "/repo/.github/workflows/ci.yml", Permissions: map[string]any{"contents": "read"}},
		{Name: "build", OriginFile: "/repo/.github/workflows/ci.yml"},
		{Name: "deploy", OriginFile: ".github/workflows/release.yml", Permissions: "write-all"},
		// clean.yml: no job declares permissions, but build-only has no
		// reusable call while lint-only calls one: both must have nil
		// Permissions AND no ReusableWorkflowUses to be eligible.
		{Name: "build-only", OriginFile: ".github/workflows/clean.yml"},
		// reusable.yml: the only job has nil Permissions of its own but
		// calls a reusable workflow, so the run's first job (which
		// might be the CALLED job, running under its own effective
		// permissions, never this workflow's default) must not be read
		// as the repository default either.
		{Name: "lint-only", OriginFile: ".github/workflows/reusable.yml", ReusableWorkflowUses: "./.github/workflows/_lint.yml"},
	}}
	if eligibleDefaultTokenWorkflow(p, ".github/workflows/ci.yml") {
		t.Error("ci.yml's lint job declares permissions: want ineligible (build alone having none is not enough)")
	}
	if eligibleDefaultTokenWorkflow(p, ".github/workflows/release.yml") {
		t.Error("release.yml's only job declares write-all: want ineligible")
	}
	if !eligibleDefaultTokenWorkflow(p, ".github/workflows/clean.yml") {
		t.Error("clean.yml's only job has no permissions and calls nothing: want eligible")
	}
	if eligibleDefaultTokenWorkflow(p, ".github/workflows/reusable.yml") {
		t.Error("reusable.yml's only job calls a reusable workflow: want ineligible")
	}
	if eligibleDefaultTokenWorkflow(p, ".github/workflows/absent.yml") {
		t.Error("a workflow with no job at all is never eligible")
	}
}

// TestEnrichGitHubDefaultTokenThreadsDefaultBranchAndDeclaresContentsWrite
// checks the two new arguments reach the lookup as computed, not
// hardcoded: pipeline.DefaultBranch forwarded verbatim, and
// declaresContentsWrite true only when some job of the pipeline
// already declares a contents write or write-all.
func TestEnrichGitHubDefaultTokenThreadsDefaultBranchAndDeclaresContentsWrite(t *testing.T) {
	orig := fetchGitHubDefaultTokenWrite
	t.Cleanup(func() { fetchGitHubDefaultTokenWrite = orig })
	var gotBranch string
	var gotDeclares bool
	fetchGitHubDefaultTokenWrite = func(host, owner, repo, defaultBranch string, declaresContentsWrite bool, eligible func(string) bool) (string, string) {
		gotBranch = defaultBranch
		gotDeclares = declaresContentsWrite
		return "unknown", "unknown"
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main", Jobs: []ir.Job{
		{Name: "build"},
		{Name: "release", Permissions: map[string]any{"contents": "write"}},
	}}
	enrichGitHubDefaultToken(p, "", "acme", "widget")
	if gotBranch != "main" {
		t.Errorf("defaultBranch = %q, want main", gotBranch)
	}
	if !gotDeclares {
		t.Error("declaresContentsWrite = false, want true (release declares contents: write)")
	}
}

// TestDeclaresDefaultTokenContentsWrite pins the three ways a job can
// declare a contents write: the write-all shortcut, an explicit
// contents: write entry in a map[string]any permissions block (the
// collector's own shape), and the same in a map[string]string one.
// read-only and no-permissions jobs never trip it.
func TestDeclaresDefaultTokenContentsWrite(t *testing.T) {
	cases := []struct {
		name string
		jobs []ir.Job
		want bool
	}{
		{"write-all", []ir.Job{{Permissions: "write-all"}}, true},
		{"contents write, map[string]any", []ir.Job{{Permissions: map[string]any{"contents": "write"}}}, true},
		{"contents write, map[string]string", []ir.Job{{Permissions: map[string]string{"contents": "write"}}}, true},
		{"contents read", []ir.Job{{Permissions: map[string]any{"contents": "read"}}}, false},
		{"no permissions", []ir.Job{{}}, false},
		{"read-all", []ir.Job{{Permissions: "read-all"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &ir.NormalizedPipeline{Jobs: c.jobs}
			if got := declaresDefaultTokenContentsWrite(p); got != c.want {
				t.Errorf("declaresDefaultTokenContentsWrite = %v, want %v", got, c.want)
			}
		})
	}
}

// TestHasEligibleDefaultTokenJob checks the overall gate: true as soon
// as one job anywhere has no declared permissions, false when every
// job declares its own.
func TestHasEligibleDefaultTokenJob(t *testing.T) {
	none := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "a", Permissions: "write-all"},
		{Name: "b", Permissions: map[string]any{"contents": "read"}},
	}}
	if hasEligibleDefaultTokenJob(none) {
		t.Error("every job declares its own permissions: want false")
	}
	some := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "a", Permissions: "write-all"},
		{Name: "b"},
	}}
	if !hasEligibleDefaultTokenJob(some) {
		t.Error("b declares no permissions: want true")
	}
}
