package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

// policyDash is the dash a policy message sets its consequence apart
// with, written as an escape so this file never carries it.
const policyDash = " \u2014 "

// individualFixture is a run's individual findings: one code with three
// findings sharing a consequence, one with two findings whose
// consequences differ, a branch finding without a job, and a message
// without a consequence.
func individualFixture() []findingGroup {
	checkout := func(job, file, line string) detailedFinding {
		return detailedFinding{
			Code:               control.CodeArtipacked,
			Message:            `job "` + job + `" runs "actions/checkout@v6" without ` + "`persist-credentials: false`" + policyDash + `GITHUB_TOKEN lingers in .git/config`,
			Job:                job,
			File:               ".github/workflows/" + file,
			Location:           "https://example.com/o/r/blob/main/.github/workflows/" + file + "#L" + line,
			ContextualSeverity: "low",
		}
	}
	return []findingGroup{
		{
			Title: "Branch must be protected",
			Stats: []statLine{{Label: "Total Branches", Value: "1"}},
			Findings: []detailedFinding{{
				Code: control.CodeBranchUnprotected, Message: "branch `main` is not protected" + policyDash + "anyone with write access can push to it",
				ContextualSeverity: "high",
			}},
		},
		{
			Title: "Checkout must not persist credentials",
			Stats: []statLine{{Label: "Workflows Scanned", Value: "3"}},
			Findings: []detailedFinding{
				checkout("ci/build", "ci.yml", "7"),
				checkout("ci/lint", "ci.yml", "21"),
				checkout("release/publish", "release.yml", "12"),
			},
		},
		{
			Title: "Actions must not reference archived repositories",
			Findings: []detailedFinding{{
				Code: control.CodeActionArchivedRepo, Message: `job "build/notes" references "actions/create-release@v1" whose upstream repository is archived`,
				Job: "build/notes", File: ".github/workflows/build.yml", Location: ".github/workflows/build.yml:27", ContextualSeverity: "high",
			}},
		},
		{
			Title: "Workflows must declare permissions",
			Findings: []detailedFinding{
				{
					Code: control.CodeUndocumentedPermissions, Message: `job "ci/build" has no permissions block` + policyDash + `the token gets the repository default`,
					Job: "ci/build", File: ".github/workflows/ci.yml", Location: "https://example.com/o/r/blob/main/.github/workflows/ci.yml#L1", ContextualSeverity: "medium",
				},
				{
					Code: control.CodeUndocumentedPermissions, Message: `job "deploy/push" has no permissions block` + policyDash + `the token can write to the repository`,
					Job: "deploy/push", File: ".github/workflows/deploy.yml", Location: "https://example.com/o/r/blob/main/.github/workflows/deploy.yml#L1", ContextualSeverity: "medium",
				},
			},
		},
	}
}

func renderIndividualFixture(t *testing.T, caps termCaps) string {
	t.Helper()
	var b strings.Builder
	renderIndividualFindings(&b, individualFixture(), 7, caps)
	return b.String()
}

var plainCaps = termCaps{Color: colorOff, Width: 100}

// One block per code, the findings sharing a consequence: one branch per
// finding saying where it runs, its location under it, the consequence
// once, the fix and the documentation.
func TestIndividualFindingsSharedConsequenceIsOneSoLine(t *testing.T) {
	useReportColor(colorOff)
	t.Cleanup(func() { useReportColor(colorBasic) })
	out := renderIndividualFixture(t, plainCaps)
	want := ` LOW   ISSUE-307  Checkout persists credentials in .git/config (latent) (3 findings)
       │
       ├──▶ job ` + "`build`" + ` from workflow ` + "`ci.yml`" + `: runs "actions/checkout@v6" without
       │    ` + "`persist-credentials: false`" + `
       │    ↳ at https://example.com/o/r/blob/main/.github/workflows/ci.yml#L7
       ├──▶ job ` + "`lint`" + ` from workflow ` + "`ci.yml`" + `: runs "actions/checkout@v6" without
       │    ` + "`persist-credentials: false`" + `
       │    ↳ at https://example.com/o/r/blob/main/.github/workflows/ci.yml#L21
       └──▶ job ` + "`publish`" + ` from workflow ` + "`release.yml`" + `: runs "actions/checkout@v6" without
            ` + "`persist-credentials: false`" + `
            ↳ at https://example.com/o/r/blob/main/.github/workflows/release.yml#L12

       So     GITHUB_TOKEN lingers in .git/config
       Fix    set persist-credentials: false on the checkout
       ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-307

  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
`
	assertContains(t, out, want)
	for _, unwanted := range []string{strings.TrimSpace(policyDash), "Issues Found", "Workflows Scanned", "more of these", "runs in job", "[low]", "✗ Checkout"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the individual findings printed %q:\n%s", unwanted, out)
		}
	}
}

// Findings of one code whose consequences differ each say theirs under
// their branch, and the block has no So line of its own.
func TestIndividualFindingsDifferentConsequencesGoUnderEachBranch(t *testing.T) {
	useReportColor(colorOff)
	t.Cleanup(func() { useReportColor(colorBasic) })
	out := renderIndividualFixture(t, plainCaps)
	want := ` MED   ISSUE-801  Workflow has no explicit ` + "`permissions:`" + ` block (2 findings)
       │
       ├──▶ job ` + "`build`" + ` from workflow ` + "`ci.yml`" + `: has no permissions block
       │    so the token gets the repository default
       │    ↳ at https://example.com/o/r/blob/main/.github/workflows/ci.yml#L1
       └──▶ job ` + "`push`" + ` from workflow ` + "`deploy.yml`" + `: has no permissions block
            so the token can write to the repository
            ↳ at https://example.com/o/r/blob/main/.github/workflows/deploy.yml#L1

       Fix    declare a permissions block with only what the job needs
       ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-801
`
	assertContains(t, out, want)
}

// A finding with no job prints its message as the branch; a message
// without a consequence is the whole branch and the block has no So; a
// single finding has no count.
func TestIndividualFindingsWithoutJobOrConsequence(t *testing.T) {
	useReportColor(colorOff)
	t.Cleanup(func() { useReportColor(colorBasic) })
	out := renderIndividualFixture(t, plainCaps)
	assertContains(t, out, ` HIGH  ISSUE-501  Branch protection missing
       │
       └──▶ branch `+"`main`"+` is not protected

       So     anyone with write access can push to it
       Fix    protect the branch
`)
	assertContains(t, out, ` HIGH  ISSUE-702  Action is hosted in an archived repository
       │
       └──▶ job `+"`notes`"+` from workflow `+"`build.yml`"+`: references "actions/create-release@v1" whose
            upstream repository is archived
            ↳ at .github/workflows/build.yml:27

       Fix    replace the archived action
       ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-702
`)
}

// Blocks print least severe first, the worst last, by code within a
// severity, a light rule between two blocks, under the section heading.
func TestIndividualFindingsOrderAndSeparator(t *testing.T) {
	useReportColor(colorOff)
	t.Cleanup(func() { useReportColor(colorBasic) })
	out := renderIndividualFixture(t, plainCaps)
	if !strings.HasPrefix(out, "────────────────────\n✗ Individual findings (7)\n────────────────────\n\n LOW ") {
		t.Errorf("heading:\n%s", out)
	}
	order := []string{" LOW   ISSUE-307", " MED   ISSUE-801", " HIGH  ISSUE-501", " HIGH  ISSUE-702"}
	at := -1
	for _, h := range order {
		i := strings.Index(out, h)
		if i <= at {
			t.Fatalf("want the blocks in the order %v:\n%s", order, out)
		}
		at = i
	}
	if n := strings.Count(out, "┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄"); n != len(order)-1 {
		t.Errorf("want %d rules between the blocks, got %d:\n%s", len(order)-1, n, out)
	}
	if !strings.HasSuffix(out, "↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-702\n\n") {
		t.Errorf("the worst block closes the section:\n%s", out)
	}
}

// With colour on, the badge is the coloured one, So and Fix are bold in
// their column and the documentation line is dim.
func TestIndividualFindingsColourLabels(t *testing.T) {
	useReportColor(colorBasic)
	out := renderIndividualFixture(t, termCaps{Color: colorBasic, Width: 100})
	assertContains(t, out, blockIndent+colorBold+"So"+colorReset+"     GITHUB_TOKEN")
	assertContains(t, out, blockIndent+colorBold+"Fix"+colorReset+"    set persist-credentials")
	assertContains(t, out, blockIndent+colorDim+"↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-307"+colorReset)
	assertContains(t, out, pathTierTag(control.TierLow)+" ISSUE-307  ")
}

// The fix of a code the fix table does not name is the first sentence of
// its remediation, as something to do; a period inside a word (a file
// name) does not end the sentence.
func TestIndividualFindingFixFallsBackToTheRemediation(t *testing.T) {
	if _, ok := control.FindingFixFor("ISSUE-999"); ok {
		t.Fatal("an unknown code has no fix")
	}
	got := remediationFix("Use images from an authorized registry configured in .plumber.yaml under x. Or add it.")
	if got != "use images from an authorized registry configured in .plumber.yaml under x" {
		t.Errorf("remediationFix = %q", got)
	}
}

// Every code the examples print as an individual finding has its own fix.
func TestIndividualFindingFixesCoverTheExamples(t *testing.T) {
	for _, code := range []control.ErrorCode{"ISSUE-307", "ISSUE-702", "ISSUE-410", "ISSUE-713", "ISSUE-101", "ISSUE-801", "ISSUE-803", "ISSUE-203", "ISSUE-102", "ISSUE-103"} {
		if _, ok := control.FindingFixFor(code); !ok {
			t.Errorf("%s has no fix of its own", code)
		}
	}
}

// A message opening on its job, quoted or in a code span, reads it as the
// job phrase; one that names its job elsewhere is printed as it is.
func TestFindingBranchReadsTheJobTheMessageOpensOn(t *testing.T) {
	file := ".github/workflows/ci.yml"
	for _, c := range []struct{ message, want string }{
		{"Job `ci/build` sets the debug variable `ACTIONS_STEP_DEBUG` to \"true\".", "job `build` from workflow `ci.yml`: sets the debug variable `ACTIONS_STEP_DEBUG` to \"true\"."},
		{`job "ci/build" runs "actions/checkout@v6"`, "job `build` from workflow `ci.yml`: runs \"actions/checkout@v6\""},
		{"Security job `ci/build` is weakened by `allow_failure: true`.", "Security job `ci/build` is weakened by `allow_failure: true`."},
	} {
		if got, _ := findingBranch(detailedFinding{Message: c.message, Job: "ci/build", File: file}); got != c.want {
			t.Errorf("findingBranch(%q) = %q, want %q", c.message, got, c.want)
		}
	}
}
