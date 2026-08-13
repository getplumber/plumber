package opa

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/finding/identity"
)

// A consumer outside this module reads findings from Plumber's serialized
// output, not from the Go type, and must arrive at the same identity. That only
// holds if every input the recipe reads is flattened into the JSON object, so
// the round trip is pinned here rather than assumed.
func TestFingerprint_SurvivesTheJSONRoundTrip(t *testing.T) {
	findings := []Finding{{
		Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "build",
		Message: "prose", Line: 12, URL: "https://example.com/ci.yml#L12",
		Data: map[string]any{"uses": "owner/act@v1", "step": "Check out", "advisories": "GHSA-1"},
	}, {
		Code: "ISSUE-803", File: "ci.yml", Job: "build", Message: "no structured subject here",
	}, {
		Code: "ISSUE-405", File: ".gitlab-ci.yml", Job: "templates/go/go",
		Message: "required template is missing",
		Data:    map[string]any{"templatePath": "templates/go/go"},
	}}
	StampFingerprints(findings, "")
	for _, f := range findings {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal %s: %v", f.Code, err)
		}
		var serialized map[string]any
		if err := json.Unmarshal(b, &serialized); err != nil {
			t.Fatalf("unmarshal %s: %v", f.Code, err)
		}
		if got := identity.Fingerprint(identity.FromMap(serialized)); got != f.Fingerprint {
			t.Errorf("%s: fingerprint from serialized finding = %q, stamped = %q", f.Code, got, f.Fingerprint)
		}
	}
}

// The engine must not keep a second copy of the selection: it computes the
// fingerprint through the public recipe, so a key added there is honoured here
// without an edit. A finding using a subject key the engine never knew about is
// the check that the two are one implementation and not two lists.
func TestFingerprint_ComesFromTheSharedRecipe(t *testing.T) {
	f := Finding{
		Code: "ISSUE-405", File: ".gitlab-ci.yml", Job: "templates/go/go",
		Message: `required template "templates/go/go" is missing from the pipeline (group 0)`,
		Data:    map[string]any{"templatePath": "templates/go/go"},
	}
	want := identity.Fingerprint(identity.Finding{
		Code: f.Code, File: f.File, Job: f.Job, Message: f.Message, Data: f.Data,
	})
	if got := computeFingerprint(f); got != want {
		t.Errorf("computeFingerprint = %q, identity.Fingerprint = %q; the engine is using its own selection", got, want)
	}
}

// The fingerprint must survive line drift: the same finding whose line moved
// (because unrelated code above it was edited) keeps the same identifier, so a
// consumer can follow it across runs.
func TestFingerprint_StableAndLineIndependent(t *testing.T) {
	base := Finding{Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "build", Message: "action X unpinned", Line: 12}
	moved := base
	moved.Line = 40
	if computeFingerprint(base) != computeFingerprint(moved) {
		t.Errorf("fingerprint changed when only the line moved; want line-independent")
	}
	if computeFingerprint(base) == "" {
		t.Fatalf("fingerprint empty for a coded finding")
	}
}

// v4 change from v3: ISSUE-701 declares {file, job, uses, step}, not message
// (message is reserved for the 29-code exception list; see
// finding/identity/declarations.go), so two findings that share code/file/job
// and differ only in message (no uses, no step -- an unrealistic shape in
// production, where the collector always supplies uses) now COLLIDE. In v3
// this test's name held because message was the only fallback available;
// under v4 that job splits into two other tests that remain accurate:
// structured-subject discrimination (TestFingerprint_SubjectDiscriminatesWithoutMessage)
// and message-keyed-code discrimination
// (TestFingerprint_FallsBackToMessageWithoutSubject). This test now pins the
// narrowing itself, so an edit that quietly restores message sensitivity to a
// uses-declared code is caught here instead of silently re-keying every
// ISSUE-701 in the wild.
func TestFingerprint_MessageAloneNoLongerDiscriminatesAUsesDeclaredCode(t *testing.T) {
	a := Finding{Code: "ISSUE-701", File: "ci.yml", Job: "build", Message: "action A unpinned"}
	b := Finding{Code: "ISSUE-701", File: "ci.yml", Job: "build", Message: "action B unpinned"}
	if computeFingerprint(a) != computeFingerprint(b) {
		t.Errorf("fingerprints differ on message alone; ISSUE-701 does not declare message in v4")
	}
}

// The real collision found on grafana/grafana: the same action referenced twice
// in one job produces an identical code/file/job/message, and only the step name
// tells the two apart (the line does too, but it drifts, so it is excluded).
func TestFingerprint_StepNameBreaksSameActionCollision(t *testing.T) {
	base := Finding{
		Code: "ISSUE-713", File: ".github/workflows/check-frontend-test-coverage.yml", Job: "coverage",
		Message: `job "coverage" references action "marocchino/sticky-pull-request-comment@7737449" from an unauthorized source`,
	}
	a, b := base, base
	a.Data = map[string]any{"step": "Delete old coverage comment if not affected"}
	b.Data = map[string]any{"step": "Post PR comment"}
	if computeFingerprint(a) == computeFingerprint(b) {
		t.Errorf("same fingerprint for two steps of the same action; step name must discriminate")
	}
	// The step name, not the line, is what separates them: moving either line
	// must not change its fingerprint.
	moved := a
	moved.Line = 999
	if computeFingerprint(a) != computeFingerprint(moved) {
		t.Errorf("fingerprint changed on line drift; want line-independent")
	}
}

// Findings with no step name keep the identifier they had before step names
// existed, so adding the discriminator does not churn unrelated fingerprints.
func TestFingerprint_NoStepIsUnchanged(t *testing.T) {
	f := Finding{Code: "ISSUE-505", Job: "main", Message: "Branch 'main' has non-compliant protection settings"}
	withEmpty := f
	withEmpty.Data = map[string]any{"step": ""}
	if computeFingerprint(f) != computeFingerprint(withEmpty) {
		t.Errorf("empty step must not alter the fingerprint")
	}
}

// The point of preferring a structured subject: rewording a rule's prose must
// not change the identifier of every finding that rule ever emitted.
func TestFingerprint_ImmuneToMessageRewordingWhenSubjectPresent(t *testing.T) {
	f := Finding{
		Code: "ISSUE-701", File: "ci.yml", Job: "build",
		Message: `job "build" references action "owner/act@v1" with a mutable ref`,
		Data:    map[string]any{"uses": "owner/act@v1"},
	}
	reworded := f
	reworded.Message = "Pin owner/act@v1 by commit SHA (message reworded in a later release)"
	if computeFingerprint(f) != computeFingerprint(reworded) {
		t.Errorf("fingerprint changed when only the message was reworded; the structured subject should carry identity")
	}
}

// Two different actions in the same job are told apart by the subject alone,
// with no help from the message. This is the grafana shape (two distinct
// unpinned actions in one job).
func TestFingerprint_SubjectDiscriminatesWithoutMessage(t *testing.T) {
	base := Finding{Code: "ISSUE-701", File: "ci.yml", Job: "release", Message: "same prose for both"}
	a, b := base, base
	a.Data = map[string]any{"uses": "grafana/shared-workflows/actions/get-vault-secrets@main"}
	b.Data = map[string]any{"uses": "grafana/grafana-github-actions-go/community-release@main"}
	if computeFingerprint(a) == computeFingerprint(b) {
		t.Errorf("two different actions collided; subject must discriminate")
	}
}

// The former message-keyed controls now identify on canonical coordinates, so
// rewording their prose no longer re-keys them. Message fallback survives only
// as the backstop for an undeclared code (covered by
// identity.TestOf_V4_UndeclaredCodeBackstop).
func TestFingerprint_FormerMessageKeyedCodeIsStableAcrossRewording(t *testing.T) {
	a := Finding{Code: "ISSUE-801", File: "ci.yml", Job: "build", Message: "first problem"}
	b := Finding{Code: "ISSUE-801", File: "ci.yml", Job: "build", Message: "second problem"}
	if computeFingerprint(a) != computeFingerprint(b) {
		t.Errorf("rewording re-keyed a now-structured code; message must be inert")
	}
}

// A volatile payload key must not participate: a new CVE landing in advisories
// or an upstream release moving latestVersion cannot make an existing finding
// look like a new one.
func TestFingerprint_IgnoresVolatilePayload(t *testing.T) {
	f := Finding{
		Code: "ISSUE-703", File: "ci.yml", Job: "build", Message: "known CVE",
		Data: map[string]any{"uses": "owner/act@v1", "advisories": "GHSA-1", "latestVersion": "2.2.0"},
	}
	later := f
	later.Data = map[string]any{"uses": "owner/act@v1", "advisories": "GHSA-1,GHSA-2", "latestVersion": "2.3.0"}
	if computeFingerprint(f) != computeFingerprint(later) {
		t.Errorf("fingerprint moved when only volatile payload changed")
	}
}

func TestFingerprint_CodelessIsEmpty(t *testing.T) {
	if computeFingerprint(Finding{Message: "x"}) != "" {
		t.Errorf("codeless finding got a fingerprint; want empty")
	}
}

// A relative path whose first segment merely STARTS WITH ".." (e.g.
// "..foo/bar.yml") is a legitimate in-repo path, not an escape above root. A
// bare strings.HasPrefix(rel, "..") check misclassifies it as an escape and
// leaves File (wrongly) absolute; the fix checks the ".." path SEGMENT
// specifically.
func TestRepoRelative_DoesNotMisclassifyDotDotPrefixedSegment(t *testing.T) {
	root := filepath.FromSlash("/repo")
	file := filepath.Join(root, "..foo", "bar.yml")

	got := repoRelative(file, root)
	if got != "..foo/bar.yml" {
		t.Errorf("repoRelative(%q, %q) = %q, want %q (a legitimate in-repo path, not an escape)", file, root, got, "..foo/bar.yml")
	}
}

// A genuine escape above root (the ".." segment itself, or a path continuing
// through it) must still be rejected and left absolute.
func TestRepoRelative_RejectsGenuineEscape(t *testing.T) {
	root := filepath.FromSlash("/repo/sub")
	file := filepath.FromSlash("/repo/outside.yml")

	got := repoRelative(file, root)
	if got != filepath.ToSlash(file) {
		t.Errorf("repoRelative(%q, %q) = %q, want the original absolute path unchanged (genuine escape)", file, root, got)
	}
}

func TestStampFingerprints_SetsFieldInPlace(t *testing.T) {
	fs := []Finding{
		{Code: "ISSUE-701", File: "ci.yml", Job: "build", Message: "x"},
		{Code: "", Message: "codeless"},
	}
	StampFingerprints(fs, "")
	if fs[0].Fingerprint == "" {
		t.Errorf("StampFingerprints did not set a fingerprint on a coded finding")
	}
	if fs[1].Fingerprint != "" {
		t.Errorf("codeless finding got a fingerprint; want empty")
	}
	if fs[0].Fingerprint != computeFingerprint(fs[0]) {
		t.Errorf("stamped fingerprint != computeFingerprint")
	}
}

// The GitHub collector records absolute paths, and the path is one of the four
// hashed identity segments. Left raw, the same finding fingerprints differently
// on a laptop and on a runner, which makes it unusable as a database key.
func TestStampFingerprints_NormalizesFileToRepoRelative(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	findings := []Finding{{
		Code: "ISSUE-701",
		File: filepath.Join(wd, ".github", "workflows", "ci.yml"),
		Job:  "ci/build",
		Data: map[string]any{"uses": "actions/checkout@v4"},
	}}
	StampFingerprints(findings, wd)

	if got := findings[0].File; got != ".github/workflows/ci.yml" {
		t.Errorf("File = %q, want the repo-relative path", got)
	}
}

// Two runs of the same finding from different absolute roots must agree.
func TestStampFingerprints_FingerprintIsRootIndependent(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	mk := func(file, root string) string {
		f := []Finding{{
			Code: "ISSUE-701", File: file, Job: "ci/build",
			Data: map[string]any{"uses": "actions/checkout@v4"},
		}}
		StampFingerprints(f, root)
		return f[0].Fingerprint
	}
	inside := mk(filepath.Join(wd, ".github", "workflows", "ci.yml"), wd)
	relative := mk(".github/workflows/ci.yml", wd)
	if inside != relative {
		t.Errorf("fingerprint depends on the absolute root: %q vs %q", inside, relative)
	}
}

// The regression this guards: the previous implementation relativized every
// File against os.Getwd() with no way to override it, but the GitHub
// collector's absolute paths are rooted at conf.GitRepoRoot, not the
// process's working directory. Running Plumber from a subdirectory of the
// repo made filepath.Rel return a "../…" path, the escape guard rejected it,
// and File (and therefore the fingerprint) stayed absolute and
// machine-dependent — the exact defect RecipeVersion 3 claims to have fixed.
// StampFingerprints now takes the repo root explicitly, so the SAME root
// (not the caller's cwd) decides the relative path and the fingerprint no
// longer depends on which directory Plumber was invoked from.
func TestStampFingerprints_FingerprintStableFromSubdirectoryOfRepoRoot(t *testing.T) {
	repoRoot := t.TempDir()
	subDir := filepath.Join(repoRoot, "sub", "dir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(repoRoot, ".github", "workflows", "ci.yml")

	mk := func() string {
		f := []Finding{{
			Code: "ISSUE-701", File: file, Job: "ci/build",
			Data: map[string]any{"uses": "actions/checkout@v4"},
		}}
		StampFingerprints(f, repoRoot)
		if f[0].File != ".github/workflows/ci.yml" {
			t.Errorf("File = %q, want the repo-relative path regardless of cwd", f[0].File)
		}
		return f[0].Fingerprint
	}

	t.Chdir(repoRoot)
	atRoot := mk()

	t.Chdir(subDir)
	fromSubdir := mk()

	if atRoot != fromSubdir {
		t.Errorf("fingerprint depends on the working directory: %q (at repo root) vs %q (from a subdirectory)", atRoot, fromSubdir)
	}
}
