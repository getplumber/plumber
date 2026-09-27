package policies_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// scanWorkflow runs one workflow through the real GitHub workflow scanner:
// the rule reads the upload steps' `with.path` inputs and their line numbers,
// which only the production parser carries. Metadata enrichment stays off.
func scanWorkflow(t *testing.T, workflow string) *ir.NormalizedPipeline {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "repro.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	pipeline, _, err := github.ScanGitHubWorkflowsWithProgress("acme/repro", "main", root, "", false, false, nil)
	if err != nil {
		t.Fatalf("scan workflows: %v", err)
	}
	return pipeline
}

func loadPolicies(t *testing.T) *opaengine.Engine {
	t.Helper()
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	return engine
}

// TestArtipacked_SeveralPackingUploadsInOneJob is the #489 policy
// regression: two upload-artifact steps in one job that both pack the
// workspace made _git_packing_upload produce two outputs for one input
// (eval_conflict_error), which took every finding of the run with it. The
// rule must evaluate and report one ISSUE-310 per packing upload.
func TestArtipacked_SeveralPackingUploadsInOneJob(t *testing.T) {
	const workflow = `name: repro
on: push
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
      - uses: actions/upload-artifact@v4
        with:
          name: everything
          path: ${{ github.workspace }}
          include-hidden-files: true
      - uses: actions/upload-artifact@v4
        with:
          name: everything-again
          path: .
          include-hidden-files: true
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate must not fail on several packing uploads in one job: %v", err)
	}
	if got := countCode(findings, "ISSUE-310"); got != 2 {
		t.Fatalf("want one ISSUE-310 per packing upload (2), got %d: %+v", got, findings)
	}
	if got := countCode(findings, "ISSUE-307"); got != 0 {
		t.Fatalf("ISSUE-307 (nothing packs .git) must not fire when uploads pack .git, got %d", got)
	}
}

// TestArtipacked_UploadsUnderTheWorkspaceAreNotALeak is the issue's exact
// workflow: two uploads of paths UNDER the workspace (a report directory
// and a file inside it). Neither packs `.git`, so the run evaluates, reports
// the latent ISSUE-307 for the persisted credential, and no ISSUE-310.
func TestArtipacked_UploadsUnderTheWorkspaceAreNotALeak(t *testing.T) {
	const workflow = `name: repro
on: push
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v5
      - run: mkdir -p reports/clients && echo hi > reports/clients/index.html
      - name: Publish all reports
        uses: actions/upload-artifact@v4
        with:
          name: full report
          path: ${{github.workspace}}/reports
      - name: Publish report client
        uses: actions/upload-artifact@v4
        with:
          name: client
          path: ${{github.workspace}}/reports/clients/index.html
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate must not fail on the issue's workflow: %v", err)
	}
	if got := countCode(findings, "ISSUE-310"); got != 0 {
		t.Fatalf("uploads under the workspace do not pack .git; want no ISSUE-310, got %d: %+v", got, findings)
	}
	if got := countCode(findings, "ISSUE-307"); got != 1 {
		t.Fatalf("the persisted credential is still the latent ISSUE-307, want 1, got %d", got)
	}
}

// TestArtipacked_RiskyPathBoundary walks the boundary of what packs `.git`:
// the workspace root in every spelling, a recursive glob rooted there, and
// the `.git` directory itself are leaks (ISSUE-310); a path under the
// workspace, a plain directory, and Git dot-files or `.github` are not.
func TestArtipacked_RiskyPathBoundary(t *testing.T) {
	cases := []struct {
		path  string
		risky bool
	}{
		{"${{ github.workspace }}", true},
		{"${{github.workspace}}", true},
		{"${{ github.workspace }}/", true},
		{"${{ github.workspace }}/.", true},
		{"${{ github.workspace }}/./", true},
		{"${{ github.workspace }}/**", true},
		{"${{ github.workspace }}/./**", true},
		{".", true},
		{"./", true},
		{"**", true},
		{"./**", true},
		{".git", true},
		{".git/config", true},
		{"${{ github.workspace }}/.git", true},
		{"checkout/.git/config", true},
		{"**/*", true},
		{"*", true},
		{"${{ github.workspace }}/*", true},
		{"${{ github.workspace }}/**/*", true},
		{"*/**", true},
		{".\n!node_modules", true},
		{"dist\n.git", true},
		{".*", true},
		{".\n!vendor/pkg/.git", true},
		{".\n!.git/lfs", true},
		{".\n!.git", false},
		{".\n!.git/", false},
		{".\n!.git/*", false},
		{".\n!**/.git", false},
		{"**\n!${{ github.workspace }}/.git/*", false},
		{"**\n!.git/**", false},
		{"${{ github.workspace }}/**\n!${{ github.workspace }}/.git", false},
		{"${{ github.workspace }}/dist", false},
		{"${{ github.workspace }}/reports/**", false},
		{"dist", false},
		{"dist/**", false},
		{".gitignore", false},
		{".gitattributes", false},
		{".github/workflows", false},
		{"build/.gitkeep", false},
	}
	engine := loadPolicies(t)
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(tc.path, "\n", " "), func(t *testing.T) {
			pathYAML := "'" + tc.path + "'"
			if strings.Contains(tc.path, "\n") {
				pathYAML = "|\n            " + strings.ReplaceAll(tc.path, "\n", "\n            ")
			}
			workflow := "name: b\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n" +
				"      - uses: actions/checkout@v5\n" +
				"      - uses: actions/upload-artifact@v4\n        with:\n          name: a\n          include-hidden-files: true\n          path: " + pathYAML + "\n"
			findings, err := evaluateStrict(engine, context.Background(), scanWorkflow(t, workflow), nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			want := 0
			if tc.risky {
				want = 1
			}
			if got := countCode(findings, "ISSUE-310"); got != want {
				t.Fatalf("path %q: want %d ISSUE-310, got %d", tc.path, want, got)
			}
			if got := countCode(findings, "ISSUE-307"); got != 1-want {
				t.Fatalf("path %q: want %d ISSUE-307, got %d", tc.path, 1-want, got)
			}
		})
	}
}

// TestArtipacked_ExclusionMustCoverTheCheckoutsOwnGit: a checkout placed
// under `path: repo` persists its credential in repo/.git, so an exclusion
// of the root `.git` alone leaves it packed; an exclusion of repo/.git, or a
// recursive one, clears it.
func TestArtipacked_ExclusionMustCoverTheCheckoutsOwnGit(t *testing.T) {
	cases := []struct {
		name      string
		exclusion string
		risky     bool
	}{
		{"root .git only", "!.git", true},
		{"the checkout's own .git", "!repo/.git", false},
		{"the checkout's own .git with a slash", "!repo/.git/", false},
		{"the checkout's .git entries", "!repo/.git/*", false},
		{"the checkout's .git recursively", "!repo/.git/**", false},
		{"any .git recursively", "!**/.git/**", false},
	}
	engine := loadPolicies(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workflow := "name: b\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n" +
				"      - uses: actions/checkout@v5\n        with:\n          path: repo\n" +
				"      - uses: actions/upload-artifact@v4\n        with:\n          name: a\n          include-hidden-files: true\n          path: |\n            .\n            " + tc.exclusion + "\n"
			findings, err := evaluateStrict(engine, context.Background(), scanWorkflow(t, workflow), nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			want := 0
			if tc.risky {
				want = 1
			}
			if got := countCode(findings, "ISSUE-310"); got != want {
				t.Fatalf("%s: want %d ISSUE-310, got %d: %+v", tc.name, want, got, findings)
			}
		})
	}
}

// TestArtipacked_UploadingTheCheckoutDirectoryPacksItsGit: with the
// checkout under `path: repo`, uploading `repo` itself or a glob rooted in
// it packs repo/.git; a directory under it does not.
func TestArtipacked_UploadingTheCheckoutDirectoryPacksItsGit(t *testing.T) {
	cases := []struct {
		path  string
		risky bool
	}{
		{"repo", true},
		{"repo/", true},
		{"repo/**", true},
		{"repo/*", true},
		{"${{ github.workspace }}/repo", true},
		{"./repo/**/*", true},
		{"repo/dist", false},
		{"repo/dist/**", false},
		{"other", false},
	}
	engine := loadPolicies(t)
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			workflow := "name: b\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n" +
				"      - uses: actions/checkout@v5\n        with:\n          path: repo\n" +
				"      - uses: actions/upload-artifact@v4\n        with:\n          name: a\n          include-hidden-files: true\n          path: '" + tc.path + "'\n"
			findings, err := evaluateStrict(engine, context.Background(), scanWorkflow(t, workflow), nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			want := 0
			if tc.risky {
				want = 1
			}
			if got := countCode(findings, "ISSUE-310"); got != want {
				t.Fatalf("path %q: want %d ISSUE-310, got %d: %+v", tc.path, want, got, findings)
			}
		})
	}
}

// TestArtipacked_HiddenFilesGate: upload-artifact v4 excludes hidden files
// unless include-hidden-files is on, so `path: .` on v4 packs `.git` only
// with the input set (boolean or the string form); a v3 ref packs it
// unconditionally.
func TestArtipacked_HiddenFilesGate(t *testing.T) {
	cases := []struct {
		name  string
		step  string
		risky bool
	}{
		{"v4 default", "uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: .", false},
		{"v4 flag off", "uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: .\n          include-hidden-files: false", false},
		{"v4 flag on", "uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: .\n          include-hidden-files: true", true},
		{"v4 flag on as a string", "uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: .\n          include-hidden-files: 'true'", true},
		{"v4 flag on as a capitalized string", "uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: .\n          include-hidden-files: 'True'", true},
		{"v4 flag on as an upper-case string", "uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: .\n          include-hidden-files: \"TRUE\"", true},
		{"v4 flag off as a string", "uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: .\n          include-hidden-files: 'false'", false},
		{"v4.4.3 default", "uses: actions/upload-artifact@v4.4.3\n        with:\n          name: a\n          path: .", false},
		{"v3 default", "uses: actions/upload-artifact@v3\n        with:\n          name: a\n          path: .", true},
		{"v3.1.0 default", "uses: actions/upload-artifact@v3.1.0\n        with:\n          name: a\n          path: .", true},
		{"sha pin default", "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with:\n          name: a\n          path: .", false},
	}
	engine := loadPolicies(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workflow := "name: b\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n" +
				"      - uses: actions/checkout@v5\n" +
				"      - " + tc.step + "\n"
			findings, err := evaluateStrict(engine, context.Background(), scanWorkflow(t, workflow), nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			want := 0
			if tc.risky {
				want = 1
			}
			if got := countCode(findings, "ISSUE-310"); got != want {
				t.Fatalf("%s: want %d ISSUE-310, got %d: %+v", tc.name, want, got, findings)
			}
			if got := countCode(findings, "ISSUE-307"); got != 1-want {
				t.Fatalf("%s: want %d ISSUE-307, got %d", tc.name, 1-want, got)
			}
		})
	}
}

// TestArtipacked_TwoCheckoutsInOneJobAreReportedSeparately: a job that
// checks out twice (its own repository at the root and another under
// `path: other`) and packs both gets one ISSUE-310 per checkout, told apart
// by the checkout's own line, never collapsed into one finding.
func TestArtipacked_TwoCheckoutsInOneJobAreReportedSeparately(t *testing.T) {
	const workflow = `name: b
on: push
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
      - uses: actions/checkout@v5
        with:
          repository: acme/other
          path: other
      - uses: actions/upload-artifact@v4
        with:
          name: root
          path: .
          include-hidden-files: true
      - uses: actions/upload-artifact@v4
        with:
          name: other
          path: other
          include-hidden-files: true
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	lines := map[int]int{}
	for _, f := range findings {
		if f.Code == "ISSUE-310" {
			lines[f.Line]++
		}
	}
	if len(lines) != 2 {
		t.Fatalf("want ISSUE-310 on two distinct checkout lines, got %v in %+v", lines, findings)
	}
	// The root checkout is packed by both uploads (`.` includes other/), the
	// second by the `other` upload only: three findings over two lines.
	if got := countCode(findings, "ISSUE-310"); got != 3 {
		t.Fatalf("want 3 ISSUE-310 (root checkout packed twice, the other once), got %d: %+v", got, findings)
	}
}

// TestArtipacked_CheckoutPathDotIsTheRoot: `path: .` and `path: ./` on the
// checkout name the workspace root, so a root `.git` exclusion clears the
// upload exactly as with no path at all.
func TestArtipacked_CheckoutPathDotIsTheRoot(t *testing.T) {
	for _, checkoutPath := range []string{".", "./", "${{ github.workspace }}"} {
		t.Run(checkoutPath, func(t *testing.T) {
			workflow := "name: b\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n" +
				"      - uses: actions/checkout@v5\n        with:\n          path: '" + checkoutPath + "'\n" +
				"      - uses: actions/upload-artifact@v4\n        with:\n          name: a\n          include-hidden-files: true\n          path: |\n            .\n            !.git\n"
			findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got := countCode(findings, "ISSUE-310"); got != 0 {
				t.Fatalf("checkout path %q is the root; !.git must clear the upload, got %d ISSUE-310: %+v", checkoutPath, got, findings)
			}
		})
	}
}

// TestArtipacked_PersistCredentialsInputForms: actions/checkout persists the
// credential only when the input upper-cases to TRUE, so every other quoted
// spelling is a disabled persistence and raises nothing; the spellings of
// true keep the latent ISSUE-307.
func TestArtipacked_PersistCredentialsInputForms(t *testing.T) {
	cases := []struct {
		value     string
		persisted bool
	}{
		{"false", false},
		{"'false'", false},
		{"'False'", false},
		{"\"FALSE\"", false},
		{"'no'", false},
		{"${{ inputs.keep-creds }}", true},
		{"true", true},
		{"'true'", true},
		{"'True'", true},
		{"\"TRUE\"", true},
	}
	engine := loadPolicies(t)
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			workflow := "name: b\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n" +
				"      - uses: actions/checkout@v5\n        with:\n          persist-credentials: " + tc.value + "\n"
			findings, err := evaluateStrict(engine, context.Background(), scanWorkflow(t, workflow), nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			want := 0
			if tc.persisted {
				want = 1
			}
			if got := countCode(findings, "ISSUE-307"); got != want {
				t.Fatalf("persist-credentials: %s: want %d ISSUE-307, got %d: %+v", tc.value, want, got, findings)
			}
		})
	}
}

// TestArtipacked_UploadingAnAncestorOfANestedCheckoutPacksItsGit: a checkout
// under `path: a/b` is packed by an upload of `a` or a glob rooted in `a`; a
// sibling directory under `a` is not.
func TestArtipacked_UploadingAnAncestorOfANestedCheckoutPacksItsGit(t *testing.T) {
	cases := []struct {
		path  string
		risky bool
	}{
		{"a", true},
		{"a/", true},
		{"a/**", true},
		{"a/*", true},
		{"a/**/*", true},
		{"a/b", true},
		{"a/c", false},
		{"a/c/**", false},
		{"ab", false},
	}
	engine := loadPolicies(t)
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			workflow := "name: b\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n" +
				"      - uses: actions/checkout@v5\n        with:\n          path: a/b\n" +
				"      - uses: actions/upload-artifact@v4\n        with:\n          name: x\n          include-hidden-files: true\n          path: '" + tc.path + "'\n"
			findings, err := evaluateStrict(engine, context.Background(), scanWorkflow(t, workflow), nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			want := 0
			if tc.risky {
				want = 1
			}
			if got := countCode(findings, "ISSUE-310"); got != want {
				t.Fatalf("path %q: want %d ISSUE-310, got %d: %+v", tc.path, want, got, findings)
			}
		})
	}
}
