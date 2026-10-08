package cmd

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/runcache"
)

// withCacheDir points the run cache at a fresh directory for one test and
// returns the cache root.
func withCacheDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := userCacheDir
	userCacheDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { userCacheDir = old })
	return runcache.Root(dir)
}

// explainFixturePaths is eight paths in no particular order: worst first,
// path 7 is p1 (low, the smaller id of the two low ones).
func explainFixturePaths() []control.AttackPath {
	tiers := []control.PathTier{control.TierLow, control.TierCritical, control.TierHigh, control.TierMedium, control.TierHigh, control.TierHigh, control.TierLow, control.TierCritical}
	var paths []control.AttackPath
	for i, tier := range tiers {
		paths = append(paths, control.AttackPath{ID: "p" + string(rune('1'+i)), Tier: tier, BaseTier: tier})
	}
	return paths
}

// explainFixtureBlock is the block of a fixture path: p1 is the push to
// an unprotected branch, the others name their id.
func explainFixtureBlock(p control.AttackPath) control.PathBlock {
	if p.ID == "p1" {
		return control.PathBlock{
			Tier: p.Tier, Entry: "main (branch anyone with write access can push to, not protected)", EntrySubject: "main",
			Branches: []control.PathBlockBranch{{Job: "job `build`", Reach: "a token with write access to pull requests"}},
			So:       "as anyone with write access to `main`, an attacker can execute code to write to pull requests", Fix: "protect the default branch",
			Findings: []control.PathBlockFinding{
				{Code: "ISSUE-501", Title: "Branch protection missing"},
				{Code: "ISSUE-203", Title: "Pipeline enables CI debug trace", Location: ".github/workflows/ci.yml:18", Count: 2},
				{Code: "ISSUE-501", Title: "Branch protection missing", Location: "settings"},
			},
		}
	}
	return control.PathBlock{
		Tier: p.Tier, Entry: "entry of " + p.ID,
		Branches: []control.PathBlockBranch{{Job: "job-" + p.ID, Reach: "code execution without secrets"}},
		So:       "the runner can be abused", Fix: "fix " + p.ID,
		Findings: []control.PathBlockFinding{{Code: "ISSUE-701", Title: "Third-party action reference is not pinned by commit SHA", Location: "ci.yml:3"}},
	}
}

// explainFixtureReport is a JSON report carrying the fixture paths and
// their blocks, the way buildAnalysisJSONReport writes them.
func explainFixtureReport(t *testing.T, project string) []byte {
	t.Helper()
	paths := explainFixturePaths()
	var blocks []jsonPathBlock
	for _, p := range paths {
		blocks = append(blocks, jsonPathBlockOf(p.ID, explainFixtureBlock(p)))
	}
	raw, err := json.Marshal(map[string]any{
		"projectPath":  project,
		"plumberScore": map[string]any{"paths": paths},
		"pathBlocks":   blocks,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// wantExplainBlock is what `explain -a n` prints for the fixture path p.
func wantExplainBlock(n int, p control.AttackPath) string {
	var out bytes.Buffer
	renderPathBlock(&out, n, explainFixtureBlock(p), termCaps{Color: colorOff}, explainBlock)
	return out.String()
}

// `explain -a 7` prints the seventh path of the worst-first order every
// report numbers by: its graph, then its findings as the report used to
// list them, the documentation line of a code right under its first
// finding, and no details line.
func TestExplainAttackPrintsThePathFromTheLastRun(t *testing.T) {
	root := withCacheDir(t)
	if err := runcache.Write(root, "github/o/r.json", explainFixtureReport(t, "o/r")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runExplainAttack(&out, "7", attackSource{}, termCaps{Color: colorOff}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if want := wantExplainBlock(7, explainFixturePaths()[0]); got != want {
		t.Errorf("explain -a 7:\n%s\nwant:\n%s", got, want)
	}
	for _, want := range []string{
		" LOW   Attack path 7\n       Entry  main (branch anyone with write access can push to, not protected)\n",
		"       Fix    protect the default branch\n       Findings\n" +
			"         ISSUE-501 Branch protection missing\n" +
			"                   ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-501\n" +
			"         ISSUE-203 Pipeline enables CI debug trace     2 findings, first .github/workflows/ci.yml:18\n" +
			"                   ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-203\n" +
			"         ISSUE-501 Branch protection missing           settings\n\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("explain -a 7 lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "details:") || strings.Count(got, "ISSUE-501\n") != 1 {
		t.Errorf("explain -a 7 prints a details line or a docs line twice:\n%s", got)
	}
}

// `all` prints every path, path 1 first, a lighter rule between two.
func TestExplainAttackAll(t *testing.T) {
	root := withCacheDir(t)
	if err := runcache.Write(root, "github/o/r.json", explainFixtureReport(t, "o/r")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runExplainAttack(&out, "all", attackSource{}, termCaps{Color: colorOff}); err != nil {
		t.Fatal(err)
	}
	ordered := control.PathsWorstFirst(explainFixturePaths())
	var want strings.Builder
	for i, p := range ordered {
		if i > 0 {
			fprintPathRule(&want, termCaps{Color: colorOff})
		}
		want.WriteString(wantExplainBlock(i+1, p))
	}
	if out.String() != want.String() {
		t.Errorf("explain -a all:\n%s\nwant:\n%s", out.String(), want.String())
	}
}

// --run reads a report written by --output, the cache left alone.
func TestExplainAttackReadsAReportFile(t *testing.T) {
	withCacheDir(t)
	file := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(file, explainFixtureReport(t, "o/r"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runExplainAttack(&out, "7", attackSource{run: file}, termCaps{Color: colorOff}); err != nil {
		t.Fatal(err)
	}
	if want := wantExplainBlock(7, explainFixturePaths()[0]); out.String() != want {
		t.Errorf("explain -a 7 --run:\n%s\nwant:\n%s", out.String(), want)
	}
}

// --project reads that project's cached run instead of the last one.
func TestExplainAttackReadsAnotherProject(t *testing.T) {
	root := withCacheDir(t)
	if err := runcache.Write(root, "gitlab/g/other.json", explainFixtureReport(t, "g/other")); err != nil {
		t.Fatal(err)
	}
	if err := runcache.Write(root, "github/o/r.json", []byte(`{"plumberScore":{"paths":[]}}`)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runExplainAttack(&out, "7", attackSource{project: "g/other"}, termCaps{Color: colorOff}); err != nil {
		t.Fatal(err)
	}
	if want := wantExplainBlock(7, explainFixturePaths()[0]); out.String() != want {
		t.Errorf("explain -a 7 --project:\n%s\nwant:\n%s", out.String(), want)
	}
	if err := runExplainAttack(&out, "7", attackSource{project: "g/other", provider: "github"}, termCaps{Color: colorOff}); err == nil {
		t.Error("--provider github found the gitlab run")
	}
}

// With no cached run, one line names where Plumber looked and what to run.
func TestExplainAttackWithNoCachedRun(t *testing.T) {
	root := withCacheDir(t)
	err := runExplainAttack(&bytes.Buffer{}, "7", attackSource{}, termCaps{Color: colorOff})
	if err == nil {
		t.Fatal("no error with an empty cache")
	}
	msg := err.Error()
	if !strings.Contains(msg, filepath.Join(root, "last")) || !strings.Contains(msg, "plumber analyze") || strings.Contains(msg, "\n") {
		t.Errorf("error = %q, want one line naming %s and plumber analyze", msg, filepath.Join(root, "last"))
	}
}

func TestExplainAttackRejectsAMissingPath(t *testing.T) {
	root := withCacheDir(t)
	if err := runcache.Write(root, "github/o/r.json", explainFixtureReport(t, "o/r")); err != nil {
		t.Fatal(err)
	}
	for _, sel := range []string{"9", "0", "-1", "seven"} {
		err := runExplainAttack(&bytes.Buffer{}, sel, attackSource{}, termCaps{Color: colorOff})
		if err == nil {
			t.Errorf("-a %s: no error", sel)
		}
	}
	err := runExplainAttack(&bytes.Buffer{}, "9", attackSource{}, termCaps{Color: colorOff})
	if err == nil || !strings.Contains(err.Error(), "8 attack paths") {
		t.Errorf("-a 9 = %v, want the count of paths", err)
	}
}

// resetExplainFlags puts every explain flag back after a test that parsed
// some.
func resetExplainFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		explainAttack, explainRun, explainProject, explainProvider = "", "", "", ""
		explainJSON, explainList, explainAll = false, false, false
	})
}

// -a and --attack are one flag; a code and -a together are refused.
func TestExplainAttackFlags(t *testing.T) {
	root := withCacheDir(t)
	if err := runcache.Write(root, "github/o/r.json", explainFixtureReport(t, "o/r")); err != nil {
		t.Fatal(err)
	}
	want := wantExplainBlock(7, explainFixturePaths()[0])
	for _, args := range [][]string{{"-a", "7"}, {"--attack", "7"}, {"--attack=7"}} {
		resetExplainFlags(t)
		if err := explainCmd.Flags().Parse(args); err != nil {
			t.Fatal(err)
		}
		var err error
		got := captureStdoutAll(t, func() { err = explainCmd.RunE(explainCmd, explainCmd.Flags().Args()) })
		if err != nil || got != want {
			t.Errorf("%v: err %v, output:\n%s", args, err, got)
		}
		explainAttack = ""
	}
	resetExplainFlags(t)
	if err := explainCmd.Flags().Parse([]string{"ISSUE-501", "-a", "7"}); err != nil {
		t.Fatal(err)
	}
	if err := explainCmd.RunE(explainCmd, explainCmd.Flags().Args()); err == nil || !strings.Contains(err.Error(), "either") {
		t.Errorf("a code with -a = %v, want a refusal", err)
	}
	explainAttack = ""
	resetExplainFlags(t)
	if err := explainCmd.Flags().Parse([]string{"--run", "x.json"}); err != nil {
		t.Fatal(err)
	}
	if err := explainCmd.RunE(explainCmd, explainCmd.Flags().Args()); err == nil || !strings.Contains(err.Error(), "--attack") {
		t.Errorf("--run without -a = %v, want a pointer to --attack", err)
	}
}

// The JSON report carries each path's block, lossless, so `explain -a`
// prints what the run computed; the score push payload does not.
func TestJSONReportCarriesThePathBlocks(t *testing.T) {
	_, result, conf, s := v4OutputFixture(t)
	if len(s.score.Paths) == 0 {
		t.Fatal("fixture has no path")
	}
	for i := range result.Findings {
		result.Findings[i].Message = "message of " + result.Findings[i].Code
	}
	raw, err := buildAnalysisJSONReport(result, conf.PlumberConfig, s, jsonOutputParams{provider: "github"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		PathBlocks []jsonPathBlock `json:"pathBlocks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.PathBlocks) != len(s.score.Paths) {
		t.Fatalf("pathBlocks = %d, want one per path (%d)", len(doc.PathBlocks), len(s.score.Paths))
	}
	for i, p := range control.PathsWorstFirst(s.score.Paths) {
		got := doc.PathBlocks[i]
		want := control.NewPathBlock(p, result.Findings)
		if got.ID != p.ID || !blocksEqual(got.block(), want) {
			t.Errorf("pathBlocks[%d] = %+v, want %+v of %s", i, got.block(), want, p.ID)
		}
		if len(want.Findings) == 0 {
			t.Errorf("fixture path %s lists no finding", p.ID)
		}
		// Each line of the block carries its findings in full, as many as
		// the line counts, so `explain -a` prints every one.
		for _, f := range got.Findings {
			if len(f.Details) != max(f.Count, 1) {
				t.Errorf("%s %s: %d details, want %d", p.ID, f.Code, len(f.Details), max(f.Count, 1))
			}
			for _, d := range f.Details {
				if d.Message != "message of "+string(f.Code) || d.Severity == "" {
					t.Errorf("%s %s: detail %+v lacks its message or its severity", p.ID, f.Code, d)
				}
			}
		}
	}
	push, err := buildAnalysisJSONReport(result, conf.PlumberConfig, s, jsonOutputParams{provider: "github", forScorePush: true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(push, []byte(`"pathBlocks"`)) {
		t.Error("the score push payload carries pathBlocks")
	}
}

func blocksEqual(a, b control.PathBlock) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

// Every analyze run that produced a report leaves it in the cache, under
// its provider and project, the bytes --output writes, and points last at
// it.
func TestOutputsCacheTheReport(t *testing.T) {
	root := withCacheDir(t)
	gh, result, conf, s := v4OutputFixture(t)
	result.ProjectPath = "Getplumber-Examples/Plumber-Example-Critical"
	defer func(o string) { outputFile = o }(outputFile)
	outputFile = filepath.Join(t.TempDir(), "out.json")
	stderr := captureStderr(t, func() {
		if err := writeOutputsWithProvider(gh, result, conf, s, nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	cached, err := os.ReadFile(filepath.Join(root, "github", "getplumber-examples", "plumber-example-critical.json"))
	if err != nil {
		t.Fatal(err)
	}
	written, _ := os.ReadFile(outputFile)
	if !bytes.Equal(cached, written) {
		t.Error("the cached report differs from --output")
	}
	if st, _ := os.Stat(filepath.Join(root, "github", "getplumber-examples", "plumber-example-critical.json")); st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", st.Mode().Perm())
	}
	if last, err := runcache.Last(root); err != nil || last != filepath.Join(root, "github", "getplumber-examples", "plumber-example-critical.json") {
		t.Errorf("last = %q, %v", last, err)
	}
	if strings.Contains(stderr, "cache") {
		t.Errorf("the cache write printed: %q", stderr)
	}
}

// A local analysis with no project path is cached under the hash of its
// working directory.
func TestOutputsCacheALocalReportByWorkingDirectory(t *testing.T) {
	root := withCacheDir(t)
	gh, result, conf, s := v4OutputFixture(t)
	result.ProjectPath = ""
	defer func(o string) { outputFile = o }(outputFile)
	outputFile = ""
	if err := writeOutputsWithProvider(gh, result, conf, s, nil, nil); err != nil {
		t.Fatal(err)
	}
	cwd, _ := os.Getwd()
	abs, _ := filepath.Abs(cwd)
	want := filepath.Join(root, filepath.FromSlash(runcache.Key("github", "", abs)))
	if _, err := os.Stat(want); err != nil {
		t.Errorf("no cached report at %s: %v", want, err)
	}
}

// The cache never fails nor warns the run, and a report that could not be
// produced is never cached.
func TestOutputsCacheIsBestEffort(t *testing.T) {
	gh, result, conf, s := v4OutputFixture(t)
	defer func(o string) { outputFile = o }(outputFile)
	outputFile = ""
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := userCacheDir
	t.Cleanup(func() { userCacheDir = old })
	userCacheDir = func() (string, error) { return blocked, nil }
	stderr := captureStderr(t, func() {
		if err := writeOutputsWithProvider(gh, result, conf, s, nil, nil); err != nil {
			t.Errorf("an unwritable cache failed the run: %v", err)
		}
	})
	if stderr != "" {
		t.Errorf("an unwritable cache printed: %q", stderr)
	}
	root := withCacheDir(t)
	s.score.FinalPoints = math.NaN()
	_ = captureStderr(t, func() { _ = writeOutputsWithProvider(gh, result, conf, s, nil, nil) })
	if _, err := os.Stat(filepath.Join(root, "last")); err == nil {
		t.Error("a report that could not be built was cached")
	}
}

// detailedFixtureReport is a JSON report with one path whose block lists
// two findings of one code, one with a forge URL and one without, and a
// third finding of another code, each carried in full.
func detailedFixtureReport(t *testing.T) []byte {
	t.Helper()
	p := control.AttackPath{ID: "p1", Tier: control.TierHigh, BaseTier: control.TierHigh, AnchorCode: "ISSUE-701"}
	block := jsonPathBlockOf(p.ID, control.PathBlock{
		Tier: p.Tier, Entry: "o/a@v1 (mutable external action)", EntrySubject: "o/a@v1",
		Branches: []control.PathBlockBranch{{Job: "job `build`", Reach: "code execution without secrets"}},
		So:       "if this action is compromised, an attacker can execute code on the runner", Fix: "pin the version on the commit SHA",
		Findings: []control.PathBlockFinding{
			{Code: "ISSUE-701", Title: "Third-party action reference is not pinned by commit SHA", Location: "ci.yml:3", Count: 2},
			{Code: "ISSUE-307", Title: "Checkout persists credentials in .git/config (latent)", Location: "ci.yml:18"},
		},
	})
	block.Findings[0].Details = []jsonPathFindingDetail{
		{Message: `job "build" references action "o/a@v1" by a mutable ref` + policyDash + `a new version of the action runs without any change in this repository`,
			Severity: "high", URL: "https://github.com/o/r/blob/main/ci.yml#L3", Location: "ci.yml:3"},
		{Message: `job "test" references action "o/a@v1"` + policyDash + `a new version of the action runs without any change in this repository`, Severity: "medium", Location: "ci.yml:9"},
	}
	block.Findings[1].Details = []jsonPathFindingDetail{
		{Message: "Checkout persists credentials in .git/config.", Severity: "low", URL: "https://github.com/o/r/blob/main/ci.yml#L18", Location: "ci.yml:18"},
	}
	raw, err := json.Marshal(map[string]any{
		"projectPath":  "o/r",
		"plumberScore": map[string]any{"paths": []control.AttackPath{p}},
		"pathBlocks":   []jsonPathBlock{block},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// `explain -a N` keeps the block, then lists every finding of the path,
// one group per code with a blank line before each, laid out as an
// individual finding's block: the contextual severity, the code, the title
// and how many findings; one branch per finding saying where it runs and
// what it found, where it is under it (the forge URL when the run has one,
// else file:line); the shared consequence once; the fix only for a
// privilege or a gate code (the block's Fix fixes the entry); the
// documentation once. --run and --project print the same.
func TestExplainAttackPrintsEveryFindingInFull(t *testing.T) {
	root := withCacheDir(t)
	raw := detailedFixtureReport(t)
	if err := runcache.Write(root, "github/o/r.json", raw); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	caps := termCaps{Color: colorOff, Width: 80}
	var out bytes.Buffer
	if err := runExplainAttack(&out, "1", attackSource{}, caps); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	want := "       Fix    pin the version on the commit SHA\n" +
		"       Findings\n" +
		"\n" +
		"          HIGH  ISSUE-701  Third-party action reference is not pinned by commit\n" +
		"                           SHA (2 findings)\n" +
		"                │\n" +
		"                ├──▶ job `build`: references action \"o/a@v1\" by a mutable ref\n" +
		"                │    ↳ at https://github.com/o/r/blob/main/ci.yml#L3\n" +
		"                └──▶ job `test`: references action \"o/a@v1\"\n" +
		"                     ↳ at ci.yml:9\n" +
		"\n" +
		"                So     a new version of the action runs without any change in\n" +
		"                       this repository\n" +
		"                ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-701\n" +
		"\n" +
		"          LOW   ISSUE-307  Checkout persists credentials in .git/config (latent)\n" +
		"                │\n" +
		"                └──▶ Checkout persists credentials in .git/config.\n" +
		"                     ↳ at https://github.com/o/r/blob/main/ci.yml#L18\n" +
		"\n" +
		"                Fix    set persist-credentials: false on the checkout\n" +
		"                ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-307\n" +
		"\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("explain -a 1:\n%s\nwant it to end on:\n%s", got, want)
	}
	if !strings.HasPrefix(got, " HIGH  Attack path 1\n       Entry  o/a@v1 (mutable external action)\n") {
		t.Errorf("explain -a 1 lost the block:\n%s", got)
	}
	for name, src := range map[string]attackSource{"--run": {run: file}, "--project": {project: "o/r"}} {
		var again bytes.Buffer
		if err := runExplainAttack(&again, "1", src, caps); err != nil {
			t.Fatal(err)
		}
		if again.String() != got {
			t.Errorf("explain -a 1 %s:\n%s\nwant:\n%s", name, again.String(), got)
		}
	}
}
