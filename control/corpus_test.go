package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/testsupport/pipelines"
)

// corpusExpectPath is one path a case expects AssemblePaths to build: every
// set field must match the same assembled path, and the path's sentence must
// contain every SentenceContains fragment and none of the SentenceOmits ones
// (a secret the platform keeps out of the run must not be named).
//
// Job, when empty, matches whichever job the path enters first (a
// verdict about an entry subject, not about the order of its jobs).
// Actor, when set, is who the entry names as able to make its job run
// (EntryFact.Actor, an ir.GateClass: outsider, maintainer_approved,
// same_repo, insider, unknown).
//
// Pending, when set, names why this one expectation cannot hold yet: it
// is checked on its own, a miss is logged with the sentence, a match
// fails the case (the marker must go), and the case's other labels are
// checked as usual.
type corpusExpectPath struct {
	EntryKind, Tier, Job, SubjectContains, ReachKind, State, Actor string
	SentenceContains, SentenceOmits                                []string
	Pending                                                        string
}

// corpusCeiling bounds the paths starting from one entry subject: no
// assembled path whose entry subject contains SubjectContains (and, when
// they are set, whose entry kind is EntryKind and whose first job is
// Job) may rank above Tier; Tier "none" admits no path at all. It records a
// verdict that names how far a path may go without naming the path
// itself: a path the assessment found false at Critical or High may
// still assemble lower when the spec keeps it (a gated entry held at
// Medium), or not at all. Pending works as on corpusExpectPath.
type corpusCeiling struct {
	EntryKind, SubjectContains, Job, Tier, Pending string
}

// corpusCase is one case directory's expected.json: where the files were
// captured from, the facts the CLI would otherwise fetch from the provider,
// and the labels written by hand from the spec.
type corpusCase struct {
	Source, Commit, Captured, Group, Visibility, DefaultBranch string
	Branches                                                   []ir.Branch
	SettingsVariables                                          []ir.SettingsVariable
	// The provider facts a GitHub run reads through its optional lanes,
	// recorded from the API answers saved at capture time: the
	// deployment environments and their approval rules, every
	// workflow's state, the default GITHUB_TOKEN's write scope and how
	// it was decided. Each Known flag false (or absent) means the lane
	// could not read it, exactly as a refused call leaves it.
	Environments        []ir.Environment
	EnvironmentsKnown   bool
	WorkflowStates      map[string]string
	WorkflowStatesKnown bool
	DefaultTokenWrite   string
	DefaultTokenSource  string
	// ActionMetadata is what the metadata lane would have answered for
	// an action, keyed by the step's `uses` text exactly as written
	// (archived repository, ref kind, a redirect's current owner,
	// advisories and their severities, a run-time download found in the
	// action's own source): set on every step of every job using it.
	ActionMetadata map[string]ir.ActionMetadata
	// Pending names the open question the case is waiting on: the labels
	// follow the spec as written, the engine disagrees, and the
	// disagreement is the spec's own. A pending case that fails is skipped
	// with the reason printed; one that passes fails, so a stale marker
	// never outlives the question it names.
	Pending string
	Note    string
	Expect  struct {
		MaxTier     string
		Paths       []corpusExpectPath
		NoPathAbove string
		// NoPathSubjects are entry subjects no path may start from: a
		// fragment an assembled path's entry subject contains is a miss.
		NoPathSubjects []string
		Ceilings       []corpusCeiling
		LetterAtLeast  string
		Letter         string
	}
}

// loadCorpusCase reads a case directory: expected.json, the captured
// workflow files (github/*.yml and github/*.yaml through the GitHub
// collector, or
// gitlab/*.yml as the merged configuration through the GitLab collector),
// an optional plumber.yaml standing in for the repository's own
// configuration (the shipped default otherwise), and the recorded facts.
func loadCorpusCase(t *testing.T, dir string) (*corpusCase, *ir.NormalizedPipeline, *configuration.Configuration) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c corpusCase
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("%s/expected.json: %v", dir, err)
	}
	var p *ir.NormalizedPipeline
	if files := githubCorpusFiles(dir); len(files) > 0 {
		p = pipelines.GitHubFromFiles(t, files)
	} else if files, _ := filepath.Glob(filepath.Join(dir, "gitlab", "*.yml")); len(files) > 0 {
		p = pipelines.GitLabFromFiles(t, files)
	} else {
		t.Fatalf("%s: no workflow files", dir)
	}
	// The project path is what a real run gets from the provider: the
	// same-organization trust rules (ISSUE-713) and the include facts read it.
	for _, host := range []string{"https://github.com/", "https://gitlab.com/"} {
		if strings.HasPrefix(c.Source, host) {
			p.ProjectPath = strings.TrimPrefix(c.Source, host)
		}
	}
	p.Visibility, p.DefaultBranch, p.Branches = c.Visibility, c.DefaultBranch, c.Branches
	p.SettingsVariables, p.SettingsVariablesKnown = c.SettingsVariables, c.SettingsVariables != nil
	applyCorpusProviderFacts(&c, p)

	conf := defaultConf(t)
	if own, err := os.ReadFile(filepath.Join(dir, "plumber.yaml")); err == nil {
		pc, _, _, err := configuration.LoadPlumberConfigFromBytes(own, filepath.Join(dir, "plumber.yaml"))
		if err != nil {
			t.Fatalf("%s/plumber.yaml: %v", dir, err)
		}
		conf.PlumberConfig = pc
	}
	return &c, p, conf
}

// githubCorpusFiles lists a case's captured GitHub workflow files, both
// extensions GitHub reads, sorted.
func githubCorpusFiles(dir string) []string {
	yml, _ := filepath.Glob(filepath.Join(dir, "github", "*.yml"))
	yaml, _ := filepath.Glob(filepath.Join(dir, "github", "*.yaml"))
	files := append(yml, yaml...)
	sort.Strings(files)
	return files
}

// applyCorpusProviderFacts sets the recorded provider facts on the
// pipeline, then runs the two passes a real GitHub run makes once its
// lanes are read (control/task_github.go): MarkInert (jobs that cannot
// run) and ClassifyGates (who can make each privileged job run). Both
// are no-ops on GitLab. Every case goes through them, whether or not it
// records a fact: a retired runner label or an `if:` gate needs no API
// answer at all.
func applyCorpusProviderFacts(c *corpusCase, p *ir.NormalizedPipeline) {
	if p.Provider == ir.ProviderGitHub {
		p.Environments, p.EnvironmentsKnown = c.Environments, c.EnvironmentsKnown
		p.WorkflowStates, p.WorkflowStatesKnown = c.WorkflowStates, c.WorkflowStatesKnown
		p.ActionsDisabled = actionsDisabled(c.WorkflowStates, c.WorkflowStatesKnown)
		p.DefaultTokenWrite, p.DefaultTokenSource = c.DefaultTokenWrite, c.DefaultTokenSource
		for i := range p.Jobs {
			for j := range p.Jobs[i].Uses {
				if meta, ok := c.ActionMetadata[p.Jobs[i].Uses[j].Uses]; ok {
					p.Jobs[i].Uses[j].Metadata = &meta
				}
			}
		}
	}
	ir.MarkInert(p)
	ir.ClassifyGates(p)
}

// TestCorpus is the precision gate (spec section 7): every known path of an
// incident is found at its tier, no clean case has a path above its bound,
// every sentence carries its slots. Each case runs the same chain as a real
// analysis minus the collection: the policies through evaluatePolicies with
// the case's configuration, the situation module with the same engine
// config, AssemblePaths, then the scoring-v4 formula.
func TestCorpus(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join("testdata", "corpus", "*"))
	var cases []string
	for _, d := range dirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			cases = append(cases, d)
		}
	}
	if len(cases) == 0 {
		t.Fatal("empty corpus")
	}
	// The corpus is offline: captured workflows, no action definitions. The
	// nested actions stage reads definitions whatever the metadata
	// enrichment says, so the offline switch is set here, once, before the
	// parallel cases start (a parallel test cannot set it itself): every
	// direct reference is then listed api_disabled without degrading.
	t.Setenv(github.EnvDisableGitHubAPI, "1")
	// PLUMBER_CORPUS_SNAPSHOT=<file> writes every case's paths and score to
	// that file, for a before and after comparison across a refactor.
	snapshot := os.Getenv("PLUMBER_CORPUS_SNAPSHOT")
	if snapshot != "" {
		if err := os.WriteFile(snapshot, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range cases {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			// The cases share nothing but the snapshot file, which is
			// written in case order: run them in parallel unless one is
			// being written.
			if snapshot == "" {
				t.Parallel()
			}
			c, p, conf := loadCorpusCase(t, dir)
			provider := string(p.Provider)
			quiet := logrus.New()
			quiet.SetOutput(io.Discard)
			findings, failures := evaluatePolicies(logrus.NewEntry(quiet), conf, provider, p)
			if len(failures) > 0 {
				t.Fatalf("policy failures: %+v", failures)
			}
			sit, err := EvaluateSituation(context.Background(), p, buildEngineConfig(conf.PlumberConfig.ControlsFor(provider), ""))
			if err != nil {
				t.Fatal(err)
			}
			// As a run does (attachSituation): a finding on a job no
			// outsider can make run is priced Low, with the note.
			markGatedFindings(findings, sit)
			paths := assemblePaths(findings, sit)
			score := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
			if snapshot != "" {
				appendFile(t, snapshot, corpusSnapshot(filepath.Base(dir), paths, score))
			}
			problems := checkCorpusCase(c, paths, score)
			report := fmt.Sprintf("letter %s (%.2f points)\n%s", score.Score, score.FinalPoints, describePaths(paths))
			if os.Getenv("PLUMBER_CORPUS_VERBOSE") != "" {
				t.Log(report)
			}
			if c.Pending == "" {
				missed, passing := checkPendingExpectations(c, paths)
				for _, m := range missed {
					t.Log(m)
				}
				problems = append(problems, passing...)
			}
			switch {
			case c.Pending != "" && len(problems) > 0:
				t.Skipf("pending %s:\n%s\n%s", c.Pending, strings.Join(problems, "\n"), report)
			case c.Pending != "":
				t.Errorf("case is marked pending %s but now passes: remove the marker", c.Pending)
			case len(problems) > 0:
				t.Errorf("%s\n%s", strings.Join(problems, "\n"), report)
			}
		})
	}
}

// checkPendingExpectations checks the expectations marked pending one by
// one: missed lists those that still miss, each with its sentence (logged,
// not failed); passing lists those that now hold, which fail the case so
// a marker never outlives its cause. A case-level Pending case never gets
// here: everything in it is skipped together.
func checkPendingExpectations(c *corpusCase, paths []AttackPath) (missed, passing []string) {
	for _, want := range c.Expect.Paths {
		if want.Pending == "" {
			continue
		}
		if corpusPathMatches(paths, want) {
			passing = append(passing, fmt.Sprintf("expectation is marked pending %s but now holds: remove the marker: %+v", want.Pending, want))
		} else {
			missed = append(missed, fmt.Sprintf("pending %s: expected path not found: %+v", want.Pending, want))
		}
	}
	for _, ceiling := range c.Expect.Ceilings {
		if ceiling.Pending == "" {
			continue
		}
		if over := ceilingProblems(ceiling, paths); len(over) > 0 {
			missed = append(missed, fmt.Sprintf("pending %s:\n%s", ceiling.Pending, strings.Join(over, "\n")))
		} else {
			passing = append(passing, fmt.Sprintf("ceiling is marked pending %s but now holds: remove the marker: %+v", ceiling.Pending, ceiling))
		}
	}
	return missed, passing
}

// ceilingProblems lists the assembled paths a ceiling admits none of.
func ceilingProblems(ceiling corpusCeiling, paths []AttackPath) []string {
	var problems []string
	for _, got := range paths {
		if !strings.Contains(got.Entry.Subject, ceiling.SubjectContains) || (ceiling.Job != "" && got.Jobs[0] != ceiling.Job) || (ceiling.EntryKind != "" && string(got.EntryKind) != ceiling.EntryKind) {
			continue
		}
		if TierRank(got.Tier) > TierRank(PathTier(ceiling.Tier)) {
			problems = append(problems, fmt.Sprintf("path from %s above %s: %s %s: %s", ceiling.SubjectContains, ceiling.Tier, got.Tier, got.Jobs[0], PathSentence(got)))
		}
	}
	return problems
}

// checkCorpusCase lists every way the assembled paths and the score miss the
// case's labels; an empty list is a pass. An expectation marked pending is
// left to checkPendingExpectations, unless the whole case is pending (then
// every label is checked and the case is skipped together).
func checkCorpusCase(c *corpusCase, paths []AttackPath, score PlumberScoreResult) []string {
	var problems []string
	for _, want := range c.Expect.Paths {
		if want.Pending != "" && c.Pending == "" {
			continue
		}
		if !corpusPathMatches(paths, want) {
			problems = append(problems, fmt.Sprintf("expected path not found: %+v", want))
		}
	}
	if c.Expect.MaxTier != "" {
		got := "none"
		for _, p := range paths {
			if got == "none" || TierRank(p.Tier) > TierRank(PathTier(got)) {
				got = string(p.Tier)
			}
		}
		if got != c.Expect.MaxTier {
			problems = append(problems, fmt.Sprintf("strongest path is %s, want %s", got, c.Expect.MaxTier))
		}
	}
	if c.Expect.NoPathAbove != "" {
		for _, got := range paths {
			if TierRank(got.Tier) > TierRank(PathTier(c.Expect.NoPathAbove)) {
				problems = append(problems, fmt.Sprintf("path above %s: %s %s: %s", c.Expect.NoPathAbove, got.Tier, got.Jobs[0], PathSentence(got)))
			}
		}
	}
	for _, ceiling := range c.Expect.Ceilings {
		if ceiling.Pending != "" && c.Pending == "" {
			continue
		}
		problems = append(problems, ceilingProblems(ceiling, paths)...)
	}
	for _, subject := range c.Expect.NoPathSubjects {
		for _, got := range paths {
			if strings.Contains(got.Entry.Subject, subject) {
				problems = append(problems, fmt.Sprintf("path from %s: %s %s: %s", subject, got.Tier, got.Jobs[0], PathSentence(got)))
			}
		}
	}
	if c.Expect.LetterAtLeast != "" && ScoreLetterRank(score.Score) < ScoreLetterRank(c.Expect.LetterAtLeast) {
		problems = append(problems, fmt.Sprintf("letter %s, want at least %s", score.Score, c.Expect.LetterAtLeast))
	}
	if c.Expect.Letter != "" && score.Score != c.Expect.Letter {
		problems = append(problems, fmt.Sprintf("letter %s, want %s", score.Score, c.Expect.Letter))
	}
	return problems
}

func corpusPathMatches(paths []AttackPath, want corpusExpectPath) bool {
	for _, p := range paths {
		if string(p.EntryKind) != want.EntryKind || string(p.Tier) != want.Tier || (want.Job != "" && p.Jobs[0] != want.Job) {
			continue
		}
		if want.ReachKind != "" && p.ReachKind != want.ReachKind {
			continue
		}
		if want.State != "" && string(p.State) != want.State {
			continue
		}
		if want.Actor != "" && p.Entry.Actor != want.Actor {
			continue
		}
		if want.SubjectContains != "" && !strings.Contains(p.Entry.Subject, want.SubjectContains) {
			continue
		}
		sentence := PathSentence(p)
		ok := true
		for _, s := range want.SentenceContains {
			if !strings.Contains(sentence, s) {
				ok = false
			}
		}
		for _, s := range want.SentenceOmits {
			if strings.Contains(sentence, s) {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func describePaths(paths []AttackPath) string {
	var b strings.Builder
	for _, p := range paths {
		b.WriteString("  " + string(p.Tier) + " " + string(p.State) + " " + string(p.EntryKind) + " " + p.Jobs[0] + " " + p.ReachKind + " [" + p.Entry.Subject + "] " + strings.Join(p.Modifiers, ",") + ": " + PathSentence(p) + "\n")
	}
	return b.String()
}

// corpusSnapshot renders one case's assembled paths and score as stable
// text, so two runs of the corpus can be compared line by line: one line
// per path in AssemblePaths' order, then the score, then the other
// findings.
func corpusSnapshot(name string, paths []AttackPath, score PlumberScoreResult) string {
	var b strings.Builder
	for _, p := range paths {
		codes := make([]string, len(p.AnchorCodes))
		for i, c := range p.AnchorCodes {
			codes[i] = string(c)
		}
		fmt.Fprintf(&b, "%s | %s %s/%s %s %s [%s] jobs=%s reach=%s mods=%s anchors=%s | %s\n",
			name, p.ID, p.Tier, p.BaseTier, p.State, p.EntryKind, p.Entry.Subject,
			strings.Join(p.Jobs, ","), p.ReachKind, strings.Join(p.Modifiers, ","), strings.Join(codes, ","), PathSentence(p))
	}
	fmt.Fprintf(&b, "%s | score %s %.2f\n", name, score.Score, score.FinalPoints)
	fmt.Fprintf(&b, "%s | other %s\n", name, otherCodes(score))
	return b.String()
}

// otherCodes lists the other-findings bucket per code, "none" when empty.
func otherCodes(score PlumberScoreResult) string {
	if len(score.CodeLosses) == 0 {
		return "none"
	}
	parts := make([]string, len(score.CodeLosses))
	for i, cl := range score.CodeLosses {
		parts[i] = fmt.Sprintf("%s/%s x%d", cl.Code, cl.Severity, cl.Count)
	}
	return strings.Join(parts, ", ")
}

// appendFile appends text to the file at path, failing the test on error.
func appendFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, werr := f.WriteString(text)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		t.Fatal(werr)
	}
}

// TestCorpusCheckReportsEveryMiss pins the harness itself: a label the paths
// do not satisfy is reported, never silently passed.
func TestCorpusCheckReportsEveryMiss(t *testing.T) {
	c := &corpusCase{}
	c.Expect.MaxTier = "critical"
	c.Expect.NoPathAbove = "low"
	c.Expect.Letter = "A"
	c.Expect.LetterAtLeast = "B"
	c.Expect.Paths = []corpusExpectPath{{EntryKind: "fork_pr", Tier: "high", Job: "build"}}
	paths := []AttackPath{{Tier: TierMedium, EntryKind: EntryMutableDependency, Jobs: []string{"build"}}}
	got := checkCorpusCase(c, paths, PlumberScoreResult{Score: "E"})
	if len(got) != 5 {
		t.Fatalf("want 5 problems (path, max tier, bound, letter, letter at least), got %d: %v", len(got), got)
	}
	named := []AttackPath{{Tier: TierHigh, EntryKind: EntryForkPR, Jobs: []string{"build"}, Entry: EntryFact{Subject: "x"}, Reach: Reach{Secrets: []string{"KEPT", "DROPPED"}}, ReachKind: "secrets"}}
	if corpusPathMatches(named, corpusExpectPath{EntryKind: "fork_pr", Tier: "high", Job: "build", SentenceOmits: []string{"DROPPED"}}) {
		t.Fatal("a sentence naming an omitted fragment must not match")
	}
	c3 := &corpusCase{}
	c3.Expect.NoPathSubjects = []string{"getplumber/plumber@"}
	trusted := []AttackPath{{Tier: TierMedium, EntryKind: EntryMutableDependency, Jobs: []string{"plumber"}, Entry: EntryFact{Subject: "getplumber/plumber@abc"}}}
	if got := checkCorpusCase(c3, trusted, PlumberScoreResult{Score: "A"}); len(got) != 1 {
		t.Fatalf("a path whose entry subject is listed as having no path must be reported, got %v", got)
	}
	c2 := &corpusCase{}
	c2.Expect.MaxTier = "none"
	c2.Expect.Letter = "A"
	if got := checkCorpusCase(c2, nil, PlumberScoreResult{Score: "A"}); len(got) != 0 {
		t.Fatalf("a clean run matching its labels must pass, got %v", got)
	}
}

// TestCorpusCaseCarriesTheProviderFacts pins the harness's provider
// facts: an environment recorded as known reaches the pipeline and gates
// the job naming it (ClassifyGates ran), an action's recorded metadata
// lands on its step, a workflow recorded as disabled marks its jobs
// inert (MarkInert ran), and the token default is carried as recorded.
func TestCorpusCaseCarriesTheProviderFacts(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "github"), 0o755); err != nil {
		t.Fatal(err)
	}
	scan := `on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  scan:
    runs-on: ubuntu-latest
    environment: frogbot
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@v1
        env:
          TOKEN: ${{ secrets.TOKEN }}
`
	old := `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make
`
	for name, body := range map[string]string{"scan.yml": scan, "old.yaml": old} {
		if err := os.WriteFile(filepath.Join(dir, "github", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	expected := `{
  "source": "https://github.com/acme/widget",
  "visibility": "public",
  "defaultBranch": "main",
  "environments": [{"name": "frogbot", "known": true, "requiredReviewers": true, "reviewers": 1}],
  "environmentsKnown": true,
  "workflowStates": {".github/workflows/scan.yml": "active", ".github/workflows/old.yaml": "disabled_inactivity"},
  "workflowStatesKnown": true,
  "defaultTokenWrite": "false",
  "defaultTokenSource": "log",
  "actionMetadata": {"some/action@v1": {"repoArchived": true, "refKind": "tag"}},
  "expect": {}
}`
	if err := os.WriteFile(filepath.Join(dir, "expected.json"), []byte(expected), 0o644); err != nil {
		t.Fatal(err)
	}
	_, p, _ := loadCorpusCase(t, dir)
	if !p.EnvironmentsKnown || len(p.Environments) != 1 || !p.Environments[0].RequiredReviewers {
		t.Fatalf("environments not carried: known=%v %+v", p.EnvironmentsKnown, p.Environments)
	}
	if p.DefaultTokenWrite != "false" || p.DefaultTokenSource != "log" {
		t.Fatalf("token default not carried: %q %q", p.DefaultTokenWrite, p.DefaultTokenSource)
	}
	if p.ActionsDisabled {
		t.Fatal("one active workflow must keep Actions enabled")
	}
	var scanJob, buildJob *ir.Job
	for i := range p.Jobs {
		switch p.Jobs[i].Name {
		case "scan/scan":
			scanJob = &p.Jobs[i]
		case "old/build":
			buildJob = &p.Jobs[i]
		}
	}
	if scanJob == nil || buildJob == nil {
		t.Fatalf("both workflows must be read, .yml and .yaml: %+v", p.Jobs)
	}
	if scanJob.Gate == nil || scanJob.Gate.Class != ir.GateMaintainerApproved {
		t.Fatalf("the approval-gated environment must gate the job, got %+v", scanJob.Gate)
	}
	if buildJob.Inert == "" {
		t.Fatal("a job of a disabled workflow must be inert")
	}
	if scanJob.Inert != "" {
		t.Fatalf("a job of an active workflow must run, got %q", scanJob.Inert)
	}
	var meta *ir.ActionMetadata
	for _, u := range scanJob.Uses {
		if u.Uses == "some/action@v1" {
			meta = u.Metadata
		}
	}
	if meta == nil || !meta.RepoArchived || meta.RefKind != "tag" {
		t.Fatalf("action metadata not carried: %+v", meta)
	}
}

// TestCorpusCeilingBoundsOneSubject pins the ceiling label: a path from
// the named subject above the tier is a miss, one at or below it passes,
// and a path from another subject is not its business.
func TestCorpusCeilingBoundsOneSubject(t *testing.T) {
	c := &corpusCase{}
	c.Expect.Ceilings = []corpusCeiling{{SubjectContains: "head.sha", Tier: "medium"}}
	paths := []AttackPath{
		{Tier: TierHigh, EntryKind: EntryPRTarget, Jobs: []string{"scan/scan"}, Entry: EntryFact{Subject: "github.event.pull_request.head.sha"}},
		{Tier: TierCritical, EntryKind: EntryMutableDependency, Jobs: []string{"scan/scan"}, Entry: EntryFact{Subject: "some/action@v1"}},
	}
	if got := checkCorpusCase(c, paths, PlumberScoreResult{}); len(got) != 1 {
		t.Fatalf("want the High path above the ceiling reported alone, got %v", got)
	}
	paths[0].Tier = TierMedium
	if got := checkCorpusCase(c, paths, PlumberScoreResult{}); len(got) != 0 {
		t.Fatalf("a path at the ceiling passes, got %v", got)
	}
	actor := corpusExpectPath{EntryKind: "pr_target", Tier: "medium", Job: "scan/scan", Actor: "maintainer_approved"}
	if corpusPathMatches(paths, actor) {
		t.Fatal("an actor the path does not name must not match")
	}
	paths[0].Entry.Actor = "maintainer_approved"
	if !corpusPathMatches(paths, actor) {
		t.Fatal("the named actor must match")
	}

	none := &corpusCase{}
	none.Expect.Ceilings = []corpusCeiling{{SubjectContains: "head.sha", Tier: "none"}}
	if got := checkCorpusCase(none, paths, PlumberScoreResult{}); len(got) != 1 {
		t.Fatalf("tier none must admit no path at all, even a Medium one, got %v", got)
	}
	if got := checkCorpusCase(none, nil, PlumberScoreResult{}); len(got) != 0 {
		t.Fatalf("tier none passes when no path assembles, got %v", got)
	}

	filtered := &corpusCase{}
	filtered.Expect.Ceilings = []corpusCeiling{
		{SubjectContains: "some/action", EntryKind: "pr_target", Tier: "low"},
		{SubjectContains: "some/action", Job: "other/job", Tier: "low"},
	}
	if got := checkCorpusCase(filtered, paths, PlumberScoreResult{}); len(got) != 0 {
		t.Fatalf("a ceiling filtered to another entry kind or job must not bound this path, got %v", got)
	}
	filtered.Expect.Ceilings = []corpusCeiling{{SubjectContains: "some/action", EntryKind: "mutable_dependency", Job: "scan/scan", Tier: "low"}}
	if got := checkCorpusCase(filtered, paths, PlumberScoreResult{}); len(got) != 1 {
		t.Fatalf("a ceiling matching the entry kind and job must bound the path, got %v", got)
	}
}

// TestCorpusPendingExpectationIsCheckedAlone pins the per-expectation
// marker: a pending expectation that misses is reported as missed and does
// not fail the case, the case's other labels are still checked, and a
// pending expectation that holds is reported so the marker is removed.
func TestCorpusPendingExpectationIsCheckedAlone(t *testing.T) {
	paths := []AttackPath{{Tier: TierHigh, EntryKind: EntryMutableDependency, Jobs: []string{"ci/build"}, Entry: EntryFact{Subject: "some/action@v1"}}}
	c := &corpusCase{}
	c.Expect.Ceilings = []corpusCeiling{
		{SubjectContains: "some/action", Tier: "medium", Pending: "a known defect"},
		{SubjectContains: "other/action", Tier: "low"},
	}
	c.Expect.Paths = []corpusExpectPath{{EntryKind: "mutable_dependency", Tier: "critical", Pending: "another defect"}}
	if got := checkCorpusCase(c, paths, PlumberScoreResult{}); len(got) != 0 {
		t.Fatalf("pending expectations must not fail the case, got %v", got)
	}
	missed, passing := checkPendingExpectations(c, paths)
	if len(missed) != 2 || len(passing) != 0 {
		t.Fatalf("want both pending expectations missed, got missed=%v passing=%v", missed, passing)
	}
	c.Expect.Ceilings = append(c.Expect.Ceilings, corpusCeiling{SubjectContains: "some/action", Tier: "medium"})
	if got := checkCorpusCase(c, paths, PlumberScoreResult{}); len(got) != 1 {
		t.Fatalf("a non-pending label of the same case must still be checked, got %v", got)
	}
	c.Expect.Ceilings[0].Tier = "high"
	if _, passing := checkPendingExpectations(c, paths); len(passing) != 1 {
		t.Fatalf("a pending ceiling that now holds must be reported, got %v", passing)
	}
}

// TestCorpusSnapshotListsEveryPathThenTheScore pins the snapshot format the
// corpus is compared with across a refactor: one line per path, in the
// order AssemblePaths returned them, then one score line.
func TestCorpusSnapshotListsEveryPathThenTheScore(t *testing.T) {
	paths := []AttackPath{{
		ID: "abc", Tier: TierHigh, BaseTier: TierHigh, State: PathProven, EntryKind: EntryMutableDependency,
		Entry: EntryFact{Subject: "some/action@v1"}, Jobs: []string{"release"}, ReachKind: "secrets",
		AnchorCodes: []ErrorCode{"ISSUE-701", "ISSUE-713"},
	}}
	got := corpusSnapshot("case", paths, PlumberScoreResult{Score: "C", FinalPoints: 65})
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want a path line, a score line and an other-findings line, got %q", got)
	}
	wantPrefix := "case | abc high/high proven mutable_dependency [some/action@v1] jobs=release reach=secrets mods= anchors=ISSUE-701,ISSUE-713 | "
	if !strings.HasPrefix(lines[0], wantPrefix) {
		t.Errorf("path line = %q, want prefix %q", lines[0], wantPrefix)
	}
	if lines[1] != "case | score C 65.00" {
		t.Errorf("score line = %q", lines[1])
	}
	if lines[2] != "case | other none" {
		t.Errorf("other line = %q", lines[2])
	}
	withOthers := corpusSnapshot("case", nil, PlumberScoreResult{Score: "B", FinalPoints: 85, CodeLosses: []CodeLoss{
		{Code: "ISSUE-210", Severity: SeverityHigh, Count: 1}, {Code: "ISSUE-401", Severity: SeverityMedium, Count: 2},
	}})
	if !strings.HasSuffix(withOthers, "case | other ISSUE-210/high x1, ISSUE-401/medium x2\n") {
		t.Errorf("snapshot = %q", withOthers)
	}
}
