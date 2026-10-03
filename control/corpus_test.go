package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/testsupport/pipelines"
)

// corpusExpectPath is one path a case expects AssemblePaths to build: every
// set field must match the same assembled path, and the path's sentence must
// contain every SentenceContains fragment and none of the SentenceOmits ones
// (a secret the platform keeps out of the run must not be named).
type corpusExpectPath struct {
	EntryKind, Tier, Job, SubjectContains, ReachKind, State string
	SentenceContains, SentenceOmits                         []string
}

// corpusCase is one case directory's expected.json: where the files were
// captured from, the facts the CLI would otherwise fetch from the provider,
// and the labels written by hand from the spec.
type corpusCase struct {
	Source, Commit, Captured, Group, Visibility, DefaultBranch string
	Branches                                                   []ir.Branch
	SettingsVariables                                          []ir.SettingsVariable
	// Pending names the open ruling (a QUESTIONS row of the monorepo's
	// decision queue) the case is waiting on: the labels follow the spec as
	// written, the engine disagrees, and the disagreement is the spec's own.
	// A pending case that fails is skipped with the ruling printed; one that
	// passes fails, so a stale marker never outlives its ruling.
	Pending string
	Note    string
	Expect  struct {
		MaxTier       string
		Paths         []corpusExpectPath
		NoPathAbove   string
		LetterAtLeast string
		Letter        string
	}
}

// loadCorpusCase reads a case directory: expected.json, the captured
// workflow files (github/*.yml through the GitHub collector, or
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
	if files, _ := filepath.Glob(filepath.Join(dir, "github", "*.yml")); len(files) > 0 {
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
	for _, dir := range cases {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			c, p, conf := loadCorpusCase(t, dir)
			provider := string(p.Provider)
			quiet := logrus.New()
			quiet.SetOutput(io.Discard)
			findings, failures := evaluatePolicies(logrus.NewEntry(quiet), conf, provider, p)
			if len(failures) > 0 {
				t.Fatalf("policy failures: %+v", failures)
			}
			sit, err := EvaluateSituation(context.Background(), p, buildEngineConfig(conf.PlumberConfig.ControlsFor(provider)))
			if err != nil {
				t.Fatal(err)
			}
			paths := AssemblePaths(findings, sit)
			score := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
			problems := checkCorpusCase(c, paths, score)
			report := fmt.Sprintf("letter %s (%.2f points)\n%s", score.Score, score.FinalPoints, describePaths(paths))
			if os.Getenv("PLUMBER_CORPUS_VERBOSE") != "" {
				t.Log(report)
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

// checkCorpusCase lists every way the assembled paths and the score miss the
// case's labels; an empty list is a pass.
func checkCorpusCase(c *corpusCase, paths []AttackPath, score PlumberScoreResult) []string {
	var problems []string
	for _, want := range c.Expect.Paths {
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
		if string(p.EntryKind) != want.EntryKind || string(p.Tier) != want.Tier || p.Jobs[0] != want.Job {
			continue
		}
		if want.ReachKind != "" && p.ReachKind != want.ReachKind {
			continue
		}
		if want.State != "" && string(p.State) != want.State {
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
	c2 := &corpusCase{}
	c2.Expect.MaxTier = "none"
	c2.Expect.Letter = "A"
	if got := checkCorpusCase(c2, nil, PlumberScoreResult{Score: "A"}); len(got) != 0 {
		t.Fatalf("a clean run matching its labels must pass, got %v", got)
	}
}
