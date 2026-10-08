package control

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// assemblePaths is AssemblePaths for a repository whose own path is not
// known, the case most tests build.
func assemblePaths(findings []opaengine.Finding, sit *Situation) []AttackPath {
	return AssemblePaths(findings, sit, "")
}

// oneJobSituation is a single job holding one secret.
func oneJobSituation(job string) *Situation {
	j := JobSituation{}
	j.Privilege.Secrets = []string{"API_KEY"}
	j.Privilege.SecretsState = "proven"
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{job: j}}
}

// A workflow or an action of the analysed repository itself, named by its
// full owner/repo path (any case), changes only with a commit here: it
// starts no path, like a "./" reference.
func TestOwnRepositoryReferenceByFullNameStartsNoPath(t *testing.T) {
	sit := oneJobSituation("ci/notify")
	for _, uses := range []string{
		"react/react/.github/workflows/shared_check_maintainer.yml@main",
		"React/React/.github/actions/label@main",
		"react/react@main",
	} {
		f := finding(string(CodeActionUnpinned), "ci/notify", map[string]any{"uses": uses})
		if paths := AssemblePaths([]opaengine.Finding{f}, sit, "react/react"); len(paths) != 0 {
			t.Errorf("%s: want no path for the repository's own reference, got %+v", uses, paths)
		}
	}
	// Another repository of the same owner is still a dependency.
	f := finding(string(CodeActionUnpinned), "ci/notify", map[string]any{"uses": "react/react-tools@main"})
	if paths := AssemblePaths([]opaengine.Finding{f}, sit, "react/react"); len(paths) != 1 {
		t.Errorf("want one path for another repository of the owner, got %d", len(paths))
	}
}

// The repository's own owner is not a third party: a path block never
// calls an action of that owner "Third-party", whatever the code's title.
func TestPathBlockNeverCallsAnOwnOwnerActionThirdParty(t *testing.T) {
	sit := oneJobSituation("claude/claude")
	f := finding(string(CodeActionUnpinned), "claude/claude", map[string]any{"uses": "anthropics/claude-code-action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit, "Anthropics/claude-code")
	if len(paths) != 1 {
		t.Fatalf("want one path, got %d", len(paths))
	}
	b := NewPathBlock(paths[0], []opaengine.Finding{f})
	for _, l := range b.Findings {
		if strings.Contains(strings.ToLower(l.Title), "third-party") {
			t.Errorf("finding line %q calls the repository's own owner a third party", l.Title)
		}
	}
	// Another owner keeps the registry title.
	g := finding(string(CodeActionUnpinned), "claude/claude", map[string]any{"uses": "other/action@v1"})
	paths = AssemblePaths([]opaengine.Finding{g}, sit, "anthropics/claude-code")
	b = NewPathBlock(paths[0], []opaengine.Finding{g})
	if !strings.HasPrefix(b.Findings[0].Title, "Third-party") {
		t.Errorf("finding line %q, want the registry title for another owner", b.Findings[0].Title)
	}
}

// insiderJob is a job that writes the repository through a declared token,
// with neither a fork pull request fact (a same-repository guard dropped
// it, or the trigger is not a pull request) nor a privileged trigger.
func insiderJob(refTriggers ...string) JobSituation {
	j := JobSituation{RefTriggers: refTriggers}
	j.Privilege.TokenWrite = []string{"contents"}
	j.Privilege.TokenWriteSource = "declared"
	j.Impact = []ImpactFact{{Kind: "writes_repo", State: "proven", Evidence: "token", Source: impactFromToken}}
	return j
}

func injectionFinding(job, subject string) opaengine.Finding {
	return opaengine.Finding{Code: string(CodeTemplateInjection), Job: job, File: ".github/workflows/x.yml", Line: 20, Subject: subject}
}

// An injected expression only insiders set (a same-repository pull
// request's branch name, a release body) is an insider entry: the sentence
// names who really controls it, and like a push to the branch it never
// reaches Critical (it needs write access).
func TestInsiderInjectionEntryIsCappedAndNamesItsController(t *testing.T) {
	for _, c := range []struct {
		subject, refTrigger, who string
	}{
		{"github.head_ref", "", "Someone who can push a branch to this repository controls `github.head_ref`"},
		{"toJSON(github.event.release.body)", "release", "Someone who can publish a release controls `toJSON(github.event.release.body)`"},
		{"github.event.inputs.version", "workflow_dispatch", "Someone who can run this workflow by hand controls `github.event.inputs.version`"},
	} {
		var refs []string
		if c.refTrigger != "" {
			refs = []string{c.refTrigger}
		}
		sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"w/j": insiderJob(refs...)}}
		paths := assemblePaths([]opaengine.Finding{injectionFinding("w/j", c.subject)}, sit)
		if len(paths) != 1 {
			t.Fatalf("%s: want one path, got %d", c.subject, len(paths))
		}
		p := paths[0]
		if p.Tier != TierHigh || p.BaseTier != TierCritical || !slices.Contains(p.Modifiers, "push_entry_cap") {
			t.Errorf("%s: tier %s/%s modifiers %v, want held at High by the insider cap", c.subject, p.Tier, p.BaseTier, p.Modifiers)
		}
		s := PathSentence(p)
		if !strings.HasPrefix(s, c.who) || strings.Contains(s, "Anyone") {
			t.Errorf("%s: sentence %q, want it to start %q", c.subject, s, c.who)
		}
		if !strings.Contains(s, "needs write access, so this path is capped at High.") {
			t.Errorf("%s: sentence %q does not say why it stops at High", c.subject, s)
		}
		if b := NewPathBlock(p, nil); b.Branches[0].Marker != "" || b.Cap != "Capped at High: it needs write access first" {
			t.Errorf("%s: marker %q, cap %q", c.subject, b.Branches[0].Marker, b.Cap)
		}
	}
}

// The reach says what the token really is: a repository default token's
// write is assumed, on every path, secrets or not; an OIDC token alone is
// no repository write; and the token's verbs read one way whether a step
// also does the same thing or not.
func TestReachWordsTheTokenAsItIs(t *testing.T) {
	j := JobSituation{}
	j.Privilege.Secrets = []string{"S1", "S2"}
	j.Privilege.SecretsState = "proven"
	j.Privilege.TokenWrite = []string{"contents", "packages"}
	j.Privilege.TokenWriteSource = "default"
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"w/j": j}}
	paths := assemblePaths([]opaengine.Finding{finding(string(CodeActionUnpinned), "w/j", map[string]any{"uses": "o/a@v1"})}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %d", len(paths))
	}
	b := NewPathBlock(paths[0], nil)
	if b.ReachesShort != "2 secrets; token: write (assumed)" || b.Branches[0].Reach != "2 secrets and a token with push and publish access (assumed: no permissions block)" {
		t.Errorf("reach = %q / %q, want the assumed token said", b.ReachesShort, b.Branches[0].Reach)
	}
	if !slices.Contains(b.Notes(), defaultTokenUnchecked) {
		t.Errorf("notes = %v, want the unchecked token note", b.Notes())
	}
	if r := PathRowOf(paths[0]).Reaches; r != "2 secrets; token: write (assumed)" {
		t.Errorf("table reach = %q", r)
	}
	if s := PathSentence(paths[0]); !strings.Contains(s, "could not verify that `GITHUB_TOKEN` is really writable") {
		t.Errorf("sentence %q does not say the token is assumed", s)
	}

	if got := reachesShort(AttackPath{Reach: Reach{TokenWrite: []string{"id-token"}, Executes: true}}); got != "OIDC token" {
		t.Errorf("id-token only: %q, want OIDC token", got)
	}
	if got := reachesShort(AttackPath{Reach: Reach{TokenWrite: []string{"id-token", "issues"}, Executes: true}}); got != "token: write" {
		t.Errorf("id-token and issues: %q, want token: write", got)
	}
	tokenOnly := []ImpactFact{{Kind: "writes_repo", Source: impactFromToken}, {Kind: "publishes", Source: impactFromToken}}
	withStep := append([]ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}, tokenOnly...)
	a := reachesShort(AttackPath{Reach: Reach{TokenWrite: []string{"contents", "packages"}, Impacts: tokenOnly, Executes: true}})
	c := reachesShort(AttackPath{Reach: Reach{TokenWrite: []string{"contents", "packages"}, Impacts: withStep, Executes: true}})
	if a != "token: push, publish" || c != a {
		t.Errorf("token verbs: %q and %q, want both token: push, publish", a, c)
	}
}

const pinnedSpelling = "check-spelling/check-spelling@cfb6f7e75bbfc89c71eaa30366d0c166f1bd9c8c"

// Fixing a finding's subject fixes it in every job: the best fix prices
// every other finding of that code on that subject at once, and its
// sentence never asks for a pin the reference already has.
func TestBestFixPricesEveryFindingOnItsSubject(t *testing.T) {
	var findings []opaengine.Finding
	for _, job := range []string{"spelling/a", "spelling/b", "spelling/c", "spelling/d"} {
		findings = append(findings, opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Job: job, File: ".github/workflows/spelling.yml", Line: 10,
			Data: map[string]any{"uses": pinnedSpelling}})
	}
	findings = append(findings, opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Job: "other/x", File: ".github/workflows/other.yml", Line: 3,
		Data: map[string]any{"uses": "other/action@0123456789abcdef0123456789abcdef01234567"}})
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	in := ScoreInputV4{Findings: findings}
	cur := ComputePlumberScoreV4(in)
	// Five actions pinned by a full commit SHA, Medium each: 25.
	if cur.FinalPoints != 75 {
		t.Fatalf("current = %v, want 75", cur.FinalPoints)
	}
	cur.BestFix = ComputeBestFix(in, sit, cur)
	fix := cur.BestFix
	if fix == nil || fix.PointsGained != 20 || fix.NewPoints != 95 || fix.Subject != pinnedSpelling {
		t.Fatalf("fix = %+v, want the four findings on %s fixed together, +20", fix, pinnedSpelling)
	}
	if got := BestFixSummary(&cur); !strings.HasPrefix(got, "use an action from a trusted source (check-spelling/check-spelling@cfb6f7e75bbf)") {
		t.Errorf("summary %q", got)
	}
}

// Every code reads as something to do in a best fix, never as its title,
// and a fix never asks a pinned reference to be pinned.
func TestEveryCodeHasAnActionSentence(t *testing.T) {
	for c, info := range errorCodeRegistry {
		for _, s := range []string{findingFix(c, ""), pathFix(c, "")} {
			if s == info.Title || s == "" || s == "see the issue reference" {
				t.Errorf("%s: fix %q is no action", c, s)
			}
		}
	}
	pinned := "dtolnay/rust-toolchain@e081816240890017053eacbb1bdf337761dc5582"
	if got := pathFix(CodeActionMutableRemoteExec, pinned); got != "pin what the action downloads, or vendor it" {
		t.Errorf("714 pinned: %q", got)
	}
	if got := findingFix(CodeActionArchivedRepo, pinned); got != "replace the archived action" {
		t.Errorf("702: %q", got)
	}
	if got := findingFix(CodeActionUnauthorizedSource, pinned); got != "use an action from a trusted source" {
		t.Errorf("713 pinned: %q", got)
	}
	if got := findingFix(CodeActionUnauthorizedSource, "o/a@v1"); got != "use an action from a trusted source and pin the version on the commit SHA" {
		t.Errorf("713 unpinned: %q", got)
	}
}

// A job shows once in a path's graph: an entry job is never repeated as a
// job another branch feeds, and a job two branches feed hangs off the
// first only.
func TestPathGraphShowsEachJobOnce(t *testing.T) {
	p := AttackPath{Jobs: []string{"w/build", "w/tag"}, Branches: []PathBranch{
		{Job: "w/build", Jobs: []string{"w/build", "w/release"}},
		{Job: "w/tag", Jobs: []string{"w/tag", "w/build", "w/release", "w/lint"}},
	}}
	got := blockBranches(p, nil)
	if len(got) != 2 || !slices.Equal(got[0].Fed, []string{"job `release` from workflow `w`"}) || !slices.Equal(got[1].Fed, []string{"job `lint` from workflow `w`"}) {
		t.Errorf("branches = %+v, want w/release under w/build only and w/build never fed", got)
	}
}

// Every secret of the repository is a wider reach than a list of them:
// the branch holding it is the path's strongest when the tiers tie.
func TestEverySecretIsTheStrongerReach(t *testing.T) {
	every := Reach{AllSecrets: true, Impacts: []ImpactFact{{Kind: "publishes"}}, Executes: true}
	listed := Reach{Secrets: []string{"A", "B", "C"}, Impacts: []ImpactFact{{Kind: "publishes"}, {Kind: "deploys"}}, Executes: true}
	if reachWeight(every) <= reachWeight(listed) {
		t.Errorf("every secret weighs %d, listed secrets with one more impact %d", reachWeight(every), reachWeight(listed))
	}
}

// A graph never runs past the width, even for a long job, its marker and
// the job it feeds, and a reach wraps only between its phrases.
func TestPathGraphKeepsLongBranchesInTheWidth(t *testing.T) {
	marker := "(on pull_request_target or workflow_dispatch, unverified)"
	b := PathBlock{Tier: TierHigh, Entry: "dtolnay/rust-toolchain@e08181624089 (external action that downloads code at run time from a mutable source)",
		EntrySubject: "dtolnay/rust-toolchain@e08181624089",
		Branches: []PathBlockBranch{
			{Job: "job `build` from workflow `rust-release.yml`", Marker: marker, Fed: []string{"job `release` from workflow `rust-release.yml`", "job `sign` from workflow `rust-release.yml`"},
				Reach: "13 secrets, a token with push access, a step that publishes and a step that deploys"},
			{Job: "job `build` from workflow `rusty-v8-release.yml`", Marker: marker, Fed: []string{"job `publish-release` from workflow `rusty-v8-release.yml`"},
				Reach: "1 secret, a token with push and publish access and a step that deploys"},
			{Job: "job `build-windows-source` from workflow `rusty-v8-release.yml`", Marker: marker, Reach: "a token with push and publish access"},
			{Job: "job `cargo-deny` from workflow `cargo-deny.yml`", Reach: "a token with push access (assumed: no permissions block)"},
		},
		So: "if this action is compromised or malicious, an attacker can read 13 secrets of the repository, push in your repository, alter what the job deploys and ship a malicious release", Fix: "pin it"}
	lines := graphLines(3, b, 100)
	for _, l := range lines {
		if lipgloss.Width(l) > 100 {
			t.Errorf("line of %d cells: %q", lipgloss.Width(l), l)
		}
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{"job `publish-release` from workflow `rusty-v8-release.yml`", marker, "a token with push access (assumed: no permissions block)"} {
		if !strings.Contains(got, want) {
			t.Errorf("graph lacks %q:\n%s", want, got)
		}
	}
	narrow := strings.Join(graphLines(3, b, 60), "\n")
	for _, l := range strings.Split(narrow, "\n") {
		if lipgloss.Width(l) > 60 {
			t.Errorf("width 60: line of %d cells: %q", lipgloss.Width(l), l)
		}
	}
	for _, broken := range []string{"token\n", "secret\n", "with\n"} {
		if strings.Contains(narrow, broken) {
			t.Errorf("a reach wraps inside a phrase (%q):\n%s", broken, narrow)
		}
	}
}

// More than six branches reaching the same thing fold into one line, the
// folded jobs listed under the graph.
func TestPathGraphFoldsBranchesWithTheSameReach(t *testing.T) {
	var branches []PathBlockBranch
	for i := range 9 {
		branches = append(branches, PathBlockBranch{Job: fmt.Sprintf("ci/job-%d", i), Reach: "token: write"})
	}
	branches = append([]PathBlockBranch{{Job: "release/build", Reach: "every secret"}}, branches...)
	kept, folded := foldBranches(branches)
	if len(kept) != 8 || kept[7].Job != "3 more jobs with the same reach" || kept[7].Reach != "token: write" {
		t.Errorf("kept = %+v", kept)
	}
	if !slices.Equal(folded, []string{"ci/job-6", "ci/job-7", "ci/job-8"}) {
		t.Errorf("folded = %v", folded)
	}
	b := PathBlock{Tier: TierHigh, Entry: "e", Branches: branches, Fix: "f"}
	got := strings.Join(PathGraph(1, b, 100), "\n")
	if !strings.Contains(got, "└──▶ runs in 3 more jobs with the same reach ─▶ reaches token: write") || !strings.Contains(got, "Also   ci/job-6, ci/job-7, ci/job-8") {
		t.Errorf("graph:\n%s", got)
	}
}

// A path block lists one line per code, however many findings of it the
// path carries, with how many and the first location.
func TestPathBlockFindingsOneLinePerCode(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	var findings []opaengine.Finding
	for i, file := range []string{"c.yml", "a.yml", "b.yml"} {
		job := fmt.Sprintf("w%d/j", i)
		sit.Jobs[job] = JobSituation{}
		findings = append(findings,
			opaengine.Finding{Code: string(CodeActionUnpinned), Job: job, File: file, Line: 12, Data: map[string]any{"uses": "o/a@v1"}},
			opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Job: job, File: file, Line: 12, Data: map[string]any{"uses": "o/a@v1"}})
	}
	paths := assemblePaths(findings, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %d", len(paths))
	}
	got := NewPathBlock(paths[0], findings).Findings
	if len(got) != 2 || got[0].Code != CodeActionUnpinned || got[0].Count != 3 || got[0].Location != "a.yml:12" || got[1].Count != 3 {
		t.Fatalf("findings = %+v, want one line per code, three each, first a.yml:12", got)
	}
	lines := strings.Join(PathGraphFindings(got, 100), "\n")
	if !strings.Contains(lines, "3 findings, first a.yml:12") {
		t.Errorf("lines:\n%s", lines)
	}
}

// A consequence resting on an impact Plumber could not confirm says what
// may happen, never what does.
func TestConsequenceHedgesAnUnconfirmedImpact(t *testing.T) {
	p := AttackPath{BaseTier: TierCritical, Tier: TierHigh, State: PathUnverified, Modifiers: []string{"unresolvable"}, Jobs: []string{"w/j"},
		EntryKind: EntryMutableDependency, AnchorCode: CodeActionUnpinned, Entry: EntryFact{Subject: "o/a@v1"},
		Reach: Reach{TokenWrite: []string{"contents"}, tokenAssumed: true, Impacts: []ImpactFact{{Kind: "writes_repo", State: "unresolvable", Evidence: "peter-evans/create-pull-request"}}, Executes: true}}
	b := NewPathBlock(p, nil)
	if b.So != "if this action is compromised, an attacker may execute code to push in your repository" {
		t.Errorf("So = %q", b.So)
	}
	if !slices.Contains(b.Notes(), "Plumber could not check that this job pushes to the repository") {
		t.Errorf("notes = %v", b.Notes())
	}
	p.Reach.Impacts[0].State = "proven"
	if so := NewPathBlock(p, nil).So; so != "if this action is compromised, an attacker can execute code to push in your repository" {
		t.Errorf("proven impact: So = %q", so)
	}
}

// A branch whose job runs on a privileged trigger or on a schedule says so
// on its line, so a dependency entry never hides who can start the run.
func TestBranchSaysItsPrivilegedTrigger(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{
		"pr/test":     {PrivilegedTriggers: []string{"pull_request_target"}, CacheScopes: defaultScope},
		"bot/rebase":  {PrivilegedTriggers: []string{"issue_comment", "workflow_run"}, CacheScopes: defaultScope},
		"nightly/run": {RefTriggers: []string{"push", "schedule"}, CacheScopes: defaultScope},
		"ci/build":    {RefTriggers: []string{"push"}, CacheScopes: defaultScope},
	}}
	var findings []opaengine.Finding
	for job := range sit.Jobs {
		findings = append(findings, finding(string(CodeActionMutableRemoteExec), job, map[string]any{"uses": "o/a@v1"}))
	}
	paths := assemblePaths(findings, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %d", len(paths))
	}
	want := map[string]string{
		"job `test` from workflow `pr`": "(on pull_request_target)", "job `rebase` from workflow `bot`": "(on issue_comment or workflow_run)",
		"job `run` from workflow `nightly`": "(on schedule)", "job `build` from workflow `ci`": "",
	}
	for _, b := range NewPathBlock(paths[0], nil).Branches {
		if b.Marker != want[b.Job] {
			t.Errorf("%s: marker %q, want %q", b.Job, b.Marker, want[b.Job])
		}
	}
}

// An expression an outsider writes keeps its outsider entry: an issue
// title on a job no fork fact reaches is still Critical when it can do
// damage, and a job on a privileged trigger keeps its contributor wording.
func TestOutsiderInjectionEntryIsNotCapped(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"w/j": insiderJob()}}
	paths := assemblePaths([]opaengine.Finding{injectionFinding("w/j", "github.event.issue.title")}, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical || slices.Contains(paths[0].Modifiers, "push_entry_cap") {
		t.Fatalf("issue title: %+v, want an uncapped Critical path", paths)
	}
	priv := insiderJob()
	priv.PrivilegedTriggers = []string{"pull_request_target"}
	sit.Jobs["w/j"] = priv
	paths = assemblePaths([]opaengine.Finding{injectionFinding("w/j", "github.head_ref")}, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical {
		t.Fatalf("privileged trigger: %+v, want an uncapped Critical path", paths)
	}
	if s := PathSentence(paths[0]); !strings.HasPrefix(s, "Anyone who can open a pull request") {
		t.Errorf("privileged trigger: sentence %q", s)
	}
}
