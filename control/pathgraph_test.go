package control

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// A path block is a graph: the tier and the number, the Entry line, then
// one branch per entry job saying where it runs and what it reaches, then
// what it means, the fix and the findings.
func TestPathGraphDrawsOneBranchPerEntryJob(t *testing.T) {
	b := PathBlock{
		Tier: TierHigh, Entry: "main (branch anyone with write access can push to, not protected)", EntrySubject: "main",
		Branches: []PathBlockBranch{
			{Job: "job `auto-approve` from workflow `ci.yml`", Reach: "a token with push, publish and deploy access"},
			{Job: "job `scan` from workflow `plumber.yml`", Reach: "a token with write access to security events and an OIDC token"},
			{Job: "job `security-scan` from workflow `build.yml`", Reach: "code execution on the runner, no secret and no write token"},
		},
		So: "as anyone with write access to `main`, an attacker can execute code to push in your repository, publish packages and deploy", Fix: "protect the default branch",
		Findings: []PathBlockFinding{{Code: "ISSUE-501", Title: "Branch protection missing"}},
	}
	want := strings.Join([]string{
		" HIGH  path 2",
		"       Entry  main (branch anyone with write access can push to, not protected)",
		"       │",
		"       ├──▶ runs in job `auto-approve` from workflow `ci.yml`",
		"       │    └─▶ reaches a token with push, publish and deploy access",
		"       ├──▶ runs in job `scan` from workflow `plumber.yml`",
		"       │    └─▶ reaches a token with write access to security events and an OIDC token",
		"       └──▶ runs in job `security-scan` from workflow `build.yml`",
		"            └─▶ reaches code execution on the runner, no secret and no write token",
		"",
		"       So     as anyone with write access to `main`,",
		"              an attacker can execute code to push in your repository, publish packages and deploy",
		"       Fix    protect the default branch",
		"       Findings",
		"         ISSUE-501 Branch protection missing",
	}, "\n")
	if got := strings.Join(graphLines(2, b, 100), "\n"); got != want {
		t.Errorf("graph:\n%s\nwant:\n%s", got, want)
	}
}

// A job the entry job feeds hangs off it; several hang one per line under
// it. A note goes under the consequence, and the location of a finding
// sits beside its title.
func TestPathGraphHangsTheFedJobsOffTheirEntryJob(t *testing.T) {
	b := PathBlock{
		Tier: TierCritical, Entry: "npm-${{ hashFiles('**/package-lock.json') }} (cache an untrusted run can write)",
		EntrySubject: "npm-${{ hashFiles('**/package-lock.json') }}",
		Branches:     []PathBlockBranch{{Job: "job `build` from workflow `release.yml`", Fed: []string{"job `publish` from workflow `release.yml`"}, FedVia: [][]string{{FeedArtifact}}, Reach: "1 secret and a step that publishes"}},
		So:           "as anyone who can write that cache, an attacker can read 1 secret of the repository and ship a malicious release",
		Fix:          "do not restore a cache that untrusted runs can write in a release job",
		Findings:     []PathBlockFinding{{Code: "ISSUE-705", Title: "Release/publish workflow may consume a poisoned build cache", Location: ".github/workflows/release.yml:22"}},
	}
	want := strings.Join([]string{
		" CRIT  path 1",
		"       Entry  npm-${{ hashFiles('**/package-lock.json') }} (cache an untrusted run can write)",
		"       │",
		"       └──▶ runs in job `build` from workflow `release.yml` ─▶ reaches 1 secret and a step that publishes",
		"            └──▶ feeds artifact to job `publish` from workflow `release.yml`",
		"",
		"       So     as anyone who can write that cache, an attacker can read 1 secret of the repository",
		"              and ship a malicious release",
		"       Fix    do not restore a cache that untrusted runs can write in a release job",
		"       Findings",
		"         ISSUE-705 Release/publish workflow may consume a poisoned build cache   .github/workflows/release.yml:22",
	}, "\n")
	if got := strings.Join(graphLines(1, b, 120), "\n"); got != want {
		t.Errorf("graph:\n%s\nwant:\n%s", got, want)
	}

	b.Branches = []PathBlockBranch{
		{Job: "job `build`", Fed: []string{"job `deploy`", "job `publish`"}, Reach: "2 secrets", Marker: "(unverified)"},
		{Job: "job `lint`", Fed: []string{"job `report`", "job `upload`"}, Reach: "code execution on the runner, no secret and no write token"},
	}
	b.Cap = "Capped at High: it needs a dependency compromise first"
	got := strings.Join(graphLines(1, b, 120), "\n")
	if !strings.Contains(got, "       ├──▶ runs in job `build` (unverified) ─▶ reaches 2 secrets\n"+
		"       │    ├──▶ feeds job `deploy`\n"+
		"       │    └──▶ feeds job `publish`\n"+
		"       └──▶ runs in job `lint` ─▶ reaches code execution on the runner, no secret and no write token\n"+
		"            ├──▶ feeds job `report`\n"+
		"            └──▶ feeds job `upload`\n") {
		t.Errorf("graph lacks the branches in:\n%s", got)
	}
	// The cap is how the score is computed, not what the path is: its
	// Note line is printed only when the points are (ShowCap).
	if strings.Contains(got, "Capped at") {
		t.Errorf("the cap Note is printed without ShowCap:\n%s", got)
	}
	b.ShowCap = true
	if got := strings.Join(graphLines(1, b, 120), "\n"); !strings.Contains(got, "       Note   Capped at High: it needs a dependency compromise first\n       Fix    ") {
		t.Errorf("ShowCap: graph lacks the cap Note in:\n%s", got)
	}
}

// At a narrow width the entry wraps under itself, never cut, and so does
// what a branch reaches; no line runs past the width or ends in a space.
func TestPathGraphFitsTheWidth(t *testing.T) {
	b := PathBlock{
		Tier: TierCritical, Entry: "npm-${{ hashFiles('**/package-lock.json') }} (cache an untrusted run can write)",
		EntrySubject: "npm-${{ hashFiles('**/package-lock.json') }}",
		Branches: []PathBlockBranch{
			{Job: "job `build` from workflow `ci.yml`", Reach: "every secret of the repository and a token with push, publish and deploy access"},
			{Job: "job `publish` from workflow `release.yml`", Reach: "1 secret, a token with push and deploy access and a step that publishes"},
		},
		So: "as anyone who can write that cache, an attacker can read 1 secret of the repository and ship a malicious release", Fix: "protect the default branch",
		Findings: []PathBlockFinding{{Code: "ISSUE-705", Title: "Release/publish workflow may consume a poisoned build cache", Location: ".github/workflows/release.yml:22"}},
	}
	lines := graphLines(1, b, 60)
	got := strings.Join(lines, "\n")
	for _, l := range lines {
		if lipgloss.Width(l) > 60 || strings.TrimRight(l, " ") != l {
			t.Errorf("line of %d cells: %q", lipgloss.Width(l), l)
		}
	}
	for _, w := range []string{
		"       Entry  npm-${{ hashFiles('**/package-lock.json') }}\n              (cache an untrusted run can write)\n",
		"       ├──▶ runs in job `build` from workflow `ci.yml`\n       │    └─▶ reaches every secret of the repository\n       │                and a token with push, publish and\n       │                deploy access\n",
		"       └──▶ runs in job `publish` from workflow\n            `release.yml`\n            └─▶ reaches 1 secret,\n                        a token with push and deploy access\n                        and a step that publishes\n",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("graph lacks:\n%s\nin:\n%s", w, got)
		}
	}
	if !strings.Contains(strings.ReplaceAll(got, "\n", " "), "package-lock.json') }}") {
		t.Errorf("the entry was cut:\n%s", got)
	}
}

// The block reads a path's branches out of its own: each entry job with
// the jobs it feeds, what it reaches in a few words, and its marker.
func TestNewPathBlockReadsTheBranches(t *testing.T) {
	sit := multiJobPushSituation()
	paths := assemblePaths([]opaengine.Finding{pushFinding()}, sit)
	b := NewPathBlock(paths[0], nil)
	want := []PathBlockBranch{
		{Job: "job `build`", Reach: "1 secret and a step that publishes"},
		{Job: "job `scan`", Reach: "a token with write access to security events"},
		{Job: "job `lint`", Reach: "code execution on the runner, no secret and no write token"},
	}
	if len(b.Branches) != len(want) {
		t.Fatalf("branches = %+v", b.Branches)
	}
	for i, w := range want {
		if g := b.Branches[i]; g.Job != w.Job || len(g.Fed) != 0 || g.Reach != w.Reach || g.Marker != w.Marker {
			t.Errorf("branch %d = %+v, want %+v", i, g, w)
		}
	}
	// The push cap that held the build branch says so only on the cap
	// Note, which only the points print.
	if b.Cap != "Capped at High: it needs write access first" {
		t.Errorf("cap = %q", b.Cap)
	}
}

// graphLines is a block as a terminal prints it: the graph, then the
// findings.
func graphLines(n int, b PathBlock, width int) []string {
	return append(PathGraph(n, b, width), PathGraphFindings(b.Findings, width)...)
}

// A branch marker says what the branch is (unverified, on which
// trigger), never how the score was computed: a cap that held the branch
// is not in it, whichever cap it is.
func TestBlockBranchesMarkerNeverNamesTheCap(t *testing.T) {
	cases := []struct {
		name      string
		tier      PathTier
		modifiers []string
		state     PathState
		want      string
	}{
		{"push cap", TierHigh, []string{"push_entry_cap"}, PathProven, ""},
		{"dependency cap", TierHigh, []string{"dependency_cap"}, PathProven, ""},
		{"pinning cap", TierMedium, []string{"dependency_cap"}, PathProven, ""},
		{"source cap", TierHigh, []string{"dependency_cap", "source_cap"}, PathProven, ""},
		{"both caps", TierHigh, []string{"push_entry_cap", "dependency_cap"}, PathProven, ""},
		{"unverified and capped", TierHigh, []string{"dependency_cap"}, PathUnverified, "(unverified)"},
		{"unverified and pinning cap", TierMedium, []string{"unresolvable", "dependency_cap"}, PathUnverified, "(unverified)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := AttackPath{Jobs: []string{"build"}, Branches: []PathBranch{
				{Job: "build", Jobs: []string{"build"}, Tier: c.tier, State: c.state, Modifiers: c.modifiers},
			}}
			got := blockBranches(p, nil)
			if len(got) != 1 || got[0].Marker != c.want {
				t.Errorf("marker = %q, want %q", got[0].Marker, c.want)
			}
		})
	}
}

// wordingPath is a one-job path of kind and codes on subject, the job
// holding nothing, for the tables below.
func wordingPath(kind EntryKind, subject string, codes ...ErrorCode) AttackPath {
	return AttackPath{
		Tier: TierHigh, BaseTier: TierHigh, State: PathProven, EntryKind: kind,
		Entry: EntryFact{Kind: kind, State: "proven", Subject: subject}, AnchorCode: codes[0], AnchorCodes: codes,
		Jobs: []string{"ci/build"}, Reach: Reach{Executes: true},
	}
}

type wordingCase struct {
	name string
	p    AttackPath
	want string
}

// The Entry line names what the user can search for, then what it is in a
// few words: one nature per anchoring code, the most serious one when
// several anchor the entry.
func TestPathBlockEntryNamesTheSubjectAndItsNature(t *testing.T) {
	reusable := "o/r/.github/workflows/deploy.yml@main"
	cases := []wordingCase{
		{"701", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned), "o/a@v1 (mutable external action)"},
		{"701 and 713", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned, CodeActionUnauthorizedSource), "o/a@v1 (untrusted and mutable external action)"},
		{"701 reusable", wordingPath(EntryMutableDependency, reusable, CodeActionUnpinned), reusable + " (mutable external reusable workflow)"},
		{"701 and 713 reusable", wordingPath(EntryMutableDependency, reusable, CodeActionUnpinned, CodeActionUnauthorizedSource), reusable + " (untrusted and mutable external reusable workflow)"},
		{"703", wordingPath(EntryMutableDependency, "o/a@v1", CodeKnownVulnerableAction, CodeActionUnpinned), "o/a@v1 (external action with a known vulnerability)"},
		{"707", wordingPath(EntryMutableDependency, "o/a@1c9b1f1aaa2222bbbb3333cccc4444dddd5555ee", CodeImpostorCommit), "o/a@1c9b1f1aaa22 (external action pinned to a commit that is not in its repository)"},
		{"714", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionMutableRemoteExec), "o/a@v1 (external action that downloads code at run time from a mutable source)"},
		{"715", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionObfuscatedRemoteExec), "o/a@v1 (external action that downloads obfuscated code at run time)"},
		{"716", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionRemoteExecUnverified), "o/a@v1 (external action that downloads code at run time Plumber could not check)"},
		{"102", wordingPath(EntryMutableDependency, "node:latest", CodeImageForbiddenTag, CodeImageNotPinnedByDigest), "node:latest (mutable image tag)"},
		{"103", wordingPath(EntryMutableDependency, "node:20", CodeImageNotPinnedByDigest), "node:20 (mutable image tag)"},
		{"103 and 101", wordingPath(EntryMutableDependency, "evil.io/node:20", CodeImageNotPinnedByDigest, CodeImageUnauthorizedSource), "evil.io/node:20 (untrusted and mutable image)"},
		{"404", wordingPath(EntryMutableDependency, "group/templates@main", CodeIncludeForbiddenVersion), "group/templates@main (mutable external include)"},
		{"402", wordingPath(EntryMutableDependency, "group/templates@v1", CodeRefConfusion), "group/templates@v1 (mutable external include)"},
		{"411", wordingPath(EntryMutableDependency, "https://get.example.com/install.sh", CodeUnverifiedScriptExecution), "https://get.example.com/install.sh (script downloaded and run at build time)"},
		{"204", wordingPath(EntryUntrustedExpression, "CI_COMMIT_MESSAGE", CodeUnsafeVariableExpansion), "CI_COMMIT_MESSAGE (user-controlled variable expanded in a script)"},
		{"207", wordingPath(EntryUntrustedExpression, "github.event.pull_request.title", CodeTemplateInjection, CodeGitHubEnvInjection), "github.event.pull_request.title (user-controlled input injected in a script)"},
		{"209", wordingPath(EntryUntrustedExpression, "github.event.issue.title", CodeGitHubEnvInjection), "github.event.issue.title (user-controlled input injected in a script)"},
		{"213", wordingPath(EntryUntrustedExpression, "toJson(github)", CodeUnsafeGithubContextDump), "toJson(github) (whole github context dumped into a script)"},
		{"804", wordingPath(EntryPRTarget, "github.event.pull_request.head.sha", CodePullRequestTargetWithHeadCheckout), "github.event.pull_request.head.sha (pull request code checked out in a privileged workflow)"},
		{"802 workflow_run", wordingPath(EntryPRTarget, "github.event.workflow_run.head_sha", CodeDangerousTriggers), "github.event.workflow_run.head_sha (code of another workflow's run checked out)"},
		{"802 pull request", wordingPath(EntryPRTarget, "github.event.pull_request.head.ref", CodeDangerousTriggers), "github.event.pull_request.head.ref (pull request code checked out in a privileged workflow)"},
		{"705", wordingPath(EntryPoisonedCache, "npm-${{ hashFiles('**/package-lock.json') }}", CodeCachePoisoning), "npm-${{ hashFiles('**/package-lock.json') }} (cache an untrusted run can write)"},
		{"717", wordingPath(EntryPoisonedCache, "npm-key", CodeCachePoisoningUnresolved), "npm-key (cache an untrusted run can write)"},
		{"501", wordingPath(EntryUnprotectedPush, "main", CodeBranchUnprotected), "main (branch anyone with write access can push to, not protected)"},
		{"505", wordingPath(EntryUnprotectedPush, "main", CodeBranchNonCompliant), "main (branch anyone with write access can push to, protection not compliant)"},
	}
	insider := wordingPath(EntryUntrustedExpression, "github.event.release.name", CodeTemplateInjection)
	insider.insider = true
	cases = append(cases, wordingCase{"207 insider", insider, "github.event.release.name (input an insider controls, injected in a script)"})
	for _, c := range []struct {
		code ErrorCode
		kind string
	}{{CodeImageForbiddenTag, "image"}, {CodeActionUnpinned, "action"}} {
		p := wordingPath(EntryMutableDependency, "${{ matrix.ref }}", c.code)
		p.Entry.State = "unresolvable"
		cases = append(cases, wordingCase{"computed " + c.kind, p, "${{ matrix.ref }} (" + c.kind + " computed at run time)"})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := NewPathBlock(c.p, nil)
			if b.Entry != c.want {
				t.Errorf("entry = %q, want %q", b.Entry, c.want)
			}
			if !strings.HasPrefix(b.Entry, b.EntrySubject+" (") {
				t.Errorf("subject %q does not open the entry %q", b.EntrySubject, b.Entry)
			}
		})
	}
}

var (
	writeAllScopes = []string{"actions", "contents", "deployments", "id-token", "packages", "pull-requests", "security-events"}
	writeAllImpact = []ImpactFact{{Kind: "deploys", State: "proven", Source: impactFromToken}, {Kind: "publishes", State: "proven", Source: impactFromToken}, {Kind: "writes_repo", State: "proven", Source: impactFromToken}}
	stepPublishes  = ImpactFact{Kind: "publishes", State: "proven", Evidence: "npm publish"}
)

// What a branch reaches reads as a sentence fragment after "reaches": the
// secrets, then the token by what it lets code do (contents push,
// packages publish, deployments deploy, id-token an OIDC token, every
// other scope write access to it, none dropped), then a step's own impact
// the token does not already give.
func TestReachFragmentReadsAsASentence(t *testing.T) {
	cases := []struct {
		name  string
		r     Reach
		cause unresolvableCause
		want  string
	}{
		{"every secret, write-all", Reach{AllSecrets: true, TokenWrite: writeAllScopes, Impacts: writeAllImpact}, "", "every secret of the repository, a token with push, publish and deploy access and write access to actions, pull requests and security events and an OIDC token"},
		{"secrets and another scope", Reach{Secrets: []string{"A", "B", "C"}, TokenWrite: []string{"pull-requests"}}, "", "3 secrets and a token with write access to pull requests"},
		{"one secret", Reach{Secrets: []string{"A"}}, "", "1 secret"},
		{"assumed token", Reach{TokenWrite: []string{"contents", "packages"}, tokenAssumed: true}, unresolvableDefaultToken, "a token with push and publish access (assumed: no permissions block)"},
		{"OIDC only", Reach{TokenWrite: []string{"id-token"}}, "", "an OIDC token"},
		{"OIDC and another scope", Reach{TokenWrite: []string{"id-token", "security-events"}}, "", "a token with write access to security events and an OIDC token"},
		{"execution only", Reach{Executes: true}, "", "code execution on the runner, no secret and no write token"},
		{"unlisted secrets", Reach{}, unresolvableSecrets, "secrets Plumber could not list"},
		{"unlisted secrets and a token", Reach{TokenWrite: []string{"contents"}}, unresolvableSecrets, "secrets Plumber could not list and a token with push access"},
		{"step publishes, token covers it", Reach{Secrets: []string{"NPM_TOKEN"}, TokenWrite: writeAllScopes, Impacts: []ImpactFact{stepPublishes, writeAllImpact[0], writeAllImpact[2]}}, "", "1 secret, a token with push, publish and deploy access and write access to actions, pull requests and security events and an OIDC token"},
		{"step publishes alone", Reach{Secrets: []string{"NPM_TOKEN"}, Impacts: []ImpactFact{stepPublishes}}, "", "1 secret and a step that publishes"},
		{"step deploys and releases", Reach{Impacts: []ImpactFact{{Kind: "deploys", State: "proven"}, {Kind: "signs_or_releases", State: "proven"}}}, "", "a step that deploys and a step that releases"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reachFragment(c.r, c.cause, nil); got != c.want {
				t.Errorf("reach = %q, want %q", got, c.want)
			}
		})
	}
}

// The So line says who gets in and what they can do there: "<actor>, an
// attacker can <capability>", the actor by entry kind, the capability by
// reach, "may" when the token or the impact it rests on is assumed or
// unconfirmed; it holds in two
// lines of a 100-column screen.
func TestSoLineNamesTheActorAndTheCapability(t *testing.T) {
	with := func(p AttackPath, r Reach) AttackPath {
		p.Reach = r
		return p
	}
	insiderOn := func(subject string) AttackPath {
		p := wordingPath(EntryUntrustedExpression, subject, CodeTemplateInjection)
		p.insider = true
		return p
	}
	unlisted := wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned)
	unlisted.cause = unresolvableSecrets
	cases := []wordingCase{
		{"action, assumed token", with(wordingPath(EntryMutableDependency, "dorny/paths-filter@v3", CodeActionUnpinned, CodeActionUnauthorizedSource), Reach{TokenWrite: []string{"contents", "packages"}, tokenAssumed: true}),
			"if this action is compromised or malicious, an attacker may execute code to push in your repository and publish packages"},
		{"action, every secret, write-all", with(wordingPath(EntryMutableDependency, "o/a@v1", CodeKnownVulnerableAction), Reach{AllSecrets: true, TokenWrite: writeAllScopes, Impacts: writeAllImpact}),
			"through the known vulnerability of this action, an attacker can read every secret of the repository, push in your repository, publish packages and deploy"},
		{"reusable workflow, secrets, other scope", with(wordingPath(EntryMutableDependency, "o/r/.github/workflows/d.yml@main", CodeActionUnpinned), Reach{AllSecrets: true, TokenWrite: []string{"pull-requests"}}),
			"if this reusable workflow is compromised, an attacker can read every secret of the repository and write to pull requests"},
		{"reusable workflow, the longest", with(wordingPath(EntryMutableDependency, "o/r/.github/workflows/d.yml@main", CodeActionUnpinned), Reach{AllSecrets: true, TokenWrite: writeAllScopes, Impacts: append([]ImpactFact{stepPublishes, {Kind: "deploys", State: "proven", Evidence: "environment: prod"}}, writeAllImpact...)}),
			"if this reusable workflow is compromised, an attacker can read every secret, push in your repository, alter what the job deploys and ship a malicious release"},
		{"image, execution only", wordingPath(EntryMutableDependency, "node:latest", CodeImageForbiddenTag),
			"if this image is compromised, an attacker can execute code on the runner and poison what it caches or uploads"},
		{"include, 2 secrets", with(wordingPath(EntryMutableDependency, "g/t@main", CodeIncludeForbiddenVersion), Reach{Secrets: []string{"A", "B"}}),
			"if this include is compromised, an attacker can read 2 secrets of the repository"},
		{"script, OIDC", with(wordingPath(EntryMutableDependency, "https://x/i.sh", CodeUnverifiedScriptExecution), Reach{TokenWrite: []string{"id-token"}}),
			"if this script is compromised or malicious, an attacker can execute code to request an OIDC token"},
		{"injection, execution only", wordingPath(EntryUntrustedExpression, "github.event.pull_request.title", CodeTemplateInjection),
			"as anyone who can open a pull request, an attacker can execute code on the runner and poison what it caches or uploads"},
		{"injection by an issue", wordingPath(EntryUntrustedExpression, "github.event.issue.title", CodeTemplateInjection),
			"as anyone who can open or edit an issue, an attacker can execute code on the runner and poison what it caches or uploads"},
		{"insider, run the workflow", insiderOn("github.event.inputs.tag"), "as anyone who can run the workflow, an attacker can execute code on the runner and poison what it caches or uploads"},
		{"insider, publish a release", insiderOn("github.event.release.body"), "as anyone who can publish a release, an attacker can execute code on the runner and poison what it caches or uploads"},
		{"insider, push", insiderOn("github.event.head_commit.message"), "as anyone who can push, an attacker can execute code on the runner and poison what it caches or uploads"},
		{"pull request target, other scope", with(wordingPath(EntryPRTarget, "github.event.pull_request.head.sha", CodePullRequestTargetWithHeadCheckout), Reach{TokenWrite: []string{"pull-requests"}}),
			"as anyone who opens a pull request, an attacker can execute code to write to pull requests"},
		{"workflow run checkout", wordingPath(EntryPRTarget, "github.event.workflow_run.head_sha", CodeDangerousTriggers),
			"as anyone who opens a pull request, an attacker can execute code on the runner and poison what it caches or uploads"},
		{"cache, release step", with(wordingPath(EntryPoisonedCache, "npm-key", CodeCachePoisoning), Reach{Secrets: []string{"NPM_TOKEN"}, TokenWrite: writeAllScopes, Impacts: []ImpactFact{stepPublishes, writeAllImpact[0], writeAllImpact[2]}}),
			"as anyone who can write that cache, an attacker can read 1 secret of the repository, push in your repository, deploy and ship a malicious release"},
		{"push, every secret, write-all", with(wordingPath(EntryUnprotectedPush, "main", CodeBranchUnprotected), Reach{AllSecrets: true, TokenWrite: writeAllScopes, Impacts: writeAllImpact}),
			"as anyone with write access to `main`, an attacker can read every secret of the repository, push in your repository, publish packages and deploy"},
		{"step deploys", with(wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned), Reach{Impacts: []ImpactFact{{Kind: "deploys", State: "proven", Evidence: "environment: prod"}}}),
			"if this action is compromised, an attacker can alter what the job deploys"},
		{"unconfirmed impact", with(wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned), Reach{Impacts: []ImpactFact{{Kind: "publishes", State: "unresolvable", Evidence: "npm publish"}}}),
			"if this action is compromised, an attacker may ship a malicious release"},
		{"unlisted secrets", unlisted, "if this action is compromised, an attacker can read the secrets Plumber could not list"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewPathBlock(c.p, nil).So
			if got != c.want {
				t.Errorf("so = %q\nwant %q", got, c.want)
			}
			if n := len(wrapHard(got, 100-graphIndent-graphLabel)); n > 2 {
				t.Errorf("so takes %d lines at 100 columns: %q", n, got)
			}
		})
	}
}

// The Fix line is one thing to do per code family, imperative, never two
// ways out joined by "or" (but for vendoring what an action downloads);
// the best fix of the score block reads the same sentence.
func TestPathFixIsOneActionPerCodeFamily(t *testing.T) {
	cases := []wordingCase{
		{"701 and 713", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned, CodeActionUnauthorizedSource), "use an action from a trusted source and pin the version on the commit SHA"},
		{"701 and 713 reusable", wordingPath(EntryMutableDependency, "o/r/.github/workflows/d.yml@main", CodeActionUnpinned, CodeActionUnauthorizedSource), "use a reusable workflow from a trusted source and pin the version on the commit SHA"},
		{"701", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned), "pin the version on the commit SHA"},
		{"703", wordingPath(EntryMutableDependency, "o/a@v1", CodeKnownVulnerableAction), "move to a version without the advisory"},
		{"707", wordingPath(EntryMutableDependency, "o/a@v1", CodeImpostorCommit), "pin a commit that exists in the action's repository"},
		{"714", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionMutableRemoteExec), "pin what the action downloads, or vendor it"},
		{"714 pinned", wordingPath(EntryMutableDependency, "o/a@1c9b1f1aaa2222bbbb3333cccc4444dddd5555ee", CodeActionMutableRemoteExec), "pin what the action downloads, or vendor it"},
		{"715", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionObfuscatedRemoteExec), "pin what the action downloads, or vendor it"},
		{"716", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionRemoteExecUnverified), "pin what the action downloads, or vendor it"},
		{"102", wordingPath(EntryMutableDependency, "node:latest", CodeImageForbiddenTag), "pin the image by digest"},
		{"103", wordingPath(EntryMutableDependency, "node:20", CodeImageNotPinnedByDigest), "pin the image by digest"},
		{"103 and 101", wordingPath(EntryMutableDependency, "evil.io/node:20", CodeImageNotPinnedByDigest, CodeImageUnauthorizedSource), "use an image from a trusted registry and pin it by digest"},
		{"404", wordingPath(EntryMutableDependency, "g/t@main", CodeIncludeForbiddenVersion), "pin the include on a commit SHA"},
		{"402", wordingPath(EntryMutableDependency, "g/t@v1", CodeRefConfusion), "pin the include on a commit SHA"},
		{"411", wordingPath(EntryMutableDependency, "https://x/i.sh", CodeUnverifiedScriptExecution), "download the script, check its checksum, then run it"},
		{"207", wordingPath(EntryUntrustedExpression, "github.event.pull_request.title", CodeTemplateInjection), "pass the input through an environment variable"},
		{"209", wordingPath(EntryUntrustedExpression, "github.event.issue.title", CodeGitHubEnvInjection), "pass the input through an environment variable"},
		{"804", wordingPath(EntryPRTarget, "github.event.pull_request.head.sha", CodePullRequestTargetWithHeadCheckout), "never check out the pull request head in a privileged workflow"},
		{"802", wordingPath(EntryPRTarget, "github.event.workflow_run.head_sha", CodeDangerousTriggers), "never check out the pull request head in a privileged workflow"},
		{"705", wordingPath(EntryPoisonedCache, "k", CodeCachePoisoning), "do not restore a cache that untrusted runs can write in a release job"},
		{"717", wordingPath(EntryPoisonedCache, "k", CodeCachePoisoningUnresolved), "do not restore a cache that untrusted runs can write in a release job"},
		{"501", wordingPath(EntryUnprotectedPush, "main", CodeBranchUnprotected), "protect the default branch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NewPathBlock(c.p, nil).Fix; got != c.want {
				t.Errorf("fix = %q, want %q", got, c.want)
			}
		})
	}
	p := wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned, CodeActionUnauthorizedSource)
	p.ID = "p1"
	score := &PlumberScoreResult{Paths: []AttackPath{p}, BestFix: &BestFix{Code: CodeActionUnpinned, PathID: "p1", PointsGained: 15, NewPoints: 100, NewLetter: "A"}}
	if got, want := BestFixSummary(score), "use an action from a trusted source and pin the version on the commit SHA (action o/a@v1), +15 pts, 100 / 100 (A)"; got != want {
		t.Errorf("best fix = %q, want %q", got, want)
	}
}

// A branch says where it runs: on GitHub the job and the workflow file it
// is in, read off the findings of that job, the workflow's name when no
// finding names the file; on GitLab the job alone. A fed job of another
// workflow reads through it.
func TestBlockBranchesSayWhereTheJobRuns(t *testing.T) {
	p := wordingPath(EntryMutableDependency, "dorny/paths-filter@v3", CodeActionUnpinned)
	p.Jobs = []string{"labeler/triage", "ci/build", "release/notify"}
	p.Branches = []PathBranch{
		{Job: "labeler/triage", Jobs: []string{"labeler/triage", "release/publish"}, Tier: TierHigh, State: PathProven},
		{Job: "ci/build", Jobs: []string{"ci/build"}, Tier: TierHigh, State: PathProven},
		{Job: "release/notify", Jobs: []string{"release/notify"}, Tier: TierHigh, State: PathProven},
	}
	findings := []opaengine.Finding{
		{Code: string(CodeActionUnpinned), Job: "labeler/triage", File: ".github/workflows/labeler.yml", Line: 12},
		{Code: string(CodeUndocumentedPermissions), Job: "release/publish", File: ".github/workflows/release.yaml"},
	}
	got := NewPathBlock(p, findings).Branches
	if len(got) != 3 {
		t.Fatalf("branches = %+v", got)
	}
	if got[2].Job != "job `notify` from workflow `release.yaml`" {
		t.Errorf("branch 2 = %+v, want the file another job of its workflow names", got[2])
	}
	if got[0].Job != "job `triage` from workflow `labeler.yml`" || len(got[0].Fed) != 1 || got[0].Fed[0] != "job `publish` through workflow `release.yaml`" {
		t.Errorf("branch 0 = %+v", got[0])
	}
	if got[1].Job != "job `build` from workflow `ci`" {
		t.Errorf("branch 1 = %+v, want the workflow's name when no finding names its file", got[1])
	}
	gitlab := wordingPath(EntryMutableDependency, "node:latest", CodeImageForbiddenTag)
	gitlab.Jobs = []string{"build"}
	gl := NewPathBlock(gitlab, []opaengine.Finding{{Code: string(CodeImageForbiddenTag), Job: "build", File: ".gitlab-ci.yml"}}).Branches
	if len(gl) != 1 || gl[0].Job != "job `build`" {
		t.Errorf("gitlab branch = %+v, want the job alone", gl)
	}
}

// The block of the product owner's example: the title alone on its line,
// the Entry line, the branch saying where the job runs and what it
// reaches, the reach on the line under the job when it does not fit beside
// it, then So, Note and Fix; the merge request comment lays out the same
// text under its own title.
func TestPathGraphReadsTheEntryTheBranchAndTheConsequence(t *testing.T) {
	b := PathBlock{
		Tier: TierHigh, Entry: "dorny/paths-filter@v3 (untrusted and mutable external action)", EntrySubject: "dorny/paths-filter@v3",
		Branches:        []PathBlockBranch{{Job: "job `triage` from workflow `labeler.yml`", Reach: "a token with push and publish access (assumed: no permissions block)"}},
		So:              "if this action is compromised or malicious, an attacker can execute code to push in your repository and publish packages",
		ReachUnverified: defaultTokenUnchecked,
		Fix:             "use an action from a trusted source and pin the version on the commit SHA",
	}
	want := []string{
		" HIGH  Attack path 1",
		"       Entry  dorny/paths-filter@v3 (untrusted and mutable external action)",
		"       │",
		"       └──▶ runs in job `triage` from workflow `labeler.yml`",
		"            └─▶ reaches a token with push and publish access (assumed: no permissions block)",
		"",
		"       So     if this action is compromised or malicious,",
		"              an attacker can execute code to push in your repository and publish packages",
		"       Note   Plumber could not check that the token can write (no permissions block)",
		"       Fix    use an action from a trusted source and pin the version on the commit SHA",
	}
	if got := strings.Join(ReportPathGraph(1, b, 100), "\n"); got != strings.Join(want, "\n") {
		t.Errorf("graph:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	want[0] = " HIGH  path 1"
	if got := strings.Join(PathGraph(1, b, 100), "\n"); got != strings.Join(want, "\n") {
		t.Errorf("comment graph:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	b.Unverified = true
	if got := ReportPathGraph(1, b, 100)[0]; got != " HIGH  Attack path 1 (unverified)" {
		t.Errorf("unverified title = %q", got)
	}
}

// A reach that fits beside its job in fewer lines than under it stays on
// the branch line, wrapping between its phrases under its first word; one
// that does not goes on the line under the job and wraps between its
// phrases, its lines under the reach text; a marker that does not fit
// beside the job goes on the line under it; a fed job keeps the "runs in
// job" form; no line passes the width.
func TestPathGraphBranchLinesWrapBetweenPhrases(t *testing.T) {
	b := PathBlock{
		Tier: TierHigh, Entry: "main (branch anyone with write access can push to, not protected)", EntrySubject: "main",
		Branches: []PathBlockBranch{
			{Job: "job `build` from workflow `ci.yml`", Reach: "every secret of the repository and a token with push, publish and deploy access", Marker: "(on push, unverified)"},
			{Job: "job `scan` from workflow `plumber.yml`", Reach: "an OIDC token"},
			{Job: "job `preview` from workflow `pr-preview.yml`", Fed: []string{"job `deploy` from workflow `pr-preview.yml`"}, Reach: "code execution on the runner, no secret and no write token", Marker: "(on pull_request_target or workflow_dispatch, unverified)"},
		},
		So: "x", Fix: "protect the default branch",
	}
	joined := strings.Join(ReportPathGraph(6, b, 100), "\n")
	for _, w := range []string{
		"       ├──▶ runs in job `build` from workflow `ci.yml` (on push, unverified)\n" +
			"       │    └─▶ reaches every secret of the repository\n" +
			"       │                and a token with push, publish and deploy access\n",
		"       ├──▶ runs in job `scan` from workflow `plumber.yml` ─▶ reaches an OIDC token\n",
		"       └──▶ runs in job `preview` from workflow `pr-preview.yml`\n" +
			"            (on pull_request_target or workflow_dispatch, unverified)\n" +
			"            ├─▶ reaches code execution on the runner, no secret and no write token\n" +
			"            └──▶ feeds job `deploy` from workflow `pr-preview.yml`\n",
	} {
		if !strings.Contains(joined, w) {
			t.Errorf("graph lacks:\n%s\nin:\n%s", w, joined)
		}
	}
	// A short job and a long reach: the reach wraps beside the job, its
	// lines under its first word.
	short := PathBlock{Tier: TierHigh, Branches: []PathBlockBranch{{Job: "job `a`", Reach: "every secret of the repository, a token with push and deploy access and a step that releases"}}}
	if got, want := strings.Join(ReportPathGraph(1, short, 100)[2:4], "\n"),
		"       └──▶ runs in job `a` ─▶ reaches every secret of the repository,\n"+
			strings.Repeat(" ", 39)+"a token with push and deploy access and a step that releases"; got != want {
		t.Errorf("short job:\n%s\nwant:\n%s", got, want)
	}
	for _, width := range []int{60, 80, 100} {
		for _, l := range ReportPathGraph(6, b, width) {
			if lipgloss.Width(l) > width || strings.TrimRight(l, " ") != l {
				t.Errorf("width %d: line of %d cells: %q", width, lipgloss.Width(l), l)
			}
		}
	}
}

// A reach dropped under a branch that is not the last one keeps the
// sibling bar in its column, on the reach line and on its continuation
// lines; the reach's corner sits under the first word of the job, its
// continuation lines under its first word after "reaches".
func TestPathGraphDroppedReachOfANonLastBranchKeepsTheSiblingBar(t *testing.T) {
	b := PathBlock{Tier: TierHigh, Branches: []PathBlockBranch{
		{Job: "job `build` from workflow `ci.yml`", Reach: "every secret of the repository and a token with push, publish and deploy access"},
		{Job: "job `lint`", Reach: "an OIDC token"},
	}}
	want := strings.Join([]string{
		"       ├──▶ runs in job `build` from workflow `ci.yml`",
		"       │    └─▶ reaches every secret of the repository",
		"       │                and a token with push, publish and",
		"       │                deploy access",
		"       └──▶ runs in job `lint` ─▶ reaches an OIDC token",
	}, "\n")
	if got := strings.Join(ReportPathGraph(1, b, 60)[2:7], "\n"); got != want {
		t.Errorf("branches:\n%s\nwant:\n%s", got, want)
	}
}

// A dropped reach of a branch that feeds jobs opens on "├─▶" so the tree
// runs on down to the fed jobs: its continuation lines carry the bar, and
// the fed jobs hang in the same column, the last on "└──▶"; a fed job
// whose kinds are not known reads "feeds job ...".
func TestPathGraphDroppedReachRunsOnToTheFedJobs(t *testing.T) {
	b := PathBlock{Tier: TierCritical, Branches: []PathBlockBranch{{
		Job:   "job `build` from workflow `ci.yml`",
		Fed:   []string{"job `deploy`", "job `publish`"},
		Reach: "every secret of the repository and a token with push, publish and deploy access",
	}}}
	want := strings.Join([]string{
		"       └──▶ runs in job `build` from workflow `ci.yml`",
		"            ├─▶ reaches every secret of the repository",
		"            │           and a token with push, publish and",
		"            │           deploy access",
		"            ├──▶ feeds job `deploy`",
		"            └──▶ feeds job `publish`",
	}, "\n")
	if got := strings.Join(ReportPathGraph(1, b, 60)[2:8], "\n"); got != want {
		t.Errorf("branch:\n%s\nwant:\n%s", got, want)
	}
}

// A fed job's line names the handoff from the entry job: what it passes
// on (an artifact, a cache, job outputs along a needs dependency), every
// kind linking the pair joined with "and".
func TestPathGraphNamesTheHandoffToEachFedJob(t *testing.T) {
	for _, tc := range []struct {
		kinds []string
		want  string
	}{
		{[]string{FeedArtifact}, "            └──▶ feeds artifact to job `build-s3-hub` from workflow `build.yaml`"},
		{[]string{FeedCache}, "            └──▶ feeds cache to job `build-s3-hub` from workflow `build.yaml`"},
		{[]string{FeedOutput}, "            └──▶ feeds output to job `build-s3-hub` from workflow `build.yaml`"},
		{[]string{FeedArtifact, FeedCache}, "            └──▶ feeds artifact and cache to job `build-s3-hub` from workflow `build.yaml`"},
	} {
		b := PathBlock{Tier: TierCritical, Branches: []PathBlockBranch{{
			Job:    "job `build-image` from workflow `build.yaml`",
			Fed:    []string{"job `build-s3-hub` from workflow `build.yaml`"},
			FedVia: [][]string{tc.kinds},
			Reach:  "6 secrets, a token with push and publish access and a step that deploys",
		}}}
		lines := ReportPathGraph(1, b, 100)
		want := []string{
			"       └──▶ runs in job `build-image` from workflow `build.yaml`",
			"            ├─▶ reaches 6 secrets, a token with push and publish access and a step that deploys",
			tc.want,
		}
		if got := lines[2:5]; !slices.Equal(got, want) {
			t.Errorf("kinds %v:\n%s\nwant:\n%s", tc.kinds, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

// A block reads the kinds of each fed job off its branch, a needs
// dependency named only when nothing else links the pair: the outputs it
// carries are then the only handoff.
func TestBlockBranchesNameTheFeedKinds(t *testing.T) {
	p := AttackPath{Jobs: []string{"w/build"}, Branches: []PathBranch{{
		Job: "w/build", Jobs: []string{"w/build", "w/release", "w/notify", "w/sign"},
		FeedsVia: map[string][]string{
			"w/release": {FeedArtifact, FeedCache, FeedOutput},
			"w/notify":  {FeedOutput},
			"w/sign":    {FeedArtifact, FeedOutput},
		},
	}}}
	got := blockBranches(p, nil)
	want := [][]string{{FeedArtifact, FeedCache}, {FeedOutput}, {FeedArtifact}}
	if len(got) != 1 || !reflect.DeepEqual(got[0].FedVia, want) {
		t.Errorf("branches = %+v, want FedVia %v", got, want)
	}
}
