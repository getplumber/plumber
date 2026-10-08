package control

import (
	"strings"
	"testing"
)

// A reach fills its line as far as the width allows and breaks at the last
// boundary that fits (after ", ", before " and " or before a parenthesis),
// never inside a parenthesised phrase and never between a token's verbs;
// its continuation lines sit under the first word after "reaches".
func TestReachWrapsAtTheLastBoundaryThatFits(t *testing.T) {
	reach := "2 secrets and a token with push and publish access (assumed: no permissions block)"
	b := PathBlock{Tier: TierHigh, Branches: []PathBlockBranch{{Job: "job `monitor-issues` from workflow `monitor-new-issues.yml` (on schedule)", Reach: reach}}}
	got := ReportPathGraph(2, b, 100)[2:5]
	want := []string{
		"       └──▶ runs in job `monitor-issues` from workflow `monitor-new-issues.yml` (on schedule)",
		"            └─▶ reaches 2 secrets and a token with push and publish access",
		"                        (assumed: no permissions block)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("branch:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range got {
		if strings.HasSuffix(l, " push") || strings.HasSuffix(l, " push,") {
			t.Errorf("a line breaks between the token's verbs: %q", l)
		}
	}
	cases := []struct {
		reach string
		width int
		want  []string
	}{
		{"every secret of the repository and a token with push, publish and deploy access", 77,
			[]string{"every secret of the repository", "and a token with push, publish and deploy access"}},
		{"2 secrets, a token with push and publish access (assumed: no permissions block) and a step that releases", 77,
			[]string{"2 secrets, a token with push and publish access", "(assumed: no permissions block) and a step that releases"}},
		{"a token with push, publish and deploy access (assumed: no permissions block)", 50,
			[]string{"a token with push, publish and deploy access", "(assumed: no permissions block)"}},
		{"a token with write access to security events and an OIDC token", 50,
			[]string{"a token with write access to security events", "and an OIDC token"}},
		{"code execution on the runner, no secret and no write token", 38,
			[]string{"code execution on the runner,", "no secret and no write token"}},
	}
	for _, c := range cases {
		if got := wrapReach(c.reach, c.width); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("wrapReach(%q, %d) = %q, want %q", c.reach, c.width, got, c.want)
		}
	}
}

// The So line fills its line as far as the width allows and breaks at the
// last phrase boundary that fits, never inside a code span.
func TestSoLineWrapsAtTheLastBoundaryThatFits(t *testing.T) {
	b := PathBlock{Tier: TierHigh, So: "as anyone with write access to `main`, an attacker can execute code to write to security events and request an OIDC token"}
	got := ReportPathGraph(1, b, 100)
	want := []string{
		"       So     as anyone with write access to `main`,",
		"              an attacker can execute code to write to security events and request an OIDC token",
	}
	if strings.Join(got[2:], "\n") != strings.Join(want, "\n") {
		t.Errorf("so:\n%s\nwant:\n%s", strings.Join(got[2:], "\n"), strings.Join(want, "\n"))
	}
}

// Who gets in through a dependency follows its trust and its mutability:
// untrusted and mutable (a pinning code and a source code) is compromised
// or malicious, untrusted and immutable (a source code alone) malicious,
// trusted and mutable (a pinning code alone, or an action fetching code at
// run time from a trusted owner) compromised; a script, never trusted, is
// compromised or malicious; an image in a GitHub workflow, whose source no
// control checks, is compromised or malicious too; a known vulnerability,
// a commit outside the repository and a hidden fetch name the way in.
func TestSoActorFollowsTrustAndMutability(t *testing.T) {
	const sha = "@1c9b1f1aaa2222bbbb3333cccc4444dddd5555ee"
	reusable := "o/r/.github/workflows/d.yml"
	digest := "evil.io/node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name    string
		subject string
		codes   []ErrorCode
		want    string
	}{
		{"action 701+713", "o/a@v1", []ErrorCode{CodeActionUnpinned, CodeActionUnauthorizedSource}, "if this action is compromised or malicious"},
		{"action 713", "o/a" + sha, []ErrorCode{CodeActionUnauthorizedSource}, "if this action is malicious"},
		{"action 701", "o/a@v1", []ErrorCode{CodeActionUnpinned}, "if this action is compromised"},
		{"reusable 701+713", reusable + "@main", []ErrorCode{CodeActionUnpinned, CodeActionUnauthorizedSource}, "if this reusable workflow is compromised or malicious"},
		{"reusable 713", reusable + sha, []ErrorCode{CodeActionUnauthorizedSource}, "if this reusable workflow is malicious"},
		{"reusable 402", reusable + "@v1", []ErrorCode{CodeRefConfusion}, "if this reusable workflow is compromised"},
		{"image 102+101", "evil.io/node:latest", []ErrorCode{CodeImageForbiddenTag, CodeImageUnauthorizedSource}, "if this image is compromised or malicious"},
		{"image 103+101", "evil.io/node:20", []ErrorCode{CodeImageNotPinnedByDigest, CodeImageUnauthorizedSource}, "if this image is compromised or malicious"},
		{"image 101", digest, []ErrorCode{CodeImageUnauthorizedSource}, "if this image is malicious"},
		{"image 103 on GitHub", "node:20", []ErrorCode{CodeImageNotPinnedByDigest}, "if this image is compromised or malicious"},
		{"include 404", "group/templates@main", []ErrorCode{CodeIncludeForbiddenVersion}, "if this include is compromised"},
		{"include 402", "group/templates@v1", []ErrorCode{CodeRefConfusion}, "if this include is compromised"},
		{"script 411", "https://x/i.sh", []ErrorCode{CodeUnverifiedScriptExecution}, "if this script is compromised or malicious"},
		{"action 714", "o/a" + sha, []ErrorCode{CodeActionMutableRemoteExec}, "if this action is compromised"},
		{"action 715", "o/a" + sha, []ErrorCode{CodeActionObfuscatedRemoteExec}, "through the code fetch this action hides"},
		{"action 716", "o/a" + sha, []ErrorCode{CodeActionRemoteExecUnverified}, "if this action is compromised"},
		{"action 703", "o/a@v1", []ErrorCode{CodeKnownVulnerableAction, CodeActionUnpinned}, "through the known vulnerability of this action"},
		{"action 707", "o/a" + sha, []ErrorCode{CodeImpostorCommit}, "through the commit this action is pinned to, which is not in its repository"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := wordingPath(EntryMutableDependency, c.subject, c.codes...)
			p.Entry.File = ".github/workflows/ci.yml"
			if strings.HasPrefix(c.subject, "group/") {
				p.Entry.File = ".gitlab-ci.yml"
			}
			want := c.want + ", an attacker can execute code on the runner and poison what it caches or uploads"
			if got := NewPathBlock(p, nil).So; got != want {
				t.Errorf("so = %q\nwant %q", got, want)
			}
		})
	}
}

// A dependency of the analysed repository's own owner is no external one:
// its nature says so, and it is trusted, so only a compromise gets in.
func TestADependencyOfYourOrganizationIsTrusted(t *testing.T) {
	own := func(subject string, codes ...ErrorCode) AttackPath {
		p := wordingPath(EntryMutableDependency, subject, codes...)
		p.ownRepo = "comfy-org/comfyui"
		return p
	}
	cases := []struct {
		name, nature, actor string
		p                   AttackPath
	}{
		{"action", "mutable action of your organization", "if this action is compromised", own("comfy-org/comfy-action@main", CodeActionUnpinned)},
		{"reusable workflow", "mutable reusable workflow of your organization", "if this reusable workflow is compromised", own("Comfy-Org/workflows/.github/workflows/ci.yml@main", CodeActionUnpinned)},
		{"image", "mutable image tag of your organization", "if this image is compromised", own("ghcr.io/comfy-org/runner:latest", CodeImageForbiddenTag)},
		{"pinned action", "action of your organization with a known vulnerability", "through the known vulnerability of this action", own("comfy-org/comfy-action@v1", CodeKnownVulnerableAction)},
		{"other owner", "mutable external action", "if this action is compromised", own("other/comfy-action@main", CodeActionUnpinned)},
		{"docker hub image", "mutable image tag", "if this image is compromised", own("node:latest", CodeImageForbiddenTag)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := NewPathBlock(c.p, nil)
			if want := c.p.Entry.Subject + " (" + c.nature + ")"; b.Entry != want {
				t.Errorf("entry = %q, want %q", b.Entry, want)
			}
			if !strings.HasPrefix(b.So, c.actor+", an attacker ") {
				t.Errorf("so = %q, want it to open on %q", b.So, c.actor)
			}
		})
	}
}

// The cache Note names the jobs that can write the cache the way a branch
// names its job, grouped by workflow: the first three, then how many more.
func TestCacheWriterLineGroupsTheJobsByWorkflow(t *testing.T) {
	files := map[string]string{
		"build/": ".github/workflows/build.yml", "ci/": ".github/workflows/ci.yml",
	}
	cases := []struct {
		writers []string
		want    string
	}{
		{[]string{"build/release-notes", "build/security-scan", "ci/auto-approve", "ci/build", "ci/lint", "dangerous/comment", "plumber/scan", "pr-preview/preview"},
			"runs of jobs `release-notes` and `security-scan` from workflow `build.yml`, `auto-approve` from workflow `ci.yml` and 5 more can write the cache"},
		{[]string{"build/release-notes", "ci/auto-approve"},
			"runs of jobs `release-notes` from workflow `build.yml` and `auto-approve` from workflow `ci.yml` can write the cache"},
		{[]string{"ci/build", "ci/lint"}, "runs of jobs `build` and `lint` from workflow `ci.yml` can write the cache"},
		{[]string{"pr-preview/preview"}, "a run of job `preview` from workflow `pr-preview` can write the cache"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := cacheWriterLine(c.writers, files, true); got != c.want {
			t.Errorf("cacheWriterLine(%v) =\n%q\nwant\n%q", c.writers, got, c.want)
		}
	}
	if got := cacheWriterLine([]string{"build", "lint"}, nil, false); got != "runs of jobs `build` and `lint` can write the cache" {
		t.Errorf("gitlab = %q", got)
	}
}
