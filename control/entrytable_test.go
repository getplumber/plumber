package control

import (
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// Every code that anchors a path has a complete row: each entry-role code
// of the registry, the branch findings that anchor a push path, and the
// source codes that join a dependency path. A row never lacks its
// dependency kind, family, nature, actor or fix, and every row but a
// source code's has its phrase; its dependency kind and actor agree with
// the registry's entry kind; and no row is kept for a code that anchors
// nothing.
func TestEveryEntryCodeHasACompleteRow(t *testing.T) {
	kinds := map[ErrorCode]EntryKind{
		CodeBranchUnprotected:  EntryUnprotectedPush,
		CodeBranchNonCompliant: EntryUnprotectedPush,
	}
	for code, kind := range subjectFindingCodes {
		kinds[code] = kind
	}
	for code, info := range errorCodeRegistry {
		if info.Role == RoleEntry {
			kinds[code] = info.EntryKind
		}
	}
	for code, kind := range kinds {
		row, ok := entryCodes[code]
		if !ok {
			t.Errorf("%s anchors a path but has no row in entryCodes", code)
			continue
		}
		if row.dependency == 0 {
			t.Errorf("%s: no dependency kind", code)
		}
		if row.family == "" {
			t.Errorf("%s: no family", code)
		}
		if row.nature.base == "" {
			t.Errorf("%s: no nature", code)
		}
		if row.actor == 0 {
			t.Errorf("%s: no actor rule", code)
		}
		if row.fix == "" {
			t.Errorf("%s: no fix", code)
		}
		if dep := row.dependency != depNotADependency; dep != (kind == EntryMutableDependency) {
			t.Errorf("%s: dependency kind %d does not match entry kind %s", code, row.dependency, kind)
		}
		if want := kindActors[kind]; kind != EntryMutableDependency && row.actor != want {
			t.Errorf("%s: actor rule %d, its entry kind %s reads %d", code, row.actor, kind, want)
		}
	}
	for code := range entryCodes {
		if _, ok := kinds[code]; !ok {
			t.Errorf("%s has a row but anchors no path", code)
		}
	}
}

// When several codes anchor one entry, the Entry line's nature, the So
// line's actor, the fix and the merge request table entry all follow the
// same anchor, the most serious one: a dependency known bad, then one
// fetching code at run time, then a pinning code joined by a source code,
// then a pinning code alone. A source code joining an entry whose nature
// has an untrusted variant reads it in each of the four.
func TestTheBlockFollowsTheMostSeriousAnchor(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	action := map[string]any{"uses": "some/action@v1"}
	image := map[string]any{"link": "registry.example.com/tool:latest"}
	for _, tc := range []struct {
		codes              []string
		data               map[string]any
		nature, actor, fix string
	}{
		{[]string{"ISSUE-701"}, action,
			"mutable external action", "if this action is compromised",
			"pin the version on the commit SHA"},
		{[]string{"ISSUE-701", "ISSUE-713"}, action,
			"untrusted and mutable external action", "if this action is compromised or malicious",
			"use an action from a trusted source and pin the version on the commit SHA"},
		{[]string{"ISSUE-701", "ISSUE-714"}, action,
			"external action that downloads code at run time from a mutable source", "if this action is compromised",
			"pin what the action downloads, or vendor it"},
		{[]string{"ISSUE-701", "ISSUE-713", "ISSUE-714"}, action,
			"untrusted external action that downloads code at run time from a mutable source", "if this action is compromised or malicious",
			"use an action from a trusted source and pin what it downloads, or vendor it"},
		{[]string{"ISSUE-701", "ISSUE-713", "ISSUE-703"}, action,
			"external action with a known vulnerability", "through the known vulnerability of this action",
			"move to a version without the advisory"},
		{[]string{"ISSUE-102", "ISSUE-101"}, image,
			"untrusted and mutable image", "if this image is compromised or malicious",
			"use an image from a trusted registry and pin it by digest"},
	} {
		t.Run(strings.Join(tc.codes, "+"), func(t *testing.T) {
			var findings []opaengine.Finding
			for _, c := range tc.codes {
				findings = append(findings, finding(c, "release", tc.data))
			}
			paths := assemblePaths(findings, sit)
			if len(paths) != 1 {
				t.Fatalf("want one path, got %+v", paths)
			}
			b := NewPathBlock(paths[0], nil)
			if !strings.HasSuffix(b.Entry, " ("+tc.nature+")") {
				t.Errorf("Entry %q, want the nature %q", b.Entry, tc.nature)
			}
			if !strings.HasPrefix(b.So, tc.actor+", ") {
				t.Errorf("So %q, want the actor %q", b.So, tc.actor)
			}
			if b.Fix != tc.fix {
				t.Errorf("Fix %q, want %q", b.Fix, tc.fix)
			}
			if got := PathRowOf(paths[0]).Entry; got != b.Entry {
				t.Errorf("table entry %q, want the Entry line %q", got, b.Entry)
			}
		})
	}
}

// The best fix of a path reads the same sentence as the block's Fix line,
// the most serious anchor's (entryAnchor), never the fix of the code the
// path's identity is kept by: the summary line and the sentence alike.
func TestTheBestFixReadsTheBlockFix(t *testing.T) {
	uses := map[string]any{"uses": "some/action@v1"}
	var findings []opaengine.Finding
	for _, c := range []string{"ISSUE-701", "ISSUE-713", "ISSUE-714"} {
		findings = append(findings, finding(c, "release", uses))
	}
	result := &AnalysisResult{CiValid: true, Findings: findings, Situation: releaseSituation(ir.VisibilityPublic)}
	score := ScoreV4WithExplanations(result)
	if len(score.Paths) != 1 || score.BestFix == nil || score.BestFix.PathID != score.Paths[0].ID {
		t.Fatalf("want the one path as the best fix, got %+v / %+v", score.Paths, score.BestFix)
	}
	const want = "use an action from a trusted source and pin what it downloads, or vendor it"
	if fix := NewPathBlock(score.Paths[0], nil).Fix; fix != want {
		t.Fatalf("block Fix %q, want %q", fix, want)
	}
	if got := BestFixSummary(&score); !strings.HasPrefix(got, want+" (") {
		t.Errorf("best fix line %q, want it to open on %q", got, want)
	}
	if got, sentence := score.BestFix.Sentence, "Fixing the path through `some/action@v1` ("+want+") recovers"; !strings.HasPrefix(got, sentence) {
		t.Errorf("best fix sentence %q, want it to open on %q", got, sentence)
	}
}

// A dependency's Entry line and its So line read one trust: a trusted
// dependency can only be compromised, an untrusted one can also be
// malicious, and what makes either compromisable is that what runs can
// change (a pinning code, a run-time fetch, a reference computed at run
// time). Trust and mutability come from dependencyTrust alone, so the
// nature's untrusted variant and the actor never disagree. A known
// vulnerability, a commit outside the repository and a hidden fetch name
// the way in instead.
func TestTheEntryAndTheSoLineReadOneTrust(t *testing.T) {
	const sha = "@1c9b1f1aaa2222bbbb3333cccc4444dddd5555ee"
	digest := "evil.io/node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	computed := wordingPath(EntryMutableDependency, "${{ matrix.ref }}", CodeActionUnauthorizedSource)
	computed.Entry.State = "unresolvable"
	cases := []struct {
		name          string
		p             AttackPath
		nature, actor string
	}{
		{"701", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned),
			"mutable external action", "if this action is compromised"},
		{"701+713", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionUnpinned, CodeActionUnauthorizedSource),
			"untrusted and mutable external action", "if this action is compromised or malicious"},
		{"713", wordingPath(EntryMutableDependency, "o/a"+sha, CodeActionUnauthorizedSource),
			"untrusted external action", "if this action is malicious"},
		{"713 computed at run time", computed,
			"action computed at run time", "if this action is compromised or malicious"},
		{"714", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionMutableRemoteExec, CodeActionUnpinned),
			"external action that downloads code at run time from a mutable source", "if this action is compromised"},
		{"714+713", wordingPath(EntryMutableDependency, "o/a@v1", CodeActionMutableRemoteExec, CodeActionUnauthorizedSource),
			"untrusted external action that downloads code at run time from a mutable source", "if this action is compromised or malicious"},
		{"716", wordingPath(EntryMutableDependency, "o/a"+sha, CodeActionRemoteExecUnverified),
			"external action that downloads code at run time Plumber could not check", "if this action is compromised"},
		{"102", wordingPath(EntryMutableDependency, "node:latest", CodeImageForbiddenTag),
			"mutable image tag", "if this image is compromised"},
		{"102+101", wordingPath(EntryMutableDependency, "evil.io/node:latest", CodeImageForbiddenTag, CodeImageUnauthorizedSource),
			"untrusted and mutable image", "if this image is compromised or malicious"},
		{"101", wordingPath(EntryMutableDependency, digest, CodeImageUnauthorizedSource),
			"untrusted image", "if this image is malicious"},
		{"404", wordingPath(EntryMutableDependency, "group/templates@main", CodeIncludeForbiddenVersion),
			"mutable external include", "if this include is compromised"},
		{"411", wordingPath(EntryMutableDependency, "https://get.example.com/install.sh", CodeUnverifiedScriptExecution),
			"script downloaded and run at build time", "if this script is compromised or malicious"},
		{"703", wordingPath(EntryMutableDependency, "o/a@v1", CodeKnownVulnerableAction),
			"external action with a known vulnerability", "through the known vulnerability of this action"},
		{"707", wordingPath(EntryMutableDependency, "o/a"+sha, CodeImpostorCommit),
			"external action pinned to a commit that is not in its repository", "through the commit this action is pinned to, which is not in its repository"},
		{"715", wordingPath(EntryMutableDependency, "o/a"+sha, CodeActionObfuscatedRemoteExec),
			"external action that downloads obfuscated code at run time", "through the code fetch this action hides"},
		{"715+713", wordingPath(EntryMutableDependency, "o/a"+sha, CodeActionObfuscatedRemoteExec, CodeActionUnauthorizedSource),
			"untrusted external action that downloads obfuscated code at run time", "through the code fetch this action hides"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if strings.HasPrefix(c.p.Entry.Subject, "group/") {
				c.p.Entry.File = ".gitlab-ci.yml"
			}
			b := NewPathBlock(c.p, nil)
			if !strings.HasSuffix(b.Entry, " ("+c.nature+")") {
				t.Errorf("Entry %q, want the nature %q", b.Entry, c.nature)
			}
			if !strings.HasPrefix(b.So, c.actor+", ") {
				t.Errorf("So %q, want the actor %q", b.So, c.actor)
			}
		})
	}
}

// A dependency both trusted and immutable has nothing that can turn it
// against the pipeline, so no code anchors a path on one: every code whose
// entry reads its actor off the dependency's trust says, alone, that the
// dependency is untrusted or that what runs can change.
func TestATrustedImmutableDependencyAnchorsNoPath(t *testing.T) {
	const sha = "@1c9b1f1aaa2222bbbb3333cccc4444dddd5555ee"
	for code, words := range entryCodes {
		if words.actor != actorDependency {
			continue
		}
		trusted, mutable := dependencyTrust(wordingPath(EntryMutableDependency, "o/a"+sha, code))
		if trusted && !mutable {
			t.Errorf("%s alone reads as a trusted, immutable dependency", code)
		}
	}
	if kindActors[EntryMutableDependency] != actorDependency {
		t.Errorf("a dependency path of a code with no words reads actor %d, want the dependency rule", kindActors[EntryMutableDependency])
	}
}
