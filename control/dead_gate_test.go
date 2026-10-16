package control

import (
	"slices"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// tokenJobSituation is one job holding a contents and packages write
// token from source ("declared" or "unknown"), on a public GitHub
// repository whose default branch is main.
func tokenJobSituation(source string) *Situation {
	js := JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope}
	js.Privilege.SecretsState = "proven"
	js.Privilege.TokenWrite, js.Privilege.TokenWriteSource = []string{"contents", "packages"}, source
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", DefaultBranch: "main", Jobs: map[string]JobSituation{"links/check": js}}
}

// A missing branch protection raises a path only when the path really
// writes the repository: a declared contents write does, the repository's
// default token, assumed, does not.
func TestABranchGateNeedsARealRepositoryWrite(t *testing.T) {
	findings := []opaengine.Finding{
		finding("ISSUE-715", "links/check", map[string]any{"uses": "lycheeverse/lychee-action@v1.4.1"}),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	for source, want := range map[string]PathTier{"declared": TierCritical, "unknown": TierHigh} {
		var dep *AttackPath
		paths := assemblePaths(findings, tokenJobSituation(source))
		for i := range paths {
			if paths[i].EntryKind == EntryMutableDependency {
				dep = &paths[i]
			}
		}
		if dep == nil || dep.Tier != want {
			t.Errorf("%s token: want the dependency path %s, got %+v", source, want, dep)
			continue
		}
		if raised := slices.Contains(dep.Modifiers, "gate:ISSUE-501"); raised != (source == "declared") {
			t.Errorf("%s token: gate modifier %v, modifiers %v", source, raised, dep.Modifiers)
		}
	}
}

// A job-scoped gate never raises a path on an assumed default token alone.
func TestAJobGateNeverRaisesOnAnAssumedTokenAlone(t *testing.T) {
	findings := []opaengine.Finding{
		finding("ISSUE-715", "links/check", map[string]any{"uses": "o/a@v1"}),
		finding("ISSUE-305", "links/check", nil),
	}
	paths := assemblePaths(findings, tokenJobSituation("unknown"))
	if len(paths) != 1 || paths[0].Tier != TierHigh || len(paths[0].GateHashes) != 0 {
		t.Errorf("want one High path no gate raised, got %+v", paths)
	}
}

// A job that never runs (a constant false condition) is no branch, no
// walked job and no cache writer.
func TestADeadJobIsNoBranchNoWalkAndNoWriter(t *testing.T) {
	live := JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope, Feeds: []string{"ci/fed-off"}}
	fedOff := JobSituation{Dead: true}
	fedOff.Privilege.Secrets, fedOff.Privilege.SecretsState = []string{"S"}, "proven"
	sit := cacheSituation(map[string]JobSituation{
		"ci/off": {RefTriggers: []string{"push"}, CacheScopes: defaultScope, Dead: true}, "ci/live": live, "ci/fed-off": fedOff,
		"ci/writer-off": {RefTriggers: []string{"push"}, CacheScopes: defaultScope, Dead: true},
	})
	deadWriter := cacheFinding()
	deadWriter.Job, deadWriter.Subject = "ci/writer-off", "ci/writer-off"
	findings := []opaengine.Finding{
		finding("ISSUE-715", "ci/off", map[string]any{"uses": "o/off@v1"}),
		finding("ISSUE-715", "ci/live", map[string]any{"uses": "o/live@v1"}),
		finding("ISSUE-715", "ci/writer-off", map[string]any{"uses": "o/writer@v1"}),
		deadWriter,
	}
	paths := assemblePaths(findings, sit)
	for _, p := range paths {
		for _, j := range p.Jobs {
			if j == "ci/off" || j == "ci/fed-off" || j == "ci/writer-off" {
				t.Errorf("a dead job is on path %s: %v", p.Entry.Subject, p.Jobs)
			}
		}
		if p.EntryKind == EntryPoisonedCache {
			t.Errorf("a dead job writes the cache: %v", p.Jobs)
		}
	}
	i := slices.IndexFunc(paths, func(p AttackPath) bool { return p.EntryKind == EntryMutableDependency })
	if i < 0 || paths[i].Entry.Subject != "o/live@v1" || len(paths[i].Reach.Secrets) != 0 || slices.ContainsFunc(paths[i+1:], func(p AttackPath) bool { return p.EntryKind == EntryMutableDependency }) {
		t.Errorf("want the live job's dependency path alone, with no secret, got %+v", paths)
	}
}

// A job that cannot run (JobSituation.Inert set, a workflow disabled, a
// retired runner, a trigger that never fires) is no branch, no walked job
// and no cache writer either, the same contract a constant false if:
// (Dead) already holds. Dead is also set on every inert job here: once
// the situation module is correct (inert_reason(group) only ever fires
// when every job of the name is inert), Inert is never set without Dead
// alongside it, which is the shape liveSituation now relies on.
func TestAnInertJobIsNoBranchNoWalkAndNoWriter(t *testing.T) {
	live := JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope, Feeds: []string{"ci/fed-off"}}
	fedOff := JobSituation{Dead: true, Inert: "no trigger"}
	fedOff.Privilege.Secrets, fedOff.Privilege.SecretsState = []string{"S"}, "proven"
	sit := cacheSituation(map[string]JobSituation{
		"ci/off": {RefTriggers: []string{"push"}, CacheScopes: defaultScope, Dead: true, Inert: "actions disabled"}, "ci/live": live, "ci/fed-off": fedOff,
		"ci/writer-off": {RefTriggers: []string{"push"}, CacheScopes: defaultScope, Dead: true, Inert: "runner label retired (ubuntu-20.04)"},
	})
	inertWriter := cacheFinding()
	inertWriter.Job, inertWriter.Subject = "ci/writer-off", "ci/writer-off"
	findings := []opaengine.Finding{
		finding("ISSUE-715", "ci/off", map[string]any{"uses": "o/off@v1"}),
		finding("ISSUE-715", "ci/live", map[string]any{"uses": "o/live@v1"}),
		finding("ISSUE-715", "ci/writer-off", map[string]any{"uses": "o/writer@v1"}),
		inertWriter,
	}
	paths := assemblePaths(findings, sit)
	for _, p := range paths {
		for _, j := range p.Jobs {
			if j == "ci/off" || j == "ci/fed-off" || j == "ci/writer-off" {
				t.Errorf("an inert job is on path %s: %v", p.Entry.Subject, p.Jobs)
			}
		}
		if p.EntryKind == EntryPoisonedCache {
			t.Errorf("an inert job writes the cache: %v", p.Jobs)
		}
	}
	i := slices.IndexFunc(paths, func(p AttackPath) bool { return p.EntryKind == EntryMutableDependency })
	if i < 0 || paths[i].Entry.Subject != "o/live@v1" || len(paths[i].Reach.Secrets) != 0 || slices.ContainsFunc(paths[i+1:], func(p AttackPath) bool { return p.EntryKind == EntryMutableDependency }) {
		t.Errorf("want the live job's dependency path alone, with no secret, got %+v", paths)
	}
}

// Dead alone decides whether liveSituation drops a job; Inert is a
// display-only reason and must never gate it on its own. This pins the
// shape a buggy situation module could still hand liveSituation (Dead
// false, Inert carrying a stale or leaked reason from a mixed group of
// same-named jobs, one inert and one live): the job must still produce
// a path, because Dead false means something in the group can run.
func TestALiveJobIsNeverDroppedByInertAlone(t *testing.T) {
	js := JobSituation{Dead: false, Inert: "no trigger", RefTriggers: []string{"push"}, CacheScopes: defaultScope}
	sit := cacheSituation(map[string]JobSituation{"ci/build": js})
	findings := []opaengine.Finding{
		finding("ISSUE-715", "ci/build", map[string]any{"uses": "o/build@v1"}),
	}
	paths := assemblePaths(findings, sit)
	i2 := slices.IndexFunc(paths, func(p AttackPath) bool {
		return p.EntryKind == EntryMutableDependency && p.Entry.Subject == "o/build@v1"
	})
	if i2 < 0 {
		t.Fatalf("a job with Dead=false must still produce a path even when Inert carries a reason, got %+v", paths)
	}
}
