package control

import (
	"slices"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// tokenJobSituation is one job holding a contents and packages write
// token from source ("declared" or "default"), on a public GitHub
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
	for source, want := range map[string]PathTier{"declared": TierCritical, "default": TierHigh} {
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
	paths := assemblePaths(findings, tokenJobSituation("default"))
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
	findings := []opaengine.Finding{
		finding("ISSUE-715", "ci/off", map[string]any{"uses": "o/off@v1"}),
		finding("ISSUE-715", "ci/live", map[string]any{"uses": "o/live@v1"}),
		finding("ISSUE-715", "ci/writer-off", map[string]any{"uses": "o/writer@v1"}),
		cacheFinding(),
	}
	paths := assemblePaths(findings, sit)
	for _, p := range paths {
		for _, j := range p.Jobs {
			if j == "ci/off" || j == "ci/fed-off" || j == "ci/writer-off" {
				t.Errorf("a dead job is on path %s: %v", p.Entry.Subject, p.Jobs)
			}
		}
		if slices.Contains(p.cacheWriters, "ci/writer-off") {
			t.Errorf("a dead job writes the cache: %v", p.cacheWriters)
		}
	}
	i := slices.IndexFunc(paths, func(p AttackPath) bool { return p.EntryKind == EntryMutableDependency })
	if i < 0 || paths[i].Entry.Subject != "o/live@v1" || len(paths[i].Reach.Secrets) != 0 || slices.ContainsFunc(paths[i+1:], func(p AttackPath) bool { return p.EntryKind == EntryMutableDependency }) {
		t.Errorf("want the live job's dependency path alone, with no secret, got %+v", paths)
	}
}
