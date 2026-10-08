package control

import (
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// A cache writer is a job whose runs save where a release run reads: its
// cache scopes hold the default branch (or any ref, a job without
// triggers). A push to other branches only saves in a scope no release
// run reads, whatever trigger the job carries.
func TestACacheWriterNeedsTheDefaultBranchScope(t *testing.T) {
	for scopes, writes := range map[string]bool{"default": true, "any": true, "branch": false, "pull_request": false, "tag": false} {
		sit := cacheSituation(map[string]JobSituation{
			"ci/build": {RefTriggers: []string{"push"}, CacheScopes: []string{scopes}},
		})
		findings := []opaengine.Finding{cacheFinding(), finding("ISSUE-701", "ci/build", map[string]any{"uses": "some/action@v1"})}
		if got := len(cachePaths(assemblePaths(findings, sit))) == 1; got != writes {
			t.Errorf("scope %s: cache path %v, want %v", scopes, got, writes)
		}
	}
}

// A job that never runs writes no cache, whatever its scopes.
func TestADeadJobWritesNoCache(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{
		"ci/build": {RefTriggers: []string{"push"}, CacheScopes: []string{"default"}, Dead: true},
	})
	findings := []opaengine.Finding{cacheFinding(), finding("ISSUE-701", "ci/build", map[string]any{"uses": "some/action@v1"})}
	if cache := cachePaths(assemblePaths(findings, sit)); len(cache) != 0 {
		t.Errorf("a dead job writes the cache: %+v", cache)
	}
}

// The poisoned cache entry prints the cache's family, the key without the
// discriminators a caching action adds (a rust-cache job id, a setup
// action's dependency paths).
func TestThePoisonedCacheEntryPrintsTheFamily(t *testing.T) {
	cases := []struct {
		cache CacheFact
		f     opaengine.Finding
		want  string
	}{
		{CacheFact{Key: "${{ matrix.job.os }}-build-for-macOS", Family: "${{ matrix.job.os }}", Mode: "both", Prefix: true, Uses: "Swatinem/rust-cache@v2", Line: 22},
			rustCacheFinding("release"), "Rust build cache, key prefix ${{ matrix.job.os }}"},
		{CacheFact{Key: "setup-node-npm (package-lock.json)", Family: "setup-node-npm", Mode: "both", Uses: "actions/setup-node@v5", Line: 22},
			setupFinding("actions/setup-node@v5"), "npm cache of setup-node"},
		{CacheFact{Key: "v0-rust-build", Mode: "both", Prefix: true, Uses: "Swatinem/rust-cache@v2", Line: 22},
			rustCacheFinding("release"), "Rust build cache, key prefix v0-rust-build"},
	}
	for _, c := range cases {
		if got := cacheEntrySubject(c.f, []CacheFact{c.cache}); got != c.want {
			t.Errorf("%s: subject %q, want %q", c.cache.Key, got, c.want)
		}
	}
}

// An image the facts prove is the organization's own (every image the job
// resolves to under the owner's container registry namespace) reads as
// the organization's, whatever the reference spells.
func TestAnOwnImageFactMakesTheImageTheOrganizations(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": {OwnImage: true}}}
	f := opaengine.Finding{Code: string(CodeImageNotPinnedByDigest), Job: "ci/build", File: ".github/workflows/ci.yml", Line: 9, Data: map[string]any{"link": "ghcr.io/acme-builds/build:latest"}}
	paths := AssemblePaths([]opaengine.Finding{f}, sit, "electron/electron")
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	if b := NewPathBlock(paths[0], nil); !strings.Contains(b.Entry, "of your organization") {
		t.Errorf("entry %q", b.Entry)
	}
}

// An impact a called job performs for its caller reads as reached through
// that job, after what the caller holds itself.
func TestAnImpactThroughACalledJobReadsAsAHop(t *testing.T) {
	js := JobSituation{RefTriggers: []string{"push"},
		Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish", Via: "publish/npm"}}}
	js.Privilege.Secrets, js.Privilege.SecretsState = []string{"NPM_TOKEN"}, "proven"
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"release/call": js}}
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-701", "release/call", map[string]any{"uses": "o/a@v1"})}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	got := NewPathBlock(paths[0], nil).Branches[0].Reach
	if want := "1 secret and, through job `npm` from workflow `publish`, a step that publishes"; got != want {
		t.Errorf("reach %q, want %q", got, want)
	}
}

// The severity of a finding on no path is the one the policy gives the
// occurrence when it gives one, computed the same way otherwise.
func TestIndividualSeverityReadsTheOccurrenceSeverity(t *testing.T) {
	branch := opaengine.Finding{Code: string(CodeBranchUnprotected), Data: map[string]any{"branchName": "main", "occurrenceSeverity": "high"}}
	if got := IndividualSeverity(branch, "main"); got != SeverityHigh {
		t.Errorf("branch: %s, want the occurrence's high", got)
	}
	action := opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Data: map[string]any{"uses": "o/a@v1", "occurrenceSeverity": "medium"}}
	if got := IndividualSeverity(action, "main"); got != SeverityMedium {
		t.Errorf("action: %s, want the occurrence's medium", got)
	}
	odd := opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Data: map[string]any{"uses": "o/a@v1", "occurrenceSeverity": "severe"}}
	if got := IndividualSeverity(odd, "main"); got != SeverityHigh {
		t.Errorf("unknown occurrence severity: %s, want the computed high", got)
	}
}
