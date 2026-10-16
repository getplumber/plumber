package control

import (
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// A cache writer is a job whose runs save where other runs read: its cache
// scopes hold the default branch (or any ref, a job without triggers). A
// save in a branch's, a pull request's or a tag's scope reaches no other
// kind of run, whatever trigger the job carries.
func TestACacheWriterNeedsTheDefaultBranchScope(t *testing.T) {
	for scopes, writes := range map[string]bool{"default": true, "any": true, "branch": false, "pull_request": false, "tag": false} {
		w := triageWriter
		w.CacheScopes = []string{scopes}
		sit := cacheSituation(map[string]JobSituation{"triage/label": w})
		findings := []opaengine.Finding{cacheFinding(), finding("ISSUE-701", "triage/label", map[string]any{"uses": "some/action@v1"})}
		if got := len(cachePaths(assemblePaths(findings, sit))) == 1; got != writes {
			t.Errorf("scope %s: cache path %v, want %v", scopes, got, writes)
		}
	}
}

// A job that never runs writes no cache, whatever its scopes.
func TestADeadJobWritesNoCache(t *testing.T) {
	w := triageWriter
	w.Dead = true
	sit := cacheSituation(map[string]JobSituation{"triage/label": w})
	findings := []opaengine.Finding{cacheFinding(), finding("ISSUE-701", "triage/label", map[string]any{"uses": "some/action@v1"})}
	if cache := cachePaths(assemblePaths(findings, sit)); len(cache) != 0 {
		t.Errorf("a dead job writes the cache: %+v", cache)
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
	component := opaengine.Finding{Code: string(CodeComponentUnauthorizedSource), Data: map[string]any{"componentPath": "gitlab.example.com/g/c/x", "occurrenceSeverity": "medium"}}
	if got := IndividualSeverity(component, "main"); got != SeverityMedium {
		t.Errorf("component: %s, want the occurrence's medium", got)
	}
	function := opaengine.Finding{Code: string(CodeFunctionUnauthorizedSource), Job: "build", Data: map[string]any{"link": "registry.example.com/g/fn:1.0", "occurrenceSeverity": "medium"}}
	if got := IndividualSeverity(function, "main"); got != SeverityMedium {
		t.Errorf("function: %s, want the occurrence's medium", got)
	}
}
