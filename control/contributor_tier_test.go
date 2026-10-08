package control

import (
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// prTargetJob is a pull_request_target job holding the secrets and the
// write scopes given, on a public GitHub repository.
func prTargetJob(secrets, scopes []string) *Situation {
	js := JobSituation{PrivilegedTriggers: []string{"pull_request_target"}, CacheScopes: defaultScope}
	js.Privilege.Secrets, js.Privilege.SecretsState = secrets, "proven"
	js.Privilege.TokenWrite = scopes
	if len(scopes) > 0 {
		js.Privilege.TokenWriteSource = "declared"
	}
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"pr/triage": js}}
}

// A contributor entry is Critical with a privilege alone: anyone opening a
// pull request holds a secret or a write token, the OIDC token included.
// Code execution alone stays High.
func TestAContributorEntryIsCriticalWithAPrivilegeAlone(t *testing.T) {
	cases := []struct {
		name    string
		sit     *Situation
		f       opaengine.Finding
		want    PathTier
		wantMod bool
	}{
		{"checkout with a secret", prTargetJob([]string{"API_KEY"}, nil), entryFinding("ISSUE-804", "pr/triage", "github.event.pull_request.head.sha"), TierCritical, false},
		{"checkout with the OIDC token", prTargetJob(nil, []string{"id-token"}), entryFinding("ISSUE-804", "pr/triage", "github.event.pull_request.head.sha"), TierCritical, false},
		{"checkout with a write token", prTargetJob(nil, []string{"issues"}), entryFinding("ISSUE-804", "pr/triage", "github.event.pull_request.head.sha"), TierCritical, false},
		{"injection with a secret", prTargetJob([]string{"API_KEY"}, nil), entryFinding("ISSUE-207", "pr/triage", "github.event.pull_request.title"), TierCritical, false},
		{"checkout and nothing else", prTargetJob(nil, nil), entryFinding("ISSUE-804", "pr/triage", "github.event.pull_request.head.sha"), TierHigh, false},
	}
	for _, c := range cases {
		paths := assemblePaths([]opaengine.Finding{c.f}, c.sit)
		if len(paths) != 1 || paths[0].Tier != c.want {
			t.Errorf("%s: want one %s path, got %+v", c.name, c.want, paths)
		}
	}
}

// A dependency entry keeps the privilege-and-impact test: a secret alone
// is High, whatever the trigger.
func TestADependencyEntryNeedsAnImpactToBeCritical(t *testing.T) {
	f := finding("ISSUE-715", "pr/triage", map[string]any{"uses": "o/a@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, prTargetJob([]string{"API_KEY"}, nil))
	if len(paths) != 1 || paths[0].Tier != TierHigh {
		t.Errorf("want one High path, got %+v", paths)
	}
}

// An expression only an insider sets stays capped at High, a privilege
// or not.
func TestAnInsiderExpressionStaysCappedAtHigh(t *testing.T) {
	js := JobSituation{RefTriggers: []string{"workflow_dispatch"}, CacheScopes: defaultScope}
	js.Privilege.Secrets, js.Privilege.SecretsState = []string{"API_KEY"}, "proven"
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/run": js}}
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "ci/run", "inputs.name")}, sit)
	if len(paths) != 1 || paths[0].Tier != TierHigh {
		t.Errorf("want one High path, got %+v", paths)
	}
}
