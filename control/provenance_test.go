package control

import (
	"slices"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// tauriLikeSituation is a test job declaring `contents: read` and holding
// no secret, whose cache a release job restores; the release job holds a
// secret, a declared contents write and publishes.
func tauriLikeSituation() *Situation {
	test := JobSituation{RefTriggers: []string{"workflow_dispatch"}, CacheScopes: defaultScope, Feeds: []string{"publish-cli-js/publish"},
		FeedsVia: map[string][]string{"publish-cli-js/publish": {FeedCache}}}
	test.Privilege.SecretsState, test.Privilege.TokenWriteSource = "proven", "declared"
	publish := JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope, Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
	publish.Privilege.Secrets, publish.Privilege.SecretsState = []string{"NPM_TOKEN"}, "proven"
	publish.Privilege.TokenWrite, publish.Privilege.TokenWriteSource = []string{"contents"}, "declared"
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{
		"test-android/test": test, "publish-cli-js/publish": publish,
	}}
}

// autogptLikeSituation is a test job declaring `contents: read` with two
// secrets, fed into a benchmark job with no permissions block holding one
// more secret and the repository's default token.
func autogptLikeSituation() *Situation {
	test := JobSituation{Feeds: []string{"classic-benchmark-ci/benchmark-tests"},
		FeedsVia: map[string][]string{"classic-benchmark-ci/benchmark-tests": {FeedArtifact}}, RefTriggers: []string{"push"}, CacheScopes: defaultScope}
	test.Privilege.Secrets, test.Privilege.SecretsState, test.Privilege.TokenWriteSource = []string{"A", "B"}, "proven", "declared"
	bench := JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope}
	bench.Privilege.Secrets, bench.Privilege.SecretsState = []string{"C"}, "proven"
	bench.Privilege.TokenWrite, bench.Privilege.TokenWriteSource = []string{"contents", "packages"}, "default"
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{
		"classic-autogpt-ci/test": test, "classic-benchmark-ci/benchmark-tests": bench,
	}}
}

// A branch reads what its entry job holds first, then what it reaches
// through a job it feeds, named (with its workflow when it is another
// one's): a read-only test job never reads as holding the release job's
// secret and token.
func TestABranchNamesTheJobAHopAcquiredItemComesThrough(t *testing.T) {
	f := finding("ISSUE-701", "test-android/test", map[string]any{"uses": "dtolnay/rust-toolchain@1.90"})
	paths := assemblePaths([]opaengine.Finding{f}, tauriLikeSituation())
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	b := NewPathBlock(paths[0], nil)
	if got, want := b.Branches[0].Reach, "through job `publish` from workflow `publish-cli-js`, 1 secret, a token with push access and a step that publishes"; got != want {
		t.Errorf("reach %q, want %q", got, want)
	}
}

// A hop into a job of the same workflow names the job alone.
func TestAHopWithinTheWorkflowNamesTheJob(t *testing.T) {
	sit := tauriLikeSituation()
	test := sit.Jobs["test-android/test"]
	test.Feeds, test.FeedsVia = []string{"publish-cli-js/publish"}, map[string][]string{"publish-cli-js/publish": {FeedCache}}
	sit.Jobs["publish-cli-js/test"] = test
	delete(sit.Jobs, "test-android/test")
	f := finding("ISSUE-701", "publish-cli-js/test", map[string]any{"uses": "dtolnay/rust-toolchain@1.90"})
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if got, want := NewPathBlock(paths[0], nil).Branches[0].Reach, "through job `publish`, 1 secret, a token with push access and a step that publishes"; got != want {
		t.Errorf("reach %q, want %q", got, want)
	}
}

// The assumed marker stays on the token it is about, whatever the entry
// job holds itself; the Note says the token could not be checked, and the
// So line says what the token may do.
func TestTheAssumedMarkerStaysOnAHopAcquiredToken(t *testing.T) {
	f := finding("ISSUE-701", "classic-autogpt-ci/test", map[string]any{"uses": "codecov/test-results-action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, autogptLikeSituation())
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	b := NewPathBlock(paths[0], nil)
	if got, want := b.Branches[0].Reach, "2 secrets and, through job `benchmark-tests` from workflow `classic-benchmark-ci`, 1 secret and a token with push and publish access (assumed: no permissions block)"; got != want {
		t.Errorf("reach %q, want %q", got, want)
	}
	if !slices.Contains(b.Notes(), defaultTokenUnchecked) {
		t.Errorf("notes %q lack the token note", b.Notes())
	}
	if !strings.Contains(b.So, "an attacker can read 3 secrets") || !strings.HasSuffix(b.So, " and may push in your repository and publish packages") {
		t.Errorf("so %q", b.So)
	}
}

// A capability resting only on an assumed token reads "may".
func TestACapabilityOnAnAssumedTokenAloneReadsMay(t *testing.T) {
	js := JobSituation{}
	js.Privilege.SecretsState = "proven"
	js.Privilege.TokenWrite, js.Privilege.TokenWriteSource = []string{"contents"}, "default"
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": js}}
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-714", "ci/build", map[string]any{"uses": "o/a@v1"})}, sit)
	if so := NewPathBlock(paths[0], nil).So; !strings.HasSuffix(so, "an attacker may execute code to push in your repository") {
		t.Errorf("so %q", so)
	}
}

// Every write scope prints, and the OIDC token beside the verbs.
func TestEveryWriteScopeAndTheOIDCTokenPrint(t *testing.T) {
	cases := []struct {
		scopes []string
		want   string
	}{
		{[]string{"discussions", "issues", "pull-requests"}, "a token with write access to discussions, issues and pull requests"},
		{[]string{"contents", "id-token", "issues"}, "a token with push access and write access to issues and an OIDC token"},
		{[]string{"id-token", "packages"}, "a token with publish access and an OIDC token"},
	}
	for _, c := range cases {
		r := Reach{TokenWrite: c.scopes, Executes: true}
		if got := reachFragment(r, "", nil); got != c.want {
			t.Errorf("%v: %q, want %q", c.scopes, got, c.want)
		}
	}
}
