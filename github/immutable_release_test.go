package github

import (
	"net/http"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// immutableWorld is docker/build-push-action with a tag v7.4.0, a branch
// main, and release as the release of v7.4.0 (nil: none).
func immutableWorld(release *bool) map[string]*fakeRepo {
	refs := map[string]refFacts{
		"v7.4.0": {tag: commitObj(shaA), release: release},
		"main":   {branch: true, objectChecked: true, object: commitObj(shaB)},
	}
	return map[string]*fakeRepo{
		"docker/build-push-action": {refs: refs},
		"octo/shared":              {refs: refs},
	}
}

// Test_resolveUncached_immutableRelease pins the ISSUE-701 exemption
// signal (#421): a tag is reported as backed by an immutable release
// ONLY when the release for that exact tag says immutable=true. A
// missing release (a floating major such as v7) and a mutable one leave
// it false, so the ref keeps being flagged (fail-closed). A branch ref is
// never exempt, whatever a release of the same name says.
func Test_resolveUncached_immutableRelease(t *testing.T) {
	cases := []struct {
		name    string
		ref     string
		release *bool
		want    bool
	}{
		{"immutable release", "v7.4.0", ptr(true), true},
		{"mutable release", "v7.4.0", ptr(false), false},
		{"tag without a release", "v7.4.0", nil, false},
		{"branch ref is never exempt", "main", ptr(true), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := worldClient(t, immutableWorld(tc.release))
			m := c.resolveUncached("docker", "build-push-action", tc.ref)
			if m.RefIsImmutableRelease != tc.want {
				t.Fatalf("RefIsImmutableRelease = %v, want %v", m.RefIsImmutableRelease, tc.want)
			}
			if d := c.DegradedChecks(); len(d) != 0 {
				t.Fatalf("degraded = %q, want none", d)
			}
		})
	}
}

// Test_resolveUncached_immutableReleaseOnEnterprise: GitHub Enterprise
// Server's schema may lack Release.immutable, so the flag is read over
// REST there. A 404 (no release) is a definitive "no"; any other failure
// is fail-closed and reported.
func Test_resolveUncached_immutableReleaseOnEnterprise(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		body         string
		want         bool
		wantDegraded bool
	}{
		{"immutable release", http.StatusOK, `{"tag_name":"v7.4.0","immutable":true}`, true, false},
		{"release predating the flag", http.StatusOK, `{"tag_name":"v7.4.0"}`, false, false},
		{"tag without a release", http.StatusNotFound, `{"message":"Not Found"}`, false, false},
		{"failed lookup is fail-closed and reported", http.StatusInternalServerError, `{"message":"boom"}`, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rest := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
				if strings.HasSuffix(r.URL.Path, "/repos/docker/build-push-action/releases/tags/v7.4.0") {
					return tc.body, tc.status
				}
				if r.URL.Path == "/advisories" { // GHES reads advisories over REST too
					return `[]`, http.StatusOK
				}
				t.Errorf("unexpected REST request %s", r.URL.Path)
				return `{}`, http.StatusNotFound
			}).rest
			c, _, _ := worldClient(t, immutableWorld(ptr(true)))
			c.dotcom, c.rest = false, rest
			m := c.resolveUncached("docker", "build-push-action", "v7.4.0")
			if m.RefIsImmutableRelease != tc.want {
				t.Fatalf("RefIsImmutableRelease = %v, want %v", m.RefIsImmutableRelease, tc.want)
			}
			if got := len(c.DegradedChecks()) > 0; got != tc.wantDegraded {
				t.Fatalf("degraded = %v (%q), want %v", got, c.DegradedChecks(), tc.wantDegraded)
			}
		})
	}
}

// Test_Resolve_immutableReleaseCachedPerRef pins the per-run cache the
// issue asks for: the same owner/repo@tag used many times is loaded once.
func Test_Resolve_immutableReleaseCachedPerRef(t *testing.T) {
	c, loads, _ := worldClient(t, immutableWorld(ptr(true)))
	if !c.Resolve("docker/build-push-action@v7.4.0").RefIsImmutableRelease {
		t.Fatal("RefIsImmutableRelease = false, want true")
	}
	n := len(*loads)
	for range 2 {
		if !c.Resolve("docker/build-push-action@v7.4.0").RefIsImmutableRelease {
			t.Fatal("RefIsImmutableRelease = false, want true")
		}
	}
	if len(*loads) != n {
		t.Fatalf("loads = %d after repeated lookups, want %d", len(*loads), n)
	}
}

// TestEnrichCarriesImmutableReleaseToStepsAndReusableWorkflows covers the
// collector-to-IR handoff: the flag reaches a step's metadata, and a
// job-level reusable-workflow call is resolved too, so ISSUE-701 can
// accept both forms. A local reusable workflow is never looked up. Both
// remote references are loaded in the one prefetch.
func TestEnrichCarriesImmutableReleaseToStepsAndReusableWorkflows(t *testing.T) {
	client, loads, _ := worldClient(t, immutableWorld(ptr(true)))
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "build", Uses: []ir.Action{{Uses: "docker/build-push-action@v7.4.0"}}},
			{Name: "call", ReusableWorkflowUses: "octo/shared/.github/workflows/ci.yml@v7.4.0"},
			{Name: "local", ReusableWorkflowUses: "./.github/workflows/ci.yml"},
		},
	}
	enrichActionsWithClient(pipeline, client, false, nil)

	if md := pipeline.Jobs[0].Uses[0].Metadata; md == nil || !md.RefIsImmutableRelease || md.RefKind != "tag" {
		t.Fatalf("step metadata = %+v, want an immutable-release tag", md)
	}
	if md := pipeline.Jobs[1].ReusableWorkflowMetadata; md == nil || !md.RefIsImmutableRelease || md.RefKind != "tag" {
		t.Fatalf("reusable workflow metadata = %+v, want an immutable-release tag", md)
	}
	if md := pipeline.Jobs[2].ReusableWorkflowMetadata; md != nil {
		t.Fatalf("local reusable workflow metadata = %+v, want nil", md)
	}
	if len(*loads) != 1 || len((*loads)[0]) != 2 {
		t.Fatalf("loads = %+v, want one load for both repositories", *loads)
	}
}
