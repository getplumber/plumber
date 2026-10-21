package github

import (
	"net/http"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// immutableReleaseClient stubs the REST transport for action repos whose
// tag v7.4.0 and branch main exist; GET .../releases/tags/{tag} answers
// releaseStatus/releaseBody and increments *releaseCalls.
func immutableReleaseClient(t *testing.T, releaseStatus int, releaseBody string, releaseCalls *int) *GitHubMetadataClient {
	t.Helper()
	return stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, "/releases/tags/"):
			*releaseCalls++
			return releaseBody, releaseStatus
		case strings.HasSuffix(p, "/releases"):
			return `[]`, http.StatusOK
		case strings.HasPrefix(p, "/advisories"):
			return `[]`, http.StatusOK
		case strings.HasSuffix(p, "/git/ref/tags/v7.4.0"):
			return `{"object":{"type":"commit","sha":"` + strings.Repeat("a", 40) + `"}}`, http.StatusOK
		case strings.HasSuffix(p, "/branches/main"):
			return `{"name":"main"}`, http.StatusOK
		case strings.Count(p, "/") == 3 && strings.HasPrefix(p, "/repos/"):
			return `{"archived":false,"stargazers_count":5}`, http.StatusOK
		}
		return `{}`, http.StatusNotFound
	})
}

// Test_resolveUncached_immutableRelease pins the ISSUE-701 exemption
// signal (#421): a tag is reported as backed by an immutable release
// ONLY when the release for that exact tag says immutable=true. A
// missing release (a floating major such as v7), a mutable one and a
// failed lookup all leave it false, so the ref keeps being flagged
// (fail-closed); only the failed lookup is reported as degraded.
func Test_resolveUncached_immutableRelease(t *testing.T) {
	cases := []struct {
		name          string
		ref           string
		releaseStatus int
		releaseBody   string
		want          bool
		wantDegraded  bool
		wantCalls     int
	}{
		{"immutable release", "v7.4.0", http.StatusOK, `{"tag_name":"v7.4.0","immutable":true}`, true, false, 1},
		{"mutable release", "v7.4.0", http.StatusOK, `{"tag_name":"v7.4.0","immutable":false}`, false, false, 1},
		{"release predating the flag", "v7.4.0", http.StatusOK, `{"tag_name":"v7.4.0"}`, false, false, 1},
		{"tag without a release", "v7.4.0", http.StatusNotFound, `{"message":"Not Found"}`, false, false, 1},
		{"failed lookup is fail-closed and reported", "v7.4.0", http.StatusInternalServerError, `{"message":"boom"}`, false, true, 1},
		{"branch ref never asks for a release", "main", http.StatusOK, `{"immutable":true}`, false, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := immutableReleaseClient(t, tc.releaseStatus, tc.releaseBody, &calls)
			m := c.resolveUncached("docker", "build-push-action", tc.ref)
			if m.RefIsImmutableRelease != tc.want {
				t.Fatalf("RefIsImmutableRelease = %v, want %v", m.RefIsImmutableRelease, tc.want)
			}
			if calls != tc.wantCalls {
				t.Fatalf("release lookups = %d, want %d", calls, tc.wantCalls)
			}
			if got := len(c.DegradedChecks()) > 0; got != tc.wantDegraded {
				t.Fatalf("degraded = %v (%q), want %v", got, c.DegradedChecks(), tc.wantDegraded)
			}
		})
	}
}

// Test_Resolve_immutableReleaseCachedPerRef pins the per-run cache the
// issue asks for: the same owner/repo@tag used many times costs one
// release lookup.
func Test_Resolve_immutableReleaseCachedPerRef(t *testing.T) {
	calls := 0
	c := immutableReleaseClient(t, http.StatusOK, `{"immutable":true}`, &calls)
	for range 3 {
		if !c.Resolve("docker/build-push-action@v7.4.0").RefIsImmutableRelease {
			t.Fatal("RefIsImmutableRelease = false, want true")
		}
	}
	if calls != 1 {
		t.Fatalf("release lookups = %d, want 1", calls)
	}
}

// TestEnrichCarriesImmutableReleaseToStepsAndReusableWorkflows covers the
// collector-to-IR handoff: the flag reaches a step's metadata, and a
// job-level reusable-workflow call is resolved too, so ISSUE-701 can
// accept both forms. A local reusable workflow is never looked up.
func TestEnrichCarriesImmutableReleaseToStepsAndReusableWorkflows(t *testing.T) {
	calls := 0
	client := immutableReleaseClient(t, http.StatusOK, `{"immutable":true}`, &calls)
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
	if calls != 2 {
		t.Fatalf("release lookups = %d, want 2 (one per distinct owner/repo@tag)", calls)
	}
}
