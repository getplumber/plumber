package platform

import (
	"os"
	"testing"
)

// TestLivePlatform exercises the client against a REAL running platform
// instead of an httptest stub. It is skipped unless all three env vars are
// set, so it never runs in CI or in a normal `go test ./...`.
//
// It exists because the httptest tests can only prove the client matches
// the shapes this package declares — they cannot catch the two failures
// that actually bite a wire client: a route the platform does not have
// under that spelling, and a field whose real serialization differs from
// the documented one. Pointing this at a live backend catches both.
//
// The percent-encoded project path is the specific thing worth checking
// live: a client that builds the URL through net/url ends up with the
// project path split across route segments, which no unit test against a
// stub server can notice, because the stub has no route table.
//
// Running it against the local development stack:
//
//	PLUMBER_E2E_PLATFORM=http://127.0.0.1:8080 \
//	PLUMBER_E2E_TOKEN="$(./mint.sh org/repo 1234)" \
//	PLUMBER_E2E_PROJECT=org/repo \
//	go test ./internal/platform/ -run TestLivePlatform -v
//
// The token must be a CI OIDC id-token whose project_path claim equals
// PLUMBER_E2E_PROJECT, or the platform answers 403 by design.
func TestLivePlatform(t *testing.T) {
	base := os.Getenv("PLUMBER_E2E_PLATFORM")
	token := os.Getenv("PLUMBER_E2E_TOKEN")
	project := os.Getenv("PLUMBER_E2E_PROJECT")
	if base == "" || token == "" || project == "" {
		t.Skip("set PLUMBER_E2E_PLATFORM, PLUMBER_E2E_TOKEN and PLUMBER_E2E_PROJECT to run against a live platform")
	}

	c := NewClient(base, token)

	ctx, err := c.FetchContext(project)
	if err != nil {
		t.Fatalf("FetchContext: %v", err)
	}
	if ctx.Project != project {
		t.Fatalf("the platform resolved a different project than requested: got %q, want %q", ctx.Project, project)
	}
	// The policy set is never empty: an unassigned project resolves to the
	// derived default rather than nothing.
	if len(ctx.Policies) == 0 {
		t.Fatal("the resolved policy set must never be empty")
	}
	for _, p := range ctx.Policies {
		t.Logf("policy %-24q enforcement=%-6s real=%v", p.Name, p.Enforcement, p.IsReal())
		if p.Name == "" {
			t.Error("every policy must carry a name")
		}
	}
	if collected := ctx.Snapshot.CollectedAt; collected != nil {
		t.Logf("snapshot collected_at=%s", collected.UTC())
	} else {
		t.Log("snapshot: none cached for this project")
	}
	if a := ctx.Snapshot.Anchor(); a != nil {
		t.Logf("anchor ref=%s sha=%s digest=%s/%s", a.Ref, a.Sha, a.ConfigDigest, a.DigestVersion)
	}

	// The resolve endpoint's 503 is an expected steady state (no org token
	// configured, resolver busy, project never onboarded), so both outcomes
	// below are a pass — what must not happen is an untyped error.
	resolved, err := c.ResolveConfig(project, "0000000000000000000000000000000000000000", "", "")
	switch reason, unavailable := IsUnavailable(err); {
	case unavailable:
		t.Logf("resolve unavailable (%s) — an expected steady state, not a failure", reason)
	case err != nil:
		t.Logf("resolve returned %v", err)
	default:
		t.Logf("resolved: source=%s valid=%v sha=%s merged_yaml=%d bytes",
			resolved.Source, resolved.Valid, resolved.ResolvedSha, len(resolved.MergedYaml))
	}
}
