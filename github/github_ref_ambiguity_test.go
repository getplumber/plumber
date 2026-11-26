package github

import (
	"slices"
	"testing"
)

// Test_resolveUncached_renameRedirectIsNotAmbiguous drives the whole
// resolution for the #482 shape: `v2` is a tag upstream, and the branch
// once named v2 was renamed "releases/v2". The REST branches endpoint
// followed the rename redirect and answered 200 for v2; the GraphQL lookup
// asks refs/heads/v2 by its qualified name and gets null (checked on
// github/codeql-action, 2026-11-24). The ref must resolve as an
// unambiguous tag. The positive twin (a real branch named v2) keeps
// ISSUE-402's genuine case alive.
func Test_resolveUncached_renameRedirectIsNotAmbiguous(t *testing.T) {
	const sha = "8dca8a82000000000000000000000000000000ab"
	t.Run("no branch of that exact name: tag, not ambiguous", func(t *testing.T) {
		c, _, _ := worldClient(t, map[string]*fakeRepo{"github/codeql-action": {refs: map[string]refFacts{
			"v2": {tag: commitObj(sha)},
		}}})
		m := c.resolveUncached("github", "codeql-action", "v2")
		if m.RefKind != "tag" || !m.RefExists || m.RefIsAmbiguous {
			t.Fatalf("meta = %+v, want an existing, unambiguous tag (#482)", m)
		}
	})
	t.Run("a real branch of the same name stays ambiguous", func(t *testing.T) {
		c, _, _ := worldClient(t, map[string]*fakeRepo{"github/codeql-action": {refs: map[string]refFacts{
			"v2": {tag: commitObj(sha), branch: true},
		}}})
		if m := c.resolveUncached("github", "codeql-action", "v2"); !m.RefIsAmbiguous {
			t.Fatal("a tag AND a branch both named v2 is the genuine ISSUE-402 case and must stay flagged")
		}
	})
}

// Test_branchExists_asksTheExactRefName is the #482 regression guard at
// the query: the branch is asked as refs/heads/<ref>, an exact ref name,
// and a null answer is no branch.
func Test_branchExists_asksTheExactRefName(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"data":{"r0":{"t0":null,"h0":null,"x0":null,"l0":null}}}`, 200
	})
	if c.branchExists("github", "codeql-action", "v2") {
		t.Fatal("a null refs/heads/v2 must not read as a branch")
	}
	var values []any
	for _, q := range *got {
		for _, v := range q.Variables {
			values = append(values, v)
		}
	}
	if !slices.Contains(values, any("refs/heads/v2")) {
		t.Fatalf("variables %v do not ask refs/heads/v2", values)
	}
}
