package github

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	version "github.com/hashicorp/go-version"

	"github.com/getplumber/plumber/internal/httpcount"
)

// roundTripFunc adapts a function into an http.RoundTripper so tests can
// stub the authenticated REST transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Test_versionInRange locks the ISSUE-703 range-filter semantics.
// The scenario comes from a real-world false positive: the codeql-
// action pinned at v4.35.1 was flagged for GHSA-vqf5-2xx6-9wfm
// whose range covers `>= 3.26.11, <= 3.28.2` and `>= 2.26.11, <
// 3.0.0`. A strict semver check keeps v4.35.1 out of either range
// and silences the false positive.
func Test_versionInRange(t *testing.T) {
	cases := []struct {
		ver, rng string
		want     bool
	}{
		{"3.28.2", ">= 3.26.11, <= 3.28.2", true},  // upper bound inclusive
		{"3.28.3", ">= 3.26.11, <= 3.28.2", false}, // past upper bound
		{"3.26.10", ">= 3.26.11, <= 3.28.2", false},
		{"4.35.1", ">= 3.26.11, <= 3.28.2", false}, // real-world regression
		{"2.30.0", ">= 2.26.11, < 3.0.0", true},
		{"3.0.0", ">= 2.26.11, < 3.0.0", false},
		// Empty / unparseable ranges degrade to "affects everything"
		// so a broken advisory never silences a real CVE.
		{"1.0.0", "", true},
		{"1.0.0", "nonsense-range", true},
	}
	for _, c := range cases {
		v, err := version.NewVersion(c.ver)
		if err != nil {
			t.Fatalf("version parse %q: %v", c.ver, err)
		}
		got := _versionInRange(v, c.rng)
		if got != c.want {
			t.Errorf("_versionInRange(%q, %q) = %v, want %v", c.ver, c.rng, got, c.want)
		}
	}
}

// Test_moreSpecificTag locks the SHA-collision tie-break: when one
// commit carries both a moving major alias and the exact release tag,
// the advisory range filter must resolve to the exact release so the
// alias ("v4" -> 4.0.0) cannot drag the ref into a vulnerable range.
func Test_moreSpecificTag(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"v4", "v4.3.0", "v4.3.0"},     // exact release beats major alias
		{"v4.3.0", "v4", "v4.3.0"},     // order-independent
		{"v44", "v44.0.0", "v44.0.0"},  // alias vs exact, no patch segment
		{"v4.3.0", "latest", "v4.3.0"}, // semver beats non-semver
		{"latest", "v4.3.0", "v4.3.0"},
		{"v4.3.0", "v4.3.1", "v4.3.1"}, // same precision -> higher version
	}
	for _, c := range cases {
		if got := _moreSpecificTag(c.a, c.b); got != c.want {
			t.Errorf("_moreSpecificTag(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

// Test_resolveRefToVersion_commitSHA is the ISSUE-703 regression for a
// commit SHA that starts with a digit. hashicorp/go-version parses
// "2d756ea…" as 2.0.0-d756ea…; resolveRefToVersion must take the SHA
// branch instead of returning that bogus value, otherwise every
// advisory for the action is silently dropped. The client is offline
// (see TestMain), so the SHA simply resolves to no tag -> nil.
func Test_resolveRefToVersion_commitSHA(t *testing.T) {
	c := NewGitHubMetadataClientForHost("")
	sha := "2d756ea4c53f7f6b397767d8723b3a10a9f35bf2"
	if v := c.resolveRefToVersion("tj-actions", "changed-files", sha); v != nil {
		t.Errorf("resolveRefToVersion(%s) = %v, want nil (SHA must not parse as semver)", sha, v)
	}
	if v := c.resolveRefToVersion("actions", "download-artifact", "v4.3.0"); v == nil || v.String() != "4.3.0" {
		t.Errorf("resolveRefToVersion(v4.3.0) = %v, want 4.3.0", v)
	}
}

// Test_partialTagBounds locks the moving-tag recognition: only bare
// major (`v4`) and major.minor (`v4.1`) tags resolve to a span;
// exact tags, SHAs and non-semver refs do not.
func Test_partialTagBounds(t *testing.T) {
	cases := []struct {
		ref               string
		wantOK            bool
		wantFloor, wantHi string
	}{
		{"v4", true, "4.0.0", "4.999999.999999"},
		{"4", true, "4.0.0", "4.999999.999999"},
		{"v44", true, "44.0.0", "44.999999.999999"},
		{"v4.1", true, "4.1.0", "4.1.999999"},
		{"v4.1.0", false, "", ""}, // exact version — not a moving tag
		{"main", false, "", ""},
		{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", false, "", ""},
	}
	for _, c := range cases {
		floor, ceil, ok := _partialTagBounds(c.ref)
		if ok != c.wantOK {
			t.Errorf("_partialTagBounds(%q) ok = %v, want %v", c.ref, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		wantFloor, _ := version.NewVersion(c.wantFloor)
		wantHi, _ := version.NewVersion(c.wantHi)
		if !floor.Equal(wantFloor) || !ceil.Equal(wantHi) {
			t.Errorf("_partialTagBounds(%q) = (%s, %s), want (%s, %s)", c.ref, floor, ceil, c.wantFloor, c.wantHi)
		}
	}
}

// Test_refCoveredByRange is the ISSUE-195 regression: a moving major /
// major.minor tag is reported for an advisory only when the whole span
// it floats across is vulnerable, while exact pins keep the plain
// single-version semantics.
func Test_refCoveredByRange(t *testing.T) {
	cases := []struct {
		ref, rng, ver string
		want          bool
	}{
		// Moving tags — partial: flagged only if the whole series is vulnerable.
		{"v4", ">= 4.0.0, < 4.1.3", "", false},   // download-artifact@v4 vs GHSA-cxww — the FP this fixes
		{"v44", "<= 45.0.7", "", true},           // all of v44.x is vulnerable
		{"v4.1", ">= 4.0.0, < 4.1.3", "", false}, // moving minor tag — only 4.1.0-4.1.2 affected
		{"v5", ">= 5, < 6.4.0", "", true},        // all of v5.x is vulnerable
		// Exact pins / resolved SHAs — single-version check, unchanged.
		{"v4.1.0", ">= 4.0.0, < 4.1.3", "4.1.0", true},  // exact in-range pin still fires
		{"v4.3.0", ">= 4.0.0, < 4.1.3", "4.3.0", false}, // exact out-of-range stays silent
		// Unresolved commit SHA (ver "" -> refVersion nil): the tag list
		// was unavailable (org IP allow list 403, rate limit, network) or
		// the SHA is not a release commit. We cannot prove the pin sits in
		// the affected range, so stay silent — matching every advisory for
		// an unresolved SHA is the ISSUE-228 local-vs-CI false positive.
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", ">= 4.0.0, < 4.1.3", "", false}, // unresolved SHA -> abstain
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "<= 99.0.0", "", false},         // even a wide range -> abstain
		// A resolved SHA still gets the normal single-version check.
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", ">= 4.0.0, < 4.1.3", "4.1.0", true},  // resolved in range -> flag
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", ">= 4.0.0, < 4.1.3", "8.0.1", false}, // resolved out of range -> silent
		// A mutable ref we cannot resolve to a version abstains: it usually
		// points at the latest, patched release. "Not pinned" is ISSUE-701's
		// job. This is the harden-runner `@rc` over-match (step-security scan).
		{"main", "<= 99.0.0", "", false},
		{"rc", "<= 99.0.0", "", false},
		{"latest", "< 2.10.2", "", false},
	}
	for _, c := range cases {
		var rv *version.Version
		if c.ver != "" {
			rv, _ = version.NewVersion(c.ver)
		}
		got := _refCoveredByRange(c.ref, rv, c.rng)
		if got != c.want {
			t.Errorf("_refCoveredByRange(%q, %q) = %v, want %v", c.ref, c.rng, got, c.want)
		}
	}
}

// Test_advisoriesForRef_unresolvedSHA is the ISSUE-228 regression. When a
// SHA-pinned action cannot be resolved to a release version — because the
// repo's tag list is unavailable (org IP allow list 403, rate limit,
// network error) or the SHA is not a tagged release — the advisory filter
// must NOT report every advisory for the repo. Reporting them is what makes
// a SHA-pinned action score A locally and E in GitHub Actions: locally the
// tag list resolves and the out-of-range pin is dropped; in CI the fetch
// fails, the version is unknown, and every advisory matches.
func Test_advisoriesForRef_unresolvedSHA(t *testing.T) {
	const repoKey = "aquasecurity/trivy-action"
	const sha = "1234567890abcdef1234567890abcdef12345678"

	newClient := func() *GitHubMetadataClient {
		c := NewGitHubMetadataClientForHost("")
		// Inject a known advisory so advisoriesForRepo does not hit the API.
		c.advisoryCache[repoKey] = []advisoryInfo{
			{GhsaID: "GHSA-aaaa-bbbb-cccc", VulnerableRange: "< 0.35.0"},
		}
		return c
	}

	// Tag list unavailable (empty map cached, as a failed fetch leaves it):
	// the SHA resolves to no version -> abstain, not match-all, AND the
	// degraded check is recorded so it can be surfaced (not silent).
	c := newClient()
	c.sha2tagCache[repoKey] = map[string]string{}
	if got := c.advisoriesForRef("aquasecurity", "trivy-action", sha); len(got) != 0 {
		t.Errorf("unresolved SHA: advisoriesForRef = %v, want none (abstain)", got)
	}
	if d := c.DegradedChecks(); len(d) != 1 {
		t.Errorf("unresolved SHA: DegradedChecks = %v, want exactly 1 entry", d)
	}

	// SHA resolves to an out-of-range version -> silent, and NOT degraded
	// (we verified the version, it just isn't affected).
	c = newClient()
	c.sha2tagCache[repoKey] = map[string]string{sha: "0.37.0"}
	if got := c.advisoriesForRef("aquasecurity", "trivy-action", sha); len(got) != 0 {
		t.Errorf("out-of-range SHA: advisoriesForRef = %v, want none", got)
	}
	if d := c.DegradedChecks(); len(d) != 0 {
		t.Errorf("out-of-range SHA: DegradedChecks = %v, want none (version resolved)", d)
	}

	// SHA resolves to an in-range version -> the advisory fires, not degraded.
	c = newClient()
	c.sha2tagCache[repoKey] = map[string]string{sha: "0.34.0"}
	got := c.advisoriesForRef("aquasecurity", "trivy-action", sha)
	if len(got) != 1 || got[0] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("in-range SHA: advisoriesForRef = %v, want [GHSA-aaaa-bbbb-cccc]", got)
	}
	if d := c.DegradedChecks(); len(d) != 0 {
		t.Errorf("in-range SHA: DegradedChecks = %v, want none (version resolved)", d)
	}
}

// Test_advisoriesForRef_movingTag is the harden-runner `@rc` regression
// (validated against step-security/harden-runner). A mutable non-numeric
// tag names no fixed version, so the CVE check cannot place it in any
// advisory range: it must abstain and emit zero advisories, not match
// every advisory the repo carries. Unlike an unresolvable SHA it is NOT
// recorded as degraded — an unpinned ref is ISSUE-701's concern, not a
// "could not verify" warning. Before the fix `@rc` matched all 5
// harden-runner advisories even though `rc` points past every fix.
func Test_advisoriesForRef_movingTag(t *testing.T) {
	const repoKey = "step-security/harden-runner"
	newClient := func() *GitHubMetadataClient {
		c := NewGitHubMetadataClientForHost("")
		c.advisoryCache[repoKey] = []advisoryInfo{
			{GhsaID: "GHSA-g85v-wf27-67xc", VulnerableRange: "< 2.10.2"},
			{GhsaID: "GHSA-mxr3-8whj-j74r", VulnerableRange: ">= 0.12.0, < 2.12.0"},
		}
		return c
	}

	for _, ref := range []string{"rc", "main", "latest"} {
		c := newClient()
		if got := c.advisoriesForRef("step-security", "harden-runner", ref); len(got) != 0 {
			t.Errorf("@%s: advisoriesForRef = %v, want none (abstain)", ref, got)
		}
		if d := c.DegradedChecks(); len(d) != 0 {
			t.Errorf("@%s: DegradedChecks = %v, want none (ISSUE-701 owns unpinned refs)", ref, d)
		}
	}
}

func Test_apiBaseURLForHost(t *testing.T) {
	cases := []struct{ host, want string }{
		{"", "https://api.github.com"},
		{"   ", "https://api.github.com"},
		{"ghes.example.com", "https://ghes.example.com"},
		{"ghes.example.com/", "https://ghes.example.com"},
		{"https://ghes.example.com/api/v3", "https://ghes.example.com/api/v3"},
	}
	for _, c := range cases {
		if got := apiBaseURLForHost(c.host); got != c.want {
			t.Errorf("apiBaseURLForHost(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

// Test_metadataClientOptions covers the ISSUE-228 credential precedence:
// PLUMBER_METADATA_TOKEN, when set, becomes the REST client's AuthToken and
// takes priority over the go-gh default chain; otherwise no token is
// returned. host, when non-empty, targets a GHES instance either way.
func Test_metadataClientOptions(t *testing.T) {
	t.Setenv(EnvMetadataToken, "")
	if opts, token := metadataClientOptions(""); token != "" || opts.AuthToken != "" || opts.Host != "" {
		t.Fatalf("no token, github.com: got token=%q auth=%q host=%q, want all empty", token, opts.AuthToken, opts.Host)
	}
	if opts, token := metadataClientOptions("ghes.example.com"); token != "" || opts.AuthToken != "" || opts.Host != "ghes.example.com" {
		t.Fatalf("no token, GHES: got token=%q auth=%q host=%q, want host-only", token, opts.AuthToken, opts.Host)
	}

	t.Setenv(EnvMetadataToken, "  ghp_metadata  ")
	if opts, token := metadataClientOptions(""); token != "ghp_metadata" || opts.AuthToken != "ghp_metadata" || opts.Host != "" {
		t.Fatalf("token, github.com: got token=%q auth=%q host=%q, want trimmed token as auth", token, opts.AuthToken, opts.Host)
	}
	if opts, token := metadataClientOptions("ghes.example.com"); token != "ghp_metadata" || opts.AuthToken != "ghp_metadata" || opts.Host != "ghes.example.com" {
		t.Fatalf("token, GHES: got token=%q auth=%q host=%q, want token+host", token, opts.AuthToken, opts.Host)
	}
}

// Test_graphQLClientOptions pins that the GraphQL client never goes through
// Memo: it keeps the host and token of the REST options but sends through
// the counting-only transport, so an "absent" answer is never replayed.
func Test_graphQLClientOptions(t *testing.T) {
	t.Setenv(EnvMetadataToken, "ghp_metadata")
	rest, _ := metadataClientOptions("ghes.example.com")
	gql := graphQLClientOptions(rest)
	if gql.Transport != httpcount.DefaultTransport {
		t.Fatalf("GraphQL transport = %T, want httpcount.DefaultTransport", gql.Transport)
	}
	if gql.AuthToken != "ghp_metadata" || gql.Host != "ghes.example.com" {
		t.Fatalf("GraphQL options: auth=%q host=%q, want the REST ones", gql.AuthToken, gql.Host)
	}
	if rest.Transport != httpcount.MemoTransport {
		t.Fatalf("REST transport = %T, want httpcount.MemoTransport", rest.Transport)
	}
}

// Test_NewClient_withMetadataToken_constructs verifies the real constructor
// builds a usable REST client from PLUMBER_METADATA_TOKEN with an empty host
// (go-gh defaults the host to api.github.com), so the token path does not
// silently degrade. No network call is made; only construction is checked.
func Test_NewClient_withMetadataToken_constructs(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "") // undo the suite's offline default
	t.Setenv(EnvMetadataToken, "ghp_metadata")
	c := NewGitHubMetadataClientForHost("")
	if !c.Available() {
		t.Fatalf("client should be available with a metadata token set; disableCause=%v", c.disableCause)
	}
	if c.rest == nil {
		t.Fatal("rest client should be constructed from the metadata token")
	}
}

// Test_isZeroMetadata_stargazers guards the ISSUE-713 minimumStars path:
// a resolved star count must keep the metadata even when the ref itself
// could not be resolved, otherwise enrichment drops it and a popular
// action is wrongly reported as unauthorized.
func Test_isZeroMetadata_stargazers(t *testing.T) {
	if isZeroMetadata(GitHubMetadata{StargazersCount: 1500}) {
		t.Error("metadata with a non-zero star count must not be treated as zero")
	}
	if !isZeroMetadata(GitHubMetadata{}) {
		t.Error("fully zero metadata must be treated as zero")
	}
}

// Test_isZeroMetadata_refKnownAbsent guards the ISSUE-707 enrichment
// linchpin. For an impostor commit on a readable but zero/low-star repo
// the resolved metadata is all-zero EXCEPT RefKnownAbsent=true. If
// isZeroMetadata dropped that clause, enrichment
// (`if isZeroMetadata(meta) && action.Comment == "" { continue }`) would
// discard the metadata, action.Metadata would stay nil, and the rego
// would never fire — silently disabling the control for the exact case
// it targets.
func Test_isZeroMetadata_refKnownAbsent(t *testing.T) {
	if isZeroMetadata(GitHubMetadata{RefKnownAbsent: true}) {
		t.Error("metadata carrying only RefKnownAbsent must not be treated as zero, or ISSUE-707 metadata is dropped at enrichment")
	}
}

// Test_resolveUncached_refKnownAbsentGuard is the ISSUE-707 critical-FP
// guard test. commitResolves alone cannot prove the repo was readable —
// that gate (`checked && info.err == nil`) lives in resolveUncached. A
// private/missing repo must NOT be reported as an impostor: that would be
// a critical false positive on a legitimately unreachable action. The
// readable-repo positive path is locked too, so a broken guard cannot
// silently disable the control.
func Test_resolveUncached_refKnownAbsentGuard(t *testing.T) {
	const sha = "abcdef0123456789abcdef0123456789abcdef01"
	t.Run("readable repo + absent commit is a confirmed impostor", func(t *testing.T) {
		c, _, _ := worldClient(t, map[string]*fakeRepo{"acme/widget": {}})
		m := c.resolveUncached("acme", "widget", sha)
		if !m.RefKnownAbsent || m.RefExists {
			t.Fatalf("meta = %+v, want RefKnownAbsent and not RefExists", m)
		}
	})
	t.Run("unreadable repo does not become an impostor", func(t *testing.T) {
		c, _, _ := worldClient(t, map[string]*fakeRepo{})
		if m := c.resolveUncached("acme", "widget", sha); m.RefKnownAbsent {
			t.Fatal("a private/missing repo must NOT be reported as an impostor; RefKnownAbsent must stay false")
		}
	})
}

// Test_resolveUncached_redirectedOwner pins the RedirectedOwner signal
// trust.actorFor reads a sibling-organisation redirect off: the
// repository's current nameWithOwner is who can actually change the code,
// which can differ from the `uses` owner after a rename or an organisation
// transfer (ask-bonk/ask-bonk -> Cloudflare-Studio/ask-bonk).
func Test_resolveUncached_redirectedOwner(t *testing.T) {
	for _, tc := range []struct{ fullName, want string }{
		{"Cloudflare-Studio/ask-bonk", "Cloudflare-Studio"},
		{"ask-bonk/ask-bonk", ""},
		{"ASK-BONK/ask-bonk", ""},
	} {
		c, _, _ := worldClient(t, map[string]*fakeRepo{"ask-bonk/ask-bonk": {info: repoCacheEntry{fullName: tc.fullName}}})
		if m := c.resolveUncached("ask-bonk", "ask-bonk", "main"); m.RedirectedOwner != tc.want {
			t.Errorf("full name %q: RedirectedOwner = %q, want %q", tc.fullName, m.RedirectedOwner, tc.want)
		}
	}
}

// Test_resolveUncached_annotatedTagObjectPin is the ISSUE-401
// regression guard. Pinning an action to the SHA of an annotated tag
// object is a normal outcome of pinning by hand or with a script, the
// pin is immutable, and GitHub Actions resolves it. It is no commit, so
// without the tag-object dereference the collector marks it
// RefKnownAbsent and impostor-commit (ISSUE-707, critical) fires on a
// perfectly valid pin.
func Test_resolveUncached_annotatedTagObjectPin(t *testing.T) {
	const (
		tagObjectSHA = "7088e561eb65bb68695d245aa206f005ef30921d"
		commitSHA    = "a7487c7e89a18df4991f7f222e4898a00d66ddda"
	)
	c, _, _ := worldClient(t, map[string]*fakeRepo{"pnpm/action-setup": {refs: map[string]refFacts{
		tagObjectSHA: {objectChecked: true, object: tagObj(tagObjectSHA, commitObj(commitSHA))},
	}}})
	m := c.resolveUncached("pnpm", "action-setup", tagObjectSHA)
	if m.RefKnownAbsent || !m.RefExists {
		t.Fatalf("meta = %+v: a resolvable annotated tag object exists upstream (ISSUE-707 false positive)", m)
	}
	if m.RefKind != "commit" {
		t.Fatalf("RefKind = %q, want \"commit\": the pin designates a commit through the tag object, and refKind==\"tag\" means the ref is a tag NAME", m.RefKind)
	}
	if m.RefCommitSha != commitSHA {
		t.Fatalf("RefCommitSha = %q, want %q (the commit the tag object dereferences to)", m.RefCommitSha, commitSHA)
	}
}

// Test_resolveUncached_tagObjectAbstainKeepsIssue707Silent locks the
// abstain branch that sits between the tag-object dereference and
// RefKnownAbsent. When the ref is definitively no commit on a readable
// repo but the tag object cannot be followed to a commit, the collector
// must leave RefKnownAbsent false: impostor-commit (ISSUE-707, critical)
// fires only on confirmed absence, never on a SHA we merely failed to
// classify.
func Test_resolveUncached_tagObjectAbstainKeepsIssue707Silent(t *testing.T) {
	const (
		sha   = "abcdef0123456789abcdef0123456789abcdef01"
		inner = "fedcba9876543210fedcba9876543210fedcba98"
	)
	for _, tc := range []struct {
		name   string
		object *gitObject
	}{
		{"tag object pointing at a tree", tagObj(sha, &gitObject{Typename: "Tree", Oid: inner})},
		{"tag object chain longer than was read", tagObj(sha, tagObj(inner, nil))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := worldClient(t, map[string]*fakeRepo{"acme/widget": {refs: map[string]refFacts{sha: {objectChecked: true, object: tc.object}}}})
			if m := c.resolveUncached("acme", "widget", sha); m.RefKnownAbsent || m.RefExists {
				t.Fatalf("meta = %+v: an unclassifiable tag object must leave RefKnownAbsent and RefExists false", m)
			}
		})
	}
	t.Run("failed lookup", func(t *testing.T) {
		c, _, _ := worldClient(t, map[string]*fakeRepo{"acme/widget": {refs: map[string]refFacts{sha: {failed: true}}}})
		if m := c.resolveUncached("acme", "widget", sha); m.RefKnownAbsent || m.RefExists {
			t.Fatalf("meta = %+v: a failed lookup must leave RefKnownAbsent and RefExists false", m)
		}
	})
	// The guard must not swallow the real thing: no object at all still
	// means the SHA is nothing upstream.
	t.Run("confirmed absent object still reports the impostor", func(t *testing.T) {
		c, _, _ := worldClient(t, map[string]*fakeRepo{"acme/widget": {}})
		if m := c.resolveUncached("acme", "widget", sha); !m.RefKnownAbsent {
			t.Fatal("a SHA that is neither commit nor tag object upstream must still be reported (ISSUE-707)")
		}
	})
}

// Test_resolveUncached_absentNonShaRef: a ref that is no tag, no branch
// and no object is reported absent whatever its shape; only a SHA can name
// a tag object, so a name never reaches that dereference.
func Test_resolveUncached_absentNonShaRef(t *testing.T) {
	c, _, _ := worldClient(t, map[string]*fakeRepo{"acme/widget": {}})
	if m := c.resolveUncached("acme", "widget", "v99"); !m.RefKnownAbsent {
		t.Fatalf("meta = %+v, want RefKnownAbsent for an absent v99", m)
	}
}

// Test_resolveUncached_realWorldTagObjectVectors replays the five
// annotated-tag-object pins reported in ISSUE-401, each a tag object that
// GitHub resolves to its commit. Every one must resolve, and the
// fabricated control SHA (no object upstream) must still be reported,
// because a fix that merely relaxes the check is worse than the bug.
//
// SHAs and dereferenced commits verified against the live API. The
// deliberately absent control is the one from the report.
func Test_resolveUncached_realWorldTagObjectVectors(t *testing.T) {
	type vector struct {
		owner, repo string
		tagObject   string
		tag         string
		commit      string
	}
	vectors := []vector{
		// gradle/actions/setup-gradle is a subdirectory action; the repo
		// the collector queries is gradle/actions.
		{"gradle", "actions", "48b5f213c81028ace310571dc5ec0fbbca0b2947", "v4.4.3", "ed408507eac070d1f99cc633dbcf757c94c7933a"},
		{"mxschmitt", "action-tmate", "1fb8b1023602bf1fd0e2994d7f1e93015cb5bbec", "v3.22", "7b6a61a73bbb9793cb80ad69b8dd8ac19261834c"},
		{"pnpm", "action-setup", "7088e561eb65bb68695d245aa206f005ef30921d", "v4.1.0", "a7487c7e89a18df4991f7f222e4898a00d66ddda"},
		{"cross-platform-actions", "action", "462ed697694d2ac9aa49e1225f395f7bb6dd49fe", "v0.29.0", "e8a7b572196ff79ded1979dc2bb9ee67d1ddb252"},
		// setup-uv's v6 is a MOVING tag. refs/tags/v6 has since been
		// repointed at a newer tag object, so this SHA is orphaned from
		// every ref while remaining a valid, immutable, resolvable object
		// whose commit is in the repo. It is the reason the fork-network
		// blind spot documented on tagObjectResolves cannot be closed by
		// checking membership in the repo's own tag refs: that check
		// rejects this pin and reinstates the ISSUE-401 false positive for
		// every moving tag.
		{"astral-sh", "setup-uv", "884ad927a57e558e7a70b92f2bccf9198a4be546", "v6", "bd01e18f51369d5a26f1651c3cb451d3417e3bba"},
	}
	const absentSHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	world := map[string]*fakeRepo{"actions/checkout": {}}
	for _, v := range vectors {
		world[v.owner+"/"+v.repo] = &fakeRepo{refs: map[string]refFacts{
			v.tagObject: {objectChecked: true, object: tagObj(v.tagObject, commitObj(v.commit))},
		}}
	}
	for _, v := range vectors {
		t.Run(v.owner+"/"+v.repo+"@"+v.tag, func(t *testing.T) {
			c, _, _ := worldClient(t, world)
			m := c.resolveUncached(v.owner, v.repo, v.tagObject)
			if !m.RefExists || m.RefKnownAbsent || m.RefCommitSha != v.commit {
				t.Fatalf("meta = %+v, want an existing pin on %s", m, v.commit)
			}
		})
	}
	t.Run("fabricated SHA is still reported", func(t *testing.T) {
		c, _, _ := worldClient(t, world)
		m := c.resolveUncached("actions", "checkout", absentSHA)
		if !m.RefKnownAbsent || m.RefExists {
			t.Fatalf("meta = %+v: a SHA with no object upstream must still set RefKnownAbsent", m)
		}
	})
}

// Test_advisoriesForRepo_enterpriseREST: on GitHub Enterprise Server the
// advisories are read over REST, one call per package asking the Advisory
// Database for the actions ecosystem. Only this package's vulnerabilities
// count (matched without regard to case), with the severity lower-cased
// and the ranges kept as listed. The answer is kept for the run.
func Test_advisoriesForRepo_enterpriseREST(t *testing.T) {
	var asked []string
	c := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		asked = append(asked, r.URL.Path+"?"+r.URL.RawQuery)
		return `[
			{"ghsa_id":"GHSA-aaaa","severity":"HIGH","vulnerabilities":[
				{"package":{"name":"Acme/Deploy"},"vulnerable_version_range":"< 2.1.0","patched_versions":"2.1.0"},
				{"package":{"name":"acme/other"},"vulnerable_version_range":"< 9.0.0","patched_versions":"9.0.0"}
			]},
			{"ghsa_id":"GHSA-bbbb","severity":"moderate","vulnerabilities":[
				{"package":{"name":"someone/else"},"vulnerable_version_range":"< 1.0.0","patched_versions":"1.0.0"}
			]}
		]`, http.StatusOK
	})
	c.dotcom = false

	got := c.advisoriesForRepo("acme", "deploy")
	want := []advisoryInfo{{GhsaID: "GHSA-aaaa", VulnerableRange: "< 2.1.0", PatchedVersions: "2.1.0", Severity: "high"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("advisories = %+v\nwant %+v", got, want)
	}
	if wantAsked := []string{"/advisories?ecosystem=actions&affects=acme/deploy&per_page=100"}; !reflect.DeepEqual(asked, wantAsked) {
		t.Errorf("REST requests = %v, want %v", asked, wantAsked)
	}
	if d := c.DegradedChecks(); len(d) != 0 {
		t.Errorf("degraded = %q, want none", d)
	}
	c.advisoriesForRepo("acme", "deploy")
	if len(asked) != 1 {
		t.Errorf("sent %d requests for one package, want the answer kept", len(asked))
	}
}

// Test_advisoriesForRepo_enterpriseRESTFailureIsDegraded: a refused or
// failed Advisory Database lookup on GHES never reads as "no advisories"
// without a word: the known-CVE check is reported as skipped (ISSUE-703),
// and the empty answer is kept so one rate limit does not turn into one
// request per action.
func Test_advisoriesForRepo_enterpriseRESTFailureIsDegraded(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			requests := 0
			c := stubbedMetadataClient(t, func(*http.Request) (string, int) {
				requests++
				return `{"message":"nope"}`, status
			})
			c.dotcom = false

			if got := c.advisoriesForRepo("acme", "deploy"); len(got) != 0 {
				t.Errorf("advisories = %+v, want none", got)
			}
			d := c.DegradedChecks()
			if len(d) != 1 || !strings.Contains(d[0], "acme/deploy: the GitHub Advisory Database could not be queried") {
				t.Errorf("degraded = %q, want the skipped known-CVE check for acme/deploy", d)
			}
			c.advisoriesForRepo("acme", "deploy")
			if requests != 1 {
				t.Errorf("sent %d requests, want the failed answer kept", requests)
			}
		})
	}
}

// Test_isDotcomHost: the host decides whether the GraphQL query asks the
// fields a GitHub Enterprise Server may lack (advisories, immutable
// releases), so only github.com itself, however written, counts.
func Test_isDotcomHost(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "1")
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"github.com", true},
		{"api.github.com", true},
		{"API.GitHub.com", true},
		{"https://github.com/", true},
		{" http://api.github.com ", true},
		{"ghes.example.com", false},
		{"https://ghes.example.com/api/v3", false},
		{"github.com.evil.io", false},
		{"evil-github.com", false},
		{"github.com/api/v3", false},
	} {
		if got := isDotcomHost(tc.host); got != tc.want {
			t.Errorf("isDotcomHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
		if c := NewGitHubMetadataClientForHost(tc.host); c.dotcom != tc.want {
			t.Errorf("NewGitHubMetadataClientForHost(%q).dotcom = %v, want %v", tc.host, c.dotcom, tc.want)
		}
	}
}

// Test_advisoriesForRepo_dotcomLoadsAdvisoriesOnly: on github.com a
// package no prefetch covered is loaded once, its advisories alone. A
// loader that stores nothing leaves an empty list, kept for the run.
func Test_advisoriesForRepo_dotcomLoadsAdvisoriesOnly(t *testing.T) {
	adv := []advisoryInfo{{GhsaID: "GHSA-x", VulnerableRange: "< 2", Severity: "high"}}
	c, loads, _ := worldClient(t, map[string]*fakeRepo{"o/r": {advisories: adv}})
	c.repoCache["o/r"] = repoCacheEntry{fetched: true}

	if got := c.advisoriesForRepo("o", "r"); !reflect.DeepEqual(got, adv) {
		t.Errorf("advisories = %+v, want %+v", got, adv)
	}
	c.advisoriesForRepo("o", "r")
	if len(*loads) != 1 || len((*loads)[0]) != 1 {
		t.Fatalf("loads = %+v, want one request", *loads)
	}
	if r := (*loads)[0][0]; r.owner != "o" || r.repo != "r" || !r.advisories || r.info || len(r.refs) != 0 {
		t.Errorf("request = %+v, want the advisories of o/r alone", r)
	}

	asked := 0
	c.load = func([]repoRequest) { asked++ }
	got := c.advisoriesForRepo("o", "silent")
	if got == nil || len(got) != 0 {
		t.Errorf("advisories = %#v, want an empty list", got)
	}
	if cached, ok := c.advisoryCache["o/silent"]; !ok || cached == nil {
		t.Errorf("cache = %#v (present %v), want the empty list kept", cached, ok)
	}
	c.advisoriesForRepo("o", "silent")
	if asked != 1 {
		t.Errorf("loads = %d, want 1", asked)
	}
}

// Test_NewClient_wiring: the constructor builds the GraphQL client beside
// the REST one, wires the loaders and the cost recorder, and a disabled
// client has neither client.
func Test_NewClient_wiring(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "")
	t.Setenv(EnvMetadataToken, "ghp_metadata")
	c := NewGitHubMetadataClientForHost("")
	if c.rest == nil || c.gql == nil || !c.dotcom || c.disabled {
		t.Errorf("github.com client: rest=%v gql=%v dotcom=%v disabled=%v", c.rest != nil, c.gql != nil, c.dotcom, c.disabled)
	}
	if c.load == nil || c.loadTags == nil || c.recordCost == nil {
		t.Error("loaders or cost recorder not wired")
	}
	if e := NewGitHubMetadataClientForHost("ghes.example.com"); e.rest == nil || e.gql == nil || e.dotcom {
		t.Errorf("GHES client: rest=%v gql=%v dotcom=%v", e.rest != nil, e.gql != nil, e.dotcom)
	}

	for _, v := range []string{"1", "true"} {
		t.Setenv(EnvDisableGitHubAPI, v)
		d := NewGitHubMetadataClientForHost("")
		if d.Available() || d.rest != nil || d.gql != nil {
			t.Errorf("%s=%s: available=%v rest=%v gql=%v, want a disabled client", EnvDisableGitHubAPI, v, d.Available(), d.rest != nil, d.gql != nil)
		}
		// A disabled client prefetches nothing and so never reaches its
		// missing GraphQL client.
		d.Prefetch([]string{"a/x@v1"})
	}
}

// Test_httpClients_areCounted: the raw host is read through Memo (the same
// file is asked many times in a run), the job-log clients through the
// counting-only transport, so the --debug report lists every request.
func Test_httpClients_areCounted(t *testing.T) {
	if rawHTTPClient.Transport != httpcount.MemoTransport {
		t.Errorf("rawHTTPClient transport = %T, want httpcount.MemoTransport", rawHTTPClient.Transport)
	}
	if jobLogsAPIClient.Transport != httpcount.DefaultTransport {
		t.Errorf("jobLogsAPIClient transport = %T, want httpcount.DefaultTransport", jobLogsAPIClient.Transport)
	}
	if jobLogsStoreClient.Transport != httpcount.DefaultTransport {
		t.Errorf("jobLogsStoreClient transport = %T, want httpcount.DefaultTransport", jobLogsStoreClient.Transport)
	}
}
