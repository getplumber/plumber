package github

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
	version "github.com/hashicorp/go-version"
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

// Test_fetchAllTags_anonymousFallbackOn403 is the ISSUE-228 Problem 2
// regression: when the authenticated tags read is blocked by the owner
// org's IP allow list (403), Plumber retries anonymously (public repos are
// not gated for anonymous reads) and resolves the version instead of
// abstaining. The authenticated transport always 403s; the anonymous base
// URL points at a test server that serves the tags only when no auth header
// is present.
func Test_fetchAllTags_anonymousFallbackOn403(t *testing.T) {
	const sha = "abcdef0000000000000000000000000000000000"
	anon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"name":"v1.2.3","commit":{"sha":"`+sha+`"}}]`)
	}))
	defer anon.Close()

	c := NewGitHubMetadataClientForHost("")
	c.apiBaseURL = anon.URL
	rest, err := api.NewRESTClient(api.ClientOptions{
		AuthToken: "x",
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader(`{"message":"org has an IP allow list enabled"}`)),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("new rest client: %v", err)
	}
	c.rest = rest

	tags := c.fetchAllTags("aquasecurity", "trivy-action")
	if tags[sha] != "v1.2.3" {
		t.Fatalf("anonymous fallback did not resolve the SHA: got %v, want %s -> v1.2.3", tags, sha)
	}
}

// Test_commitResolves_triState is the ISSUE-707 correctness guard: a
// commit lookup must distinguish a definitive answer (the SHA is absent
// upstream) from an unverifiable error (403, rate limit, network). Only
// the confirmed-absent case may drive impostor-commit; every other
// failure must leave checked=false so a valid SHA we could not reach is
// never flagged. GitHub answers a well-formed but nonexistent 40-char
// SHA with 422 "No commit found for SHA" (NOT 404) — that 422 case is
// the exact real-world signal this control depends on. The old
// bool-only commitExists conflated 403 with a real absence.
func Test_commitResolves_triState(t *testing.T) {
	const (
		presentSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		absent422  = "dddddddddddddddddddddddddddddddddddddddd"
		absent404  = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		gatedSHA   = "ffffffffffffffffffffffffffffffffffffffff"
	)
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, status := `{}`, http.StatusOK
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits/"+absent422):
			body, status = `{"message":"No commit found for SHA: `+absent422+`"}`, http.StatusUnprocessableEntity
		case strings.HasSuffix(r.URL.Path, "/commits/"+absent404):
			body, status = `{"message":"Not Found"}`, http.StatusNotFound
		case strings.HasSuffix(r.URL.Path, "/commits/"+gatedSHA):
			body, status = `{"message":"API rate limit exceeded"}`, http.StatusForbidden
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	c := NewGitHubMetadataClientForHost("")
	rest, err := api.NewRESTClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new rest client: %v", err)
	}
	c.rest = rest

	cases := []struct {
		name        string
		sha         string
		wantExists  bool
		wantChecked bool
	}{
		{"present SHA resolves", presentSHA, true, true},
		{"absent full SHA is a confirmed 422", absent422, false, true},
		{"absent ref is a confirmed 404", absent404, false, true},
		{"rate-limited lookup is unverified", gatedSHA, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exists, checked := c.commitResolves("actions", "checkout", tc.sha)
			if exists != tc.wantExists || checked != tc.wantChecked {
				t.Fatalf("commitResolves = (exists=%v, checked=%v), want (exists=%v, checked=%v)",
					exists, checked, tc.wantExists, tc.wantChecked)
			}
		})
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
// that gate (`checked && info.err == nil`) lives in resolveUncached — so
// we drive the whole method through an httptest transport. A
// private/missing repo whose commits endpoint also 404s must NOT be
// reported as an impostor: that would be a critical false positive on a
// legitimately unreachable action. The readable-repo positive path is
// locked too, so a broken guard cannot silently disable the control.
func Test_resolveUncached_refKnownAbsentGuard(t *testing.T) {
	const (
		owner = "acme"
		repo  = "widget"
		sha   = "abcdef0123456789abcdef0123456789abcdef01"
	)
	// The tag / branch / commit lookups are all absent so the ref falls
	// through to the commit probe; repoStatus decides whether the
	// repository object itself reads (info.err == nil) or errors.
	newClient := func(t *testing.T, repoStatus, commitStatus int) *GitHubMetadataClient {
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			p := r.URL.Path
			body, status := `{}`, http.StatusNotFound
			switch {
			case p == "/repos/"+owner+"/"+repo:
				body, status = `{"archived":false,"stargazers_count":0}`, repoStatus
			case strings.Contains(p, "/releases"):
				body, status = `[]`, http.StatusOK
			case strings.HasPrefix(p, "/advisories"):
				body, status = `[]`, http.StatusOK
			case strings.Contains(p, "/commits/"):
				body, status = `{"message":"No commit found for SHA"}`, commitStatus
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		})
		c := NewGitHubMetadataClientForHost("")
		rest, err := api.NewRESTClient(api.ClientOptions{AuthToken: "x", Transport: rt})
		if err != nil {
			t.Fatalf("new rest client: %v", err)
		}
		c.rest = rest
		return c
	}

	t.Run("readable repo + absent commit is a confirmed impostor", func(t *testing.T) {
		c := newClient(t, http.StatusOK, http.StatusUnprocessableEntity)
		m := c.resolveUncached(owner, repo, sha)
		if !m.RefKnownAbsent {
			t.Fatal("readable repo whose commit 422s must set RefKnownAbsent=true")
		}
		if m.RefExists {
			t.Fatal("RefExists must stay false for an absent commit")
		}
	})

	t.Run("unreadable repo does not become an impostor", func(t *testing.T) {
		c := newClient(t, http.StatusNotFound, http.StatusNotFound)
		m := c.resolveUncached(owner, repo, sha)
		if m.RefKnownAbsent {
			t.Fatal("a private/missing repo (repoInfo errors) must NOT be reported as an impostor; RefKnownAbsent must stay false")
		}
	})
}

// Test_tagObjectResolves covers the ISSUE-401 dereference step. A pin
// can name an annotated tag OBJECT rather than the commit that tag
// points at (what `git rev-parse v1.2.3` returns without `^{commit}`).
// The commits endpoint answers 422 for those SHAs, so the collector
// needs git/tags/{sha} to tell a real tag object apart from a SHA that
// is genuinely absent upstream. The tri-state contract matches
// commitResolves: checked is true only on a definitive answer.
func Test_tagObjectResolves(t *testing.T) {
	const (
		tagObjectSHA = "7088e561eb65bb68695d245aa206f005ef30921d"
		commitSHA    = "a7487c7e89a18df4991f7f222e4898a00d66ddda"
		absentSHA    = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		gatedSHA     = "ffffffffffffffffffffffffffffffffffffffff"
		nestedSHA    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		danglingSHA  = "cccccccccccccccccccccccccccccccccccccccc"
		danglingCmt  = "1111111111111111111111111111111111111111"
	)
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		p := r.URL.Path
		body, status := `{}`, http.StatusOK
		switch {
		case strings.HasSuffix(p, "/git/tags/"+tagObjectSHA):
			body = `{"sha":"` + tagObjectSHA + `","tag":"v4.1.0","object":{"sha":"` + commitSHA + `","type":"commit"}}`
		case strings.HasSuffix(p, "/git/tags/"+nestedSHA):
			body = `{"sha":"` + nestedSHA + `","tag":"v9","object":{"sha":"` + tagObjectSHA + `","type":"tag"}}`
		case strings.HasSuffix(p, "/git/tags/"+danglingSHA):
			body = `{"sha":"` + danglingSHA + `","tag":"v8","object":{"sha":"` + danglingCmt + `","type":"commit"}}`
		case strings.HasSuffix(p, "/git/tags/"+absentSHA):
			body, status = `{"message":"Not Found"}`, http.StatusNotFound
		case strings.HasSuffix(p, "/git/tags/"+gatedSHA):
			body, status = `{"message":"API rate limit exceeded"}`, http.StatusForbidden
		case strings.HasSuffix(p, "/commits/"+commitSHA):
			body = `{"sha":"` + commitSHA + `"}`
		case strings.HasSuffix(p, "/commits/"+danglingCmt):
			body, status = `{"message":"No commit found for SHA"}`, http.StatusUnprocessableEntity
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	c := NewGitHubMetadataClientForHost("")
	rest, err := api.NewRESTClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new rest client: %v", err)
	}
	c.rest = rest

	cases := []struct {
		name        string
		sha         string
		wantCommit  string
		wantExists  bool
		wantChecked bool
	}{
		{"annotated tag object dereferences to its commit", tagObjectSHA, commitSHA, true, true},
		{"absent SHA is a confirmed 404", absentSHA, "", false, true},
		{"rate-limited lookup is unverified", gatedSHA, "", false, false},
		{"nested tag object is not claimed as a commit", nestedSHA, "", false, false},
		// The SHA plainly exists upstream (git/tags served it), so
		// "does not exist in the upstream repository" would be a false
		// statement at critical severity. Abstain instead.
		{"tag object whose commit will not confirm abstains", danglingSHA, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commit, exists, checked := c.tagObjectResolves("pnpm", "action-setup", tc.sha)
			if commit != tc.wantCommit || exists != tc.wantExists || checked != tc.wantChecked {
				t.Fatalf("tagObjectResolves = (%q, exists=%v, checked=%v), want (%q, exists=%v, checked=%v)",
					commit, exists, checked, tc.wantCommit, tc.wantExists, tc.wantChecked)
			}
		})
	}
}

// Test_resolveUncached_annotatedTagObjectPin is the ISSUE-401
// regression guard. Pinning an action to the SHA of an annotated tag
// object is a normal outcome of pinning by hand or with a script, the
// pin is immutable, and GitHub Actions resolves it. The commits
// endpoint still answers 422 for it, so without the git/tags fallback
// the collector marks it RefKnownAbsent and impostor-commit
// (ISSUE-707, critical) fires on a perfectly valid pin.
func Test_resolveUncached_annotatedTagObjectPin(t *testing.T) {
	const (
		owner        = "pnpm"
		repo         = "action-setup"
		tagObjectSHA = "7088e561eb65bb68695d245aa206f005ef30921d"
		commitSHA    = "a7487c7e89a18df4991f7f222e4898a00d66ddda"
	)
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		p := r.URL.Path
		body, status := `{}`, http.StatusNotFound
		switch {
		case p == "/repos/"+owner+"/"+repo:
			body, status = `{"archived":false,"stargazers_count":900}`, http.StatusOK
		case strings.Contains(p, "/releases"):
			body, status = `[]`, http.StatusOK
		case strings.HasPrefix(p, "/advisories"):
			body, status = `[]`, http.StatusOK
		case strings.HasSuffix(p, "/git/tags/"+tagObjectSHA):
			body, status = `{"sha":"`+tagObjectSHA+`","tag":"v4.1.0","object":{"sha":"`+commitSHA+`","type":"commit"}}`, http.StatusOK
		case strings.HasSuffix(p, "/commits/"+commitSHA):
			body, status = `{"sha":"`+commitSHA+`"}`, http.StatusOK
		case strings.HasSuffix(p, "/commits/"+tagObjectSHA):
			body, status = `{"message":"No commit found for SHA: `+tagObjectSHA+`"}`, http.StatusUnprocessableEntity
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	c := NewGitHubMetadataClientForHost("")
	rest, err := api.NewRESTClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new rest client: %v", err)
	}
	c.rest = rest

	m := c.resolveUncached(owner, repo, tagObjectSHA)
	if m.RefKnownAbsent {
		t.Fatal("a pin naming a resolvable annotated tag object must NOT be reported as absent upstream (ISSUE-707 false positive)")
	}
	if !m.RefExists {
		t.Fatal("a resolvable annotated tag object must count as existing upstream")
	}
	if m.RefKind != "commit" {
		t.Fatalf("RefKind = %q, want \"commit\": the pin designates a commit through the tag object, and refKind==\"tag\" means the ref is a tag NAME", m.RefKind)
	}
	if m.RefCommitSha != commitSHA {
		t.Fatalf("RefCommitSha = %q, want %q (the commit the tag object dereferences to)", m.RefCommitSha, commitSHA)
	}
}
