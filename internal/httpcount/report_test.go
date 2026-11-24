package httpcount

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func reportFixture() Report {
	start := time.Date(2026, 11, 18, 11, 30, 0, 0, time.UTC)
	lanes := CredentialKey("token lanes")
	quota := func(seq int, path string, status, remaining int) Entry {
		return Entry{Seq: seq, Method: "GET", Host: "api.github.com", Path: path, Status: status, Duration: 100 * time.Millisecond,
			Authenticated: true, Credential: lanes, HasQuota: true, Resource: "core", Limit: 5000, Remaining: remaining, Reset: 1795000149}
	}
	advisories := quota(6, "/advisories", 200, 4979)
	advisories.Query, advisories.Reset = "ecosystem=actions", 1795003000
	metadata := quota(7, "/repos/actions/checkout", 200, 4999)
	metadata.Credential, metadata.Reset = CredentialKey("token other"), 1795004000
	return Report{
		Version:         "dev",
		Target:          "getplumber/plumber (remote)",
		Host:            "api.github.com",
		Started:         start,
		Finished:        start.Add(90 * time.Second),
		Credentials:     []string{"GitHub lanes: GITHUB_TOKEN"},
		CredentialNames: map[string]string{lanes: "GITHUB_TOKEN"},
		RateLimits: []RateLimit{
			{
				Credential: "GITHUB_TOKEN",
				Before:     map[string]RateResource{"core": {Limit: 5000, Used: 10, Remaining: 4990, Reset: 1795000149}, "search": {Limit: 30}},
				After:      map[string]RateResource{"core": {Limit: 5000, Used: 13, Remaining: 4987, Reset: 1795000149}, "search": {Limit: 30}},
			},
			{Credential: "PLUMBER_METADATA_TOKEN", BeforeErr: errors.New("HTTP 404"), AfterErr: errors.New("HTTP 404")},
		},
		Snapshot: Snapshot{
			MemoHits: 4,
			Hosts: map[string]HostStats{
				"api.github.com":            {Requests: 6, Status2xx: 4, Status4xx: 1, Errors: 1},
				"raw.githubusercontent.com": {Requests: 1, Status4xx: 1, Unmetered: 1},
			},
			Quotas: []Quota{
				{Host: "api.github.com", Resource: "core", Credential: lanes, Limit: 5000, Remaining: 4987, Reset: 1795000149, Requests: 3},
				{Host: "api.github.com", Resource: "core", Credential: lanes, Limit: 5000, Remaining: 4979, Reset: 1795003000, Requests: 1},
				{Host: "api.github.com", Resource: "core", Credential: metadata.Credential, Limit: 5000, Remaining: 4999, Reset: 1795004000, Requests: 1},
			},
			Entries: []Entry{
				quota(1, "/repos/actions/checkout/git/ref/tags/v4", 200, 4989),
				quota(2, "/repos/actions/checkout/git/ref/tags/v4", 200, 4988),
				quota(3, "/repos/actions/setup-go/branches/v5", 404, 4987),
				{Seq: 4, Method: "GET", Host: "api.github.com", Path: "/repos/o/r", Err: "dial tcp: timeout"},
				{Seq: 5, Method: "GET", Host: "raw.githubusercontent.com", Path: "/actions/checkout/v4/action.yaml", Status: 404},
				advisories,
				metadata,
			},
		},
	}
}

func renderFixture(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if err := reportFixture().WriteMarkdown(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestReport_sections(t *testing.T) {
	out := renderFixture(t)
	for _, want := range []string{
		"# Plumber GitHub request report",
		"| Target | getplumber/plumber (remote) |",
		"| Duration | 1m30s |",
		"| Credentials | GitHub lanes: GITHUB_TOKEN |",
		"- **7 requests** sent.",
		"- 4 repeated requests answered from memory, not sent.",
		"- **5** counted by a token's API quota",
		"- 1 outside the API quotas",
		"- 1 without a response (errors).",
		"## Rate limit (`GET /rate_limit`)",
		"### GITHUB_TOKEN",
		"| core | 5000 | 10 | 13 | +3 | 4987 | 11:09:09Z |",
		"_Before the run: HTTP 404_",
		"## Quotas seen in response headers",
		"| api.github.com | GITHUB_TOKEN | core | 5000 | 3 | 4987 | 11:09:09Z | " +
			"`GET /repos/{owner}/{repo}/git/ref/tags/{tag}` ×2, `GET /repos/{owner}/{repo}/branches/{branch}` ×1 |",
		"| api.github.com | GITHUB_TOKEN | core | 5000 | 1 | 4979 | 11:56:40Z | `GET /advisories` ×1 |",
		"| api.github.com | token 1 | core | 5000 | 1 | 4999 | 12:13:20Z | `GET /repos/{owner}/{repo}` ×1 |",
		"> Observed, not documented: GitHub labels `/advisories` responses `core`",
		"## Outside the API quotas",
		"| raw.githubusercontent.com | 1 |",
		"## By endpoint",
		"| `GET /repos/{owner}/{repo}/git/ref/tags/{tag}` | api.github.com | 2 | 2 | 2 | 0 | 0 | 0 | 0 | 200ms | 100ms |",
		"| `GET /{owner}/{repo}/{ref}/action.yaml` | raw.githubusercontent.com | 1 | 0 | 0 | 0 | 1 | 0 | 0 |",
		"## Repeated requests",
		"| 2 | `GET api.github.com/repos/actions/checkout/git/ref/tags/v4` |",
		"## All requests",
		"| 3 | +0ms | GET | api.github.com | `/repos/actions/setup-go/branches/v5` | 404 | 100ms | core | 4987 |",
		"| 4 | +0ms | GET | api.github.com | `/repos/o/r` | error: dial tcp: timeout | 0ms | none |  |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report misses %q\n\n%s", want, out)
		}
	}
	// A resource the run did not touch stays out of the rate-limit table.
	if strings.Contains(out, "| search |") {
		t.Errorf("unused resource listed:\n%s", out)
	}
}

// Two /rate_limit reads in different windows have no meaningful difference.
func TestReport_rateLimitWindowReset(t *testing.T) {
	r := reportFixture()
	r.RateLimits = []RateLimit{{
		Credential: "GITHUB_TOKEN",
		Before:     map[string]RateResource{"core": {Limit: 5000, Used: 4000, Reset: 100}},
		After:      map[string]RateResource{"core": {Limit: 5000, Used: 12, Reset: 3700}},
	}}
	var b strings.Builder
	if err := r.WriteMarkdown(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "| core | 5000 | 4000 | 12 | window reset |") {
		t.Fatalf("window reset not reported:\n%s", b.String())
	}
}

// A window fed by many endpoints lists the top ones, then how many more.
func TestQuotaEndpoints_capped(t *testing.T) {
	q := Quota{Host: "api.github.com", Resource: "core", Reset: 100}
	var entries []Entry
	for i, path := range []string{"/a", "/a", "/a", "/b", "/b", "/c", "/d", "/e"} {
		entries = append(entries, Entry{Seq: i + 1, Method: "GET", Host: "api.github.com", Path: path, HasQuota: true, Resource: "core", Reset: 100})
	}
	// Another window and another credential stay out.
	entries = append(entries,
		Entry{Method: "GET", Host: "api.github.com", Path: "/x", HasQuota: true, Resource: "core", Reset: 900},
		Entry{Method: "GET", Host: "api.github.com", Path: "/y", HasQuota: true, Resource: "core", Reset: 100, Credential: "other"})

	if got, want := quotaEndpoints(q, entries), "`GET /a` ×3, `GET /b` ×2, `GET /c` ×1, +2 more"; got != want {
		t.Fatalf("quotaEndpoints = %q, want %q", got, want)
	}
}

// The GraphQL section lists each query, the points it cost and the budget
// left, with the total.
func TestReport_graphQLSection(t *testing.T) {
	r := reportFixture()
	r.Snapshot.GraphQL = []GraphQLQuery{{Label: "action metadata: 20 repositories", Cost: 2, Remaining: 4990}, {Label: "tag listing: 3 repositories", Cost: 1, Remaining: 4989}}
	var b strings.Builder
	if err := r.WriteMarkdown(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"## GraphQL queries",
		"- **2 queries**, 3 points.",
		"| 1 | action metadata: 20 repositories | 2 | 4990 |",
		"| 2 | tag listing: 3 repositories | 1 | 4989 |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report misses %q\n\n%s", want, out)
		}
	}
	if !strings.Contains(renderFixture(t), "## GraphQL queries\n\n_None._") {
		t.Error("a run without GraphQL queries does not say so")
	}
}

func TestCell(t *testing.T) {
	if got := cell("a|b\nc"); got != `a\|b c` {
		t.Fatalf("cell = %q", got)
	}
}
