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
		"_After the run: HTTP 404_",
		"| Started | 2026-11-18T11:30:00Z |",
		"- 0 anonymous, counted by the 60/hour per-IP quota.",
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
		"| 6 | +0ms | GET | api.github.com | `/advisories?ecosystem=actions` | 200 | 100ms | core | 4979 |",
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

func render(t *testing.T, r Report) string {
	t.Helper()
	var b strings.Builder
	if err := r.WriteMarkdown(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// section is the report from one "## " heading to the next.
func section(t *testing.T, out, heading string) string {
	t.Helper()
	_, rest, ok := strings.Cut(out, "## "+heading+"\n")
	if !ok {
		t.Fatalf("report has no %q section:\n%s", heading, out)
	}
	body, _, _ := strings.Cut(rest, "\n## ")
	return body
}

func TestReport_rateLimitTable(t *testing.T) {
	core := map[string]RateResource{"core": {Limit: 5000, Used: 12, Remaining: 4988, Reset: 100}}
	for _, tc := range []struct {
		name   string
		limits []RateLimit
		want   []string
		absent []string
	}{
		{name: "not read", limits: nil, want: []string{"_Not read._"}, absent: []string{"###", "| Resource |"}},
		{
			name:   "the read before failed",
			limits: []RateLimit{{Credential: "GH_TOKEN", BeforeErr: errors.New("HTTP 500"), After: core}},
			want:   []string{"### GH_TOKEN", "_Before the run: HTTP 500_", "| core | 5000 | 0 | 12 | n/a | 4988 | 00:01:40Z |"},
			absent: []string{"_After the run"},
		},
		{
			name:   "the read after failed",
			limits: []RateLimit{{Credential: "GH_TOKEN", Before: core, AfterErr: errors.New("HTTP 500")}},
			want:   []string{"_After the run: HTTP 500_", "| core | 0 | 12 | 0 | n/a | 0 |  |"},
			absent: []string{"_Before the run"},
		},
		{
			name:   "both reads failed",
			limits: []RateLimit{{Credential: "GH_TOKEN", BeforeErr: errors.New("a|b"), AfterErr: errors.New("HTTP 404")}},
			want:   []string{"### GH_TOKEN", `_Before the run: a\|b_`, "_After the run: HTTP 404_"},
			absent: []string{"| Resource |", "_No resource used._"},
		},
		{
			name: "a resource only the read after lists",
			limits: []RateLimit{{
				Credential: "GH_TOKEN",
				Before:     map[string]RateResource{"core": {Limit: 5000, Used: 1, Reset: 100}},
				After:      map[string]RateResource{"core": {Limit: 5000, Used: 2, Reset: 100}, "graphql": {Limit: 5000, Used: 7, Remaining: 4993}},
			}},
			want: []string{"| core | 5000 | 1 | 2 | +1 | 0 | 00:01:40Z |\n| graphql | 5000 | 0 | 7 | +7 | 4993 |  |"},
		},
		{
			name: "no resource used",
			limits: []RateLimit{{
				Credential: "GH_TOKEN",
				Before:     map[string]RateResource{"core": {Limit: 5000}},
				After:      map[string]RateResource{"core": {Limit: 5000}},
			}},
			want:   []string{"### GH_TOKEN\n\n_No resource used._"},
			absent: []string{"| Resource |", "| core |"},
		},
		{
			name: "a quota that went down",
			limits: []RateLimit{{
				Credential: "GH_TOKEN",
				Before:     map[string]RateResource{"core": {Limit: 5000, Used: 9, Reset: 100}},
				After:      map[string]RateResource{"core": {Limit: 5000, Used: 4, Reset: 100}},
			}},
			want: []string{"| core | 5000 | 9 | 4 | -5 |"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reportFixture()
			r.RateLimits = tc.limits
			got := section(t, render(t, r), "Rate limit (`GET /rate_limit`)")
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("section misses %q\n\n%s", want, got)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("section has %q\n\n%s", absent, got)
				}
			}
		})
	}
}

// A quota row names its credential: anonymous, the name the run knows, or
// "token N" in order of first appearance, the same token keeping its number.
func TestReport_quotaCredentialNames(t *testing.T) {
	r := reportFixture()
	r.Snapshot.Entries = nil
	r.Snapshot.Quotas = []Quota{
		{Host: "api.github.com", Resource: "core", Anonymous: true, Limit: 60, Remaining: 59, Reset: 100, Requests: 2},
		{Host: "api.github.com", Resource: "core", Credential: "x", Limit: 5000, Remaining: 1, Reset: 100, Requests: 1},
		{Host: "api.github.com", Resource: "core", Credential: "y", Limit: 5000, Remaining: 2, Reset: 100, Requests: 1},
		{Host: "api.github.com", Resource: "core", Credential: "x", Limit: 5000, Remaining: 3, Reset: 900, Requests: 1},
		{Host: "api.github.com", Resource: "core", Credential: CredentialKey("token lanes"), Limit: 5000, Remaining: 4, Reset: 100, Requests: 1},
	}
	out := render(t, r)
	got := section(t, out, "Quotas seen in response headers")
	want := "| api.github.com | anonymous | core | 60 | 2 | 59 | 00:01:40Z |  |\n" +
		"| api.github.com | token 1 | core | 5000 | 1 | 1 | 00:01:40Z |  |\n" +
		"| api.github.com | token 2 | core | 5000 | 1 | 2 | 00:01:40Z |  |\n" +
		"| api.github.com | token 1 | core | 5000 | 1 | 3 | 00:15:00Z |  |\n" +
		"| api.github.com | GITHUB_TOKEN | core | 5000 | 1 | 4 | 00:01:40Z |  |\n"
	if !strings.Contains(got, want) {
		t.Fatalf("quota rows:\n%s\nwant\n%s", got, want)
	}
	for _, line := range []string{
		"- **4** counted by a token's API quota",
		"- 2 anonymous, counted by the 60/hour per-IP quota.",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("summary misses %q\n\n%s", line, out)
		}
	}
}

// A run that sent nothing says so in every section, with no empty table.
func TestReport_emptyRun(t *testing.T) {
	out := render(t, Report{})
	for heading, want := range map[string]string{
		"Rate limit (`GET /rate_limit`)":  "_Not read._",
		"Quotas seen in response headers": "_None._",
		"GraphQL queries":                 "_None._",
		"Outside the API quotas":          "_None._",
		"By endpoint":                     "_No request logged._",
		"Repeated requests":               "_None._",
		"All requests":                    "_No request logged._",
	} {
		got := section(t, out, heading)
		if !strings.Contains(got, want) {
			t.Errorf("%s: misses %q\n\n%s", heading, want, got)
		}
		if strings.Contains(got, "|---") {
			t.Errorf("%s: has a table\n\n%s", heading, got)
		}
	}
	if !strings.Contains(out, "- **0 requests** sent.") {
		t.Errorf("summary:\n%s", out)
	}
}

// Hosts whose every response carried quota headers stay out of the
// "Outside the API quotas" table.
func TestReport_unmeteredHosts(t *testing.T) {
	r := reportFixture()
	r.Snapshot.Hosts = map[string]HostStats{
		"raw.githubusercontent.com": {Requests: 3, Unmetered: 3},
		"api.github.com":            {Requests: 5},
		"codeload.github.com":       {Requests: 1, Unmetered: 1},
	}
	got := section(t, render(t, r), "Outside the API quotas")
	if want := "| codeload.github.com | 1 |\n| raw.githubusercontent.com | 3 |\n"; !strings.Contains(got, want) {
		t.Errorf("rows:\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(got, "api.github.com") {
		t.Errorf("a fully metered host is listed:\n%s", got)
	}
}

// quotaEndpoints lists the entries of q's own window only: same host,
// resource and credential, a reset within the jitter, and quota headers.
func TestQuotaEndpoints_window(t *testing.T) {
	q := Quota{Host: "api.github.com", Resource: "core", Credential: "c", Reset: 100}
	in := Entry{Method: "GET", Host: "api.github.com", Path: "/in", HasQuota: true, Resource: "core", Credential: "c", Reset: 100}
	with := func(path string, change func(*Entry)) Entry {
		e := in
		e.Path = path
		change(&e)
		return e
	}
	entries := []Entry{
		in,
		with("/host", func(e *Entry) { e.Host = "ghes.example.com" }),
		with("/resource", func(e *Entry) { e.Resource = "search" }),
		with("/credential", func(e *Entry) { e.Credential = "" }),
		with("/no-quota", func(e *Entry) { e.HasQuota = false }),
		with("/jitter-in-after", func(e *Entry) { e.Reset = 105 }),
		with("/jitter-in-before", func(e *Entry) { e.Reset = 95 }),
		with("/jitter-out-after", func(e *Entry) { e.Reset = 106 }),
		with("/jitter-out-before", func(e *Entry) { e.Reset = 94 }),
		with("/in", func(e *Entry) { e.Method = "POST" }),
	}
	want := "`GET /in` ×1, `GET /jitter-in-after` ×1, `GET /jitter-in-before` ×1, +1 more"
	if got := quotaEndpoints(q, entries); got != want {
		t.Fatalf("quotaEndpoints = %q, want %q", got, want)
	}
	if got := quotaEndpoints(q, entries[1:5]); got != "" {
		t.Fatalf("quotaEndpoints of other windows = %q, want none", got)
	}
}

// "By endpoint" counts each status class and the requests a token's quota
// answered, and orders rows by requests, then host, then endpoint.
func TestReport_byEndpoint(t *testing.T) {
	entry := func(host, path string, status int, d time.Duration) Entry {
		return Entry{Method: "GET", Host: host, Path: path, Status: status, Duration: d}
	}
	metered := func(e Entry, authenticated bool) Entry {
		e.HasQuota, e.Authenticated, e.Resource = true, authenticated, "core"
		return e
	}
	r := reportFixture()
	r.Snapshot.Entries = []Entry{
		entry("b.example", "/z", 200, time.Millisecond),
		entry("b.example", "/a", 200, time.Millisecond),
		entry("a.example", "/z", 200, time.Millisecond),
		metered(entry("api.github.com", "/repos/o/r", 200, 10*time.Millisecond), true),
		metered(entry("api.github.com", "/repos/o/r", 301, 30*time.Millisecond), false),
		metered(entry("api.github.com", "/repos/p/q", 404, 20*time.Millisecond), true),
		entry("api.github.com", "/repos/o/r", 503, 5*time.Millisecond),
		entry("api.github.com", "/repos/o/r", 0, 0),
		{Method: "POST", Host: "api.github.com", Path: "/repos/o/r", Status: 201},
	}
	got := section(t, render(t, r), "By endpoint")
	want := "| `GET /repos/{owner}/{repo}` | api.github.com | 5 | 2 | 1 | 1 | 1 | 1 | 1 | 65ms | 30ms |\n" +
		"| `GET /z` | a.example | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 1ms | 1ms |\n" +
		"| `POST /repos/{owner}/{repo}` | api.github.com | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0ms | 0ms |\n" +
		"| `GET /a` | b.example | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 1ms | 1ms |\n" +
		"| `GET /z` | b.example | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 1ms | 1ms |\n"
	if !strings.Contains(got, want) {
		t.Fatalf("rows:\n%s\nwant\n%s", got, want)
	}
}

// A repeat is the same method, host, path and query. Repeats are listed
// most repeated first, and in order of first appearance when tied.
func TestReport_repeats(t *testing.T) {
	entry := func(method, path, query string) Entry {
		return Entry{Method: method, Host: "api.github.com", Path: path, Query: query}
	}
	r := reportFixture()
	r.Snapshot.Entries = []Entry{
		entry("GET", "/twice-first", ""),
		entry("GET", "/thrice", "page=1"),
		entry("GET", "/twice-second", ""),
		entry("GET", "/thrice", "page=1"),
		entry("GET", "/twice-first", ""),
		entry("GET", "/thrice", "page=1"),
		entry("GET", "/twice-second", ""),
		entry("GET", "/thrice", "page=2"),
		entry("POST", "/once", ""),
		entry("GET", "/once", ""),
	}
	got := section(t, render(t, r), "Repeated requests")
	want := "| Times | Request |\n|--:|---|\n" +
		"| 3 | `GET api.github.com/thrice?page=1` |\n" +
		"| 2 | `GET api.github.com/twice-first` |\n" +
		"| 2 | `GET api.github.com/twice-second` |\n"
	if !strings.HasSuffix(got, want) {
		t.Fatalf("repeats:\n%s\nwant\n%s", got, want)
	}

	r.Snapshot.Entries = []Entry{entry("GET", "/a", "page=1"), entry("GET", "/a", "page=2"), entry("POST", "/a", "page=1")}
	if got := section(t, render(t, r), "Repeated requests"); !strings.HasSuffix(got, "_None._\n") || strings.Contains(got, "| Times |") {
		t.Fatalf("requests that differ by query or method are no repeat:\n%s", got)
	}
}

// The request log tells an anonymous metered answer from a token's, and a
// request with no response has an empty error cell when nothing says why.
func TestReport_allRequestsQuotaColumn(t *testing.T) {
	r := reportFixture()
	r.Snapshot.Entries = []Entry{
		{Seq: 1, Offset: 1500 * time.Millisecond, Method: "GET", Host: "api.github.com", Path: "/repos/o/r", Query: "a|b", Status: 200,
			Duration: 20 * time.Millisecond, HasQuota: true, Resource: "core", Remaining: 58},
		{Seq: 2, Method: "GET", Host: "api.github.com", Path: "/graphql", Status: 200, HasQuota: true, Authenticated: true, Resource: "graphql", Remaining: 4990},
		{Seq: 3, Method: "GET", Host: "raw.githubusercontent.com", Path: "/o/r/v1/action.yml", Status: 404, Authenticated: true},
		{Seq: 4, Method: "GET", Host: "api.github.com", Path: "/repos/o/r"},
	}
	got := section(t, render(t, r), "All requests")
	for _, want := range []string{
		"| 1 | +1500ms | GET | api.github.com | `/repos/o/r?a\\|b` | 200 | 20ms | core anonymous | 58 |",
		"| 2 | +0ms | GET | api.github.com | `/graphql` | 200 | 0ms | graphql | 4990 |",
		"| 3 | +0ms | GET | raw.githubusercontent.com | `/o/r/v1/action.yml` | 404 | 0ms | none |  |",
		"| 4 | +0ms | GET | api.github.com | `/repos/o/r` | error:  | 0ms | none |  |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log misses %q\n\n%s", want, got)
		}
	}
}

func TestEntry_Target(t *testing.T) {
	if got := (Entry{Path: "/advisories", Query: "ecosystem=actions"}).Target(); got != "/advisories?ecosystem=actions" {
		t.Fatalf("Target = %q", got)
	}
	if got := (Entry{Path: "/advisories"}).Target(); got != "/advisories" {
		t.Fatalf("Target without a query = %q", got)
	}
}

// The start is reported in UTC whatever zone the run's clock is in.
func TestReport_startIsUTC(t *testing.T) {
	r := reportFixture()
	r.Started = time.Date(2026, 11, 18, 12, 30, 0, 0, time.FixedZone("CET", 3600))
	r.Finished = r.Started.Add(1500 * time.Microsecond)
	out := render(t, r)
	for _, want := range []string{"| Started | 2026-11-18T11:30:00Z |", "| Duration | 2ms |"} {
		if !strings.Contains(out, want) {
			t.Errorf("report misses %q\n\n%s", want, out)
		}
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestReport_writeErrorIsReturned(t *testing.T) {
	disk := errors.New("disk full")
	if err := reportFixture().WriteMarkdown(failingWriter{disk}); !errors.Is(err, disk) {
		t.Fatalf("WriteMarkdown err = %v, want the writer's", err)
	}
}

func TestClock(t *testing.T) {
	if got := clock(0); got != "" {
		t.Fatalf("clock(0) = %q, want an empty cell", got)
	}
	if got := clock(3600 + 62); got != "01:01:02Z" {
		t.Fatalf("clock = %q", got)
	}
}
