package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// tagAPI is a fake GitHub serving the rulesets listing, per-ruleset
// details and the tags listing. status overrides the response code per
// path prefix (e.g. "/repos/o/r/rulesets" → 403).
type tagAPI struct {
	summaries []map[string]any
	details   map[int64]map[string]any
	tags      []string
	status    map[string]int
	hits      map[string]int
}

func (a *tagAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	a.hits = map[string]int{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		a.hits[p]++
		for prefix, code := range a.status {
			if p == prefix {
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"message":"nope"}`))
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case p == "/repos/o/r/rulesets":
			if r.URL.Query().Get("includes_parents") != "true" || r.URL.Query().Get("targets") != "tag" {
				t.Errorf("rulesets listing query = %q, want includes_parents=true and targets=tag", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(pageOf(r, a.summaries))
		case strings.HasPrefix(p, "/repos/o/r/rulesets/"):
			id, _ := strconv.ParseInt(strings.TrimPrefix(p, "/repos/o/r/rulesets/"), 10, 64)
			d, ok := a.details[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(d)
		case p == "/repos/o/r/tags":
			named := make([]map[string]string, len(a.tags))
			for i, tag := range a.tags {
				named[i] = map[string]string{"name": tag}
			}
			_ = json.NewEncoder(w).Encode(pageOf(r, named))
		default:
			t.Errorf("unexpected request %s", p)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// pageOf serves the page and per_page the request asks for.
func pageOf[T any](r *http.Request, all []T) []T {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	start := min((page-1)*per, len(all))
	return all[start:min(start+per, len(all))]
}

func summary(id int64, enforcement, sourceType string) map[string]any {
	return map[string]any{"id": id, "name": fmt.Sprintf("rs-%d", id), "target": "tag", "source_type": sourceType, "enforcement": enforcement}
}

func detail(id int64, sourceType string, include, exclude []string, rules ...string) map[string]any {
	rs := []map[string]any{}
	for _, r := range rules {
		rs = append(rs, map[string]any{"type": r})
	}
	return map[string]any{
		"id": id, "name": fmt.Sprintf("rs-%d", id), "target": "tag", "source_type": sourceType, "enforcement": "active",
		"conditions": map[string]any{"ref_name": map[string]any{"include": include, "exclude": exclude}},
		"rules":      rs,
	}
}

func TestFetchGitHubTagProtection_MapsActiveRulesetsAndTags(t *testing.T) {
	org := detail(2, "Organization", []string{"~ALL"}, nil, "creation")
	// An organization ruleset on every repository: GitHub's ~ALL sentinel.
	org["conditions"].(map[string]any)["repository_name"] = map[string]any{"include": []string{"~ALL"}, "exclude": []string{}}
	otherRepo := detail(4, "Organization", []string{"~ALL"}, nil, "update")
	otherRepo["conditions"].(map[string]any)["repository_name"] = map[string]any{"include": []string{"elsewhere"}}
	api := &tagAPI{
		summaries: []map[string]any{
			summary(1, "active", "Repository"),
			summary(2, "active", "Organization"),
			summary(3, "evaluate", "Repository"),
			summary(4, "active", "Organization"),
			// A branch ruleset an old GHES returns despite targets=tag.
			{"id": 5, "target": "branch", "enforcement": "active", "source_type": "Repository"},
		},
		details: map[int64]map[string]any{
			1: detail(1, "Repository", []string{"refs/tags/v*"}, []string{"refs/tags/v*-rc*"}, "update", "deletion", "non_fast_forward"),
			2: org,
			4: otherRepo,
		},
		tags: []string{"v1.0.0", "v0.9.0"},
	}
	srv := api.server(t)
	defer srv.Close()
	swapRESTClient(t, srv)

	got, err := FetchGitHubTagProtection("", "o", "r")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := &ir.TagProtection{
		Known: true,
		Rules: []ir.TagProtectionRule{
			{ID: "1", Name: "rs-1", Source: ir.TagRuleSourceRepositoryRuleset, Include: []string{"v*"}, Exclude: []string{"v*-rc*"}, BlocksUpdate: true, BlocksDeletion: true},
			{ID: "2", Name: "rs-2", Source: ir.TagRuleSourceOrganizationRuleset, Include: []string{"**"}, RestrictsCreation: true},
		},
		Tags: []string{"v1.0.0", "v0.9.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	if api.hits["/repos/o/r/rulesets/3"] != 0 || api.hits["/repos/o/r/rulesets/5"] != 0 {
		t.Error("evaluate-mode and branch rulesets must not be fetched in detail")
	}
}

// No rulesets and no tags is an authoritative answer, not missing data.
func TestFetchGitHubTagProtection_EmptyIsKnown(t *testing.T) {
	api := &tagAPI{}
	srv := api.server(t)
	defer srv.Close()
	swapRESTClient(t, srv)

	got, err := FetchGitHubTagProtection("", "o", "r")
	if err != nil || got == nil || !got.Known || len(got.Rules) != 0 || len(got.Tags) != 0 {
		t.Fatalf("got %+v, %v; want Known with nothing in it", got, err)
	}
}

// Missing scope or a GHES without rulesets: not evaluated, no error, so
// the run is not degraded and nothing is flagged.
func TestFetchGitHubTagProtection_ForbiddenOrMissingIsUnknown(t *testing.T) {
	cases := map[string]map[string]int{
		"rulesets 403":       {"/repos/o/r/rulesets": http.StatusForbidden},
		"rulesets 404":       {"/repos/o/r/rulesets": http.StatusNotFound},
		"ruleset detail 404": {"/repos/o/r/rulesets/1": http.StatusNotFound},
		"tags 401":           {"/repos/o/r/tags": http.StatusUnauthorized},
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			api := &tagAPI{
				summaries: []map[string]any{summary(1, "active", "Repository")},
				details:   map[int64]map[string]any{1: detail(1, "Repository", []string{"~ALL"}, nil, "update")},
				status:    status,
			}
			srv := api.server(t)
			defer srv.Close()
			swapRESTClient(t, srv)

			got, err := FetchGitHubTagProtection("", "o", "r")
			if err != nil {
				t.Fatalf("want no error, got %v", err)
			}
			if got == nil || got.Known {
				t.Fatalf("want Known=false, got %+v", got)
			}
		})
	}
}

// A server error is a failed collection: the caller degrades the run.
func TestFetchGitHubTagProtection_ServerErrorIsReturned(t *testing.T) {
	api := &tagAPI{status: map[string]int{"/repos/o/r/tags": http.StatusInternalServerError}}
	srv := api.server(t)
	defer srv.Close()
	swapRESTClient(t, srv)

	got, err := FetchGitHubTagProtection("", "o", "r")
	if err == nil {
		t.Fatal("want an error on a 500")
	}
	if got == nil || got.Known {
		t.Fatalf("want Known=false alongside the error, got %+v", got)
	}
}

func TestFetchGitHubTagProtection_TagListingCap(t *testing.T) {
	api := &tagAPI{}
	for i := range maxTagListingPages*100 + 5 {
		api.tags = append(api.tags, fmt.Sprintf("t%d", i))
	}
	srv := api.server(t)
	defer srv.Close()
	swapRESTClient(t, srv)

	got, err := FetchGitHubTagProtection("", "o", "r")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Known || !got.TagsTruncated || len(got.Tags) != maxTagListingPages*100 {
		t.Fatalf("want Known, truncated, %d tags; got known=%v truncated=%v n=%d", maxTagListingPages*100, got.Known, got.TagsTruncated, len(got.Tags))
	}
}

// Past the listing cap a ruleset protecting a pattern could be missed:
// not evaluated rather than a finding invented from a partial list.
func TestFetchGitHubTagProtection_RulesetListingCapIsUnknown(t *testing.T) {
	api := &tagAPI{}
	for i := range maxBranchListingPages * 100 {
		api.summaries = append(api.summaries, summary(int64(i+1), "disabled", "Repository"))
	}
	srv := api.server(t)
	defer srv.Close()
	swapRESTClient(t, srv)

	got, err := FetchGitHubTagProtection("", "o", "r")
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if got == nil || got.Known {
		t.Fatalf("want Known=false, got %+v", got)
	}
}

// Dropping an organization ruleset that applies would invent a finding,
// keeping one that does not would hide one.
func TestRulesetAppliesToRepo(t *testing.T) {
	cases := []struct {
		name string
		cond *remoteIncludeExclude
		want bool
	}{
		{"no repository condition", nil, true},
		{"every repository", &remoteIncludeExclude{Include: []string{"~ALL"}}, true},
		{"name pattern matching", &remoteIncludeExclude{Include: []string{"r*"}}, true},
		{"name pattern not matching", &remoteIncludeExclude{Include: []string{"elsewhere"}}, false},
		{"every repository but this one", &remoteIncludeExclude{Include: []string{"~ALL"}, Exclude: []string{"r"}}, false},
		{"every repository but others", &remoteIncludeExclude{Include: []string{"~ALL"}, Exclude: []string{"other*"}}, true},
		{"exclude only, matching", &remoteIncludeExclude{Exclude: []string{"r*"}}, false},
		{"exclude only, not matching", &remoteIncludeExclude{Exclude: []string{"other"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := &remoteRuleset{}
			rs.Conditions.RepositoryName = tc.cond
			if got := rulesetAppliesToRepo(rs, "r"); got != tc.want {
				t.Fatalf("rulesetAppliesToRepo = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeGitHubTagPattern(t *testing.T) {
	for in, want := range map[string]string{
		"~ALL":           "**",
		"refs/tags/v*":   "v*",
		"v*":             "v*",
		"refs/tags/**/x": "**/x",
	} {
		if got := normalizeGitHubTagPattern(in); got != want {
			t.Errorf("normalizeGitHubTagPattern(%q) = %q, want %q", in, got, want)
		}
	}
}
