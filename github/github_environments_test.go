package github

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
)

// failingTransport fails every request before it ever reaches a
// response, the same shape as a DNS failure, a refused connection or
// a timeout.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

// environmentsPage1 carries one environment ("production") with every
// rule type the situation facts read: required_reviewers (two
// reviewers, prevent_self_review), wait_timer and branch_policy. The
// handler serving it sets the Link header pointing at page 2, so the
// test also pins pagination.
func environmentsPage1() map[string]any {
	return map[string]any{
		"total_count": 2,
		"environments": []map[string]any{
			{
				"name": "production",
				"protection_rules": []map[string]any{
					{
						"type":                "required_reviewers",
						"reviewers":           []map[string]any{{"type": "User", "reviewer": map[string]any{"login": "alice"}}, {"type": "Team", "reviewer": map[string]any{"slug": "sre"}}},
						"prevent_self_review": true,
					},
					{"type": "wait_timer", "wait_timer": 30},
					{"type": "branch_policy"},
				},
				"deployment_branch_policy": nil,
			},
		},
	}
}

// environmentsPage2 carries the second environment ("staging"), with
// no protection rules at all: an environment GitHub lists but protects
// with nothing.
func environmentsPage2() map[string]any {
	return map[string]any{
		"total_count": 2,
		"environments": []map[string]any{
			{"name": "staging", "protection_rules": []map[string]any{}, "deployment_branch_policy": nil},
		},
	}
}

// TestFetchGitHubEnvironments_ParsesRulesAndPaginates pins the shape
// parse (required_reviewers with its reviewer count and
// prevent_self_review, wait_timer, branch_policy) and that a second
// page reached only via the Link: rel="next" header is walked too.
func TestFetchGitHubEnvironments_ParsesRulesAndPaginates(t *testing.T) {
	mux := http.NewServeMux()
	var sawPage2 bool
	mux.HandleFunc("/repos/owner/repo/environments", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Header().Set("Link", `<https://api.github.com/repos/owner/repo/environments?per_page=30&page=2>; rel="next"`)
			_ = json.NewEncoder(w).Encode(environmentsPage1())
		case "2":
			sawPage2 = true
			_ = json.NewEncoder(w).Encode(environmentsPage2())
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	envs, known, err := FetchGitHubEnvironments("", "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !known {
		t.Fatal("expected known=true on a successful listing")
	}
	if !sawPage2 {
		t.Fatal("the second page (reached via the Link header) was never requested")
	}
	if len(envs) != 2 {
		t.Fatalf("expected 2 environments across both pages, got %d: %+v", len(envs), envs)
	}

	prod := envs[0]
	if prod.Name != "production" || !prod.Known {
		t.Fatalf("production: %+v", prod)
	}
	if !prod.RequiredReviewers || prod.Reviewers != 2 || !prod.PreventSelfReview {
		t.Fatalf("production required_reviewers rule: %+v", prod)
	}
	if prod.WaitTimer != 30 {
		t.Fatalf("production wait_timer: %+v", prod)
	}
	if !prod.BranchPolicy {
		t.Fatalf("production branch_policy: %+v", prod)
	}

	staging := envs[1]
	if staging.Name != "staging" || !staging.Known {
		t.Fatalf("staging: %+v", staging)
	}
	if staging.RequiredReviewers || staging.Reviewers != 0 || staging.PreventSelfReview || staging.WaitTimer != 0 || staging.BranchPolicy {
		t.Fatalf("staging must carry no rules, got %+v", staging)
	}
}

// TestFetchGitHubEnvironments_DeploymentBranchPolicySetsBranchPolicy
// pins the second, independent branch_policy signal: a non-null
// deployment_branch_policy object sets BranchPolicy even without a
// branch_policy protection rule.
func TestFetchGitHubEnvironments_DeploymentBranchPolicySetsBranchPolicy(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_count": 1,
			"environments": []map[string]any{
				{"name": "prod", "protection_rules": []map[string]any{}, "deployment_branch_policy": map[string]any{"protected_branches": false, "custom_branch_policies": true}},
			},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	envs, known, err := FetchGitHubEnvironments("", "owner", "repo")
	if err != nil || !known {
		t.Fatalf("unexpected result: envs=%+v known=%v err=%v", envs, known, err)
	}
	if len(envs) != 1 || !envs[0].BranchPolicy {
		t.Fatalf("expected deployment_branch_policy alone to set BranchPolicy, got %+v", envs)
	}
}

// TestFetchGitHubEnvironments_ForbiddenDegradesSilently pins the
// degraded-mode contract: a 403 (no scope, private repo) yields
// known=false and NO error, since a missing optional fact caps a
// claim rather than failing collection.
func TestFetchGitHubEnvironments_ForbiddenDegradesSilently(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	envs, known, err := FetchGitHubEnvironments("", "owner", "repo")
	if err != nil {
		t.Fatalf("a 403 must never surface as an error, got %v", err)
	}
	if known {
		t.Fatal("expected known=false on a 403")
	}
	if envs != nil {
		t.Fatalf("expected no environments on a 403, got %+v", envs)
	}
}

// TestFetchGitHubEnvironments_NotFoundDegradesSilently mirrors the 403
// case for a 404 (environments unsupported, or the repository itself
// is not visible).
func TestFetchGitHubEnvironments_NotFoundDegradesSilently(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	envs, known, err := FetchGitHubEnvironments("", "owner", "repo")
	if err != nil {
		t.Fatalf("a 404 must never surface as an error, got %v", err)
	}
	if known || envs != nil {
		t.Fatalf("expected known=false and no environments on a 404, got envs=%+v known=%v", envs, known)
	}
}

// TestFetchGitHubEnvironments_OtherStatusReturnsErrorForLogging pins
// the "other statuses" branch: known is still false, but the error is
// returned so the caller can log it (never propagated as a collection
// failure).
func TestFetchGitHubEnvironments_OtherStatusReturnsErrorForLogging(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	envs, known, err := FetchGitHubEnvironments("", "owner", "repo")
	if err == nil {
		t.Fatal("expected an error on a 500 so the caller can log it")
	}
	if known || envs != nil {
		t.Fatalf("expected known=false and no environments on a 500, got envs=%+v known=%v", envs, known)
	}
}

// TestFetchGitHubEnvironments_NetworkFailureDegradesSilently pins
// that a failure which never reaches an HTTP response at all (DNS,
// connection refused, timeout) degrades the same way as a 403 or 404:
// known=false, no error.
func TestFetchGitHubEnvironments_NetworkFailureDegradesSilently(t *testing.T) {
	orig := newGitHubRESTClient
	newGitHubRESTClient = func(host string) (*api.RESTClient, error) {
		return api.NewRESTClient(api.ClientOptions{AuthToken: "test-token", Transport: failingTransport{}})
	}
	t.Cleanup(func() { newGitHubRESTClient = orig })

	envs, known, err := FetchGitHubEnvironments("", "owner", "repo")
	if err != nil {
		t.Fatalf("a network failure must never surface as an error, got %v", err)
	}
	if known || envs != nil {
		t.Fatalf("expected known=false and no environments on a network failure, got envs=%+v known=%v", envs, known)
	}
}

// TestFetchGitHubEnvironments_MissingOwnerOrRepo pins that an
// unaddressable path never reaches the network.
func TestFetchGitHubEnvironments_MissingOwnerOrRepo(t *testing.T) {
	envs, known, err := FetchGitHubEnvironments("", "", "repo")
	if err != nil || known || envs != nil {
		t.Fatalf("expected a quiet no-op, got envs=%+v known=%v err=%v", envs, known, err)
	}
}
