package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
)

// workflowStatesPage1 carries one active workflow and sets the Link
// header pointing at page 2, so the test also pins pagination.
func workflowStatesPage1() map[string]any {
	return map[string]any{
		"total_count": 2,
		"workflows": []map[string]any{
			{"id": 1, "path": ".github/workflows/ci.yml", "state": "active"},
		},
	}
}

// workflowStatesPage2 carries the second workflow, disabled by
// inactivity (the state MarkInert reads to mark a job inert with
// "workflow disabled (disabled_inactivity)").
func workflowStatesPage2() map[string]any {
	return map[string]any{
		"total_count": 2,
		"workflows": []map[string]any{
			{"id": 2, "path": ".github/workflows/stale.yml", "state": "disabled_inactivity"},
		},
	}
}

// TestFetchGitHubWorkflowStates_ParsesPathAndStatePaginates pins the
// shape parse (workflows[].path -> workflows[].state) and that a second
// page reached only via the Link: rel="next" header is walked too.
func TestFetchGitHubWorkflowStates_ParsesPathAndStatePaginates(t *testing.T) {
	mux := http.NewServeMux()
	var sawPage2 bool
	mux.HandleFunc("/repos/owner/repo/actions/workflows", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Header().Set("Link", `<https://api.github.com/repos/owner/repo/actions/workflows?per_page=100&page=2>; rel="next"`)
			_ = json.NewEncoder(w).Encode(workflowStatesPage1())
		case "2":
			sawPage2 = true
			_ = json.NewEncoder(w).Encode(workflowStatesPage2())
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	states, known, err := FetchGitHubWorkflowStates("", "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !known {
		t.Fatal("expected known=true on a successful listing")
	}
	if !sawPage2 {
		t.Fatal("the second page (reached via the Link header) was never requested")
	}
	if len(states) != 2 {
		t.Fatalf("expected 2 workflow states across both pages, got %d: %+v", len(states), states)
	}
	if states[".github/workflows/ci.yml"] != "active" {
		t.Errorf("ci.yml state = %q, want active", states[".github/workflows/ci.yml"])
	}
	if states[".github/workflows/stale.yml"] != "disabled_inactivity" {
		t.Errorf("stale.yml state = %q, want disabled_inactivity", states[".github/workflows/stale.yml"])
	}
}

// TestFetchGitHubWorkflowStates_ForbiddenDegradesSilently pins the
// degraded-mode contract: a 403 (no scope, private repo) yields
// known=false and NO error, since a missing optional fact caps a claim
// rather than failing collection.
func TestFetchGitHubWorkflowStates_ForbiddenDegradesSilently(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	states, known, err := FetchGitHubWorkflowStates("", "owner", "repo")
	if err != nil {
		t.Fatalf("a 403 must never surface as an error, got %v", err)
	}
	if known {
		t.Fatal("expected known=false on a 403")
	}
	if states != nil {
		t.Fatalf("expected no states on a 403, got %+v", states)
	}
}

// TestFetchGitHubWorkflowStates_NotFoundDegradesSilently mirrors the 403
// case for a 404 (the repository itself is not visible).
func TestFetchGitHubWorkflowStates_NotFoundDegradesSilently(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	states, known, err := FetchGitHubWorkflowStates("", "owner", "repo")
	if err != nil {
		t.Fatalf("a 404 must never surface as an error, got %v", err)
	}
	if known || states != nil {
		t.Fatalf("expected known=false and no states on a 404, got states=%+v known=%v", states, known)
	}
}

// TestFetchGitHubWorkflowStates_NetworkFailureDegradesSilently pins
// that a failure which never reaches an HTTP response at all (DNS,
// connection refused, timeout) degrades the same way as a 403 or 404:
// known=false, no error.
func TestFetchGitHubWorkflowStates_NetworkFailureDegradesSilently(t *testing.T) {
	orig := newGitHubRESTClient
	newGitHubRESTClient = func(host string) (*api.RESTClient, error) {
		return api.NewRESTClient(api.ClientOptions{AuthToken: "test-token", Transport: failingTransport{}})
	}
	t.Cleanup(func() { newGitHubRESTClient = orig })

	states, known, err := FetchGitHubWorkflowStates("", "owner", "repo")
	if err != nil {
		t.Fatalf("a network failure must never surface as an error, got %v", err)
	}
	if known || states != nil {
		t.Fatalf("expected known=false and no states on a network failure, got states=%+v known=%v", states, known)
	}
}

// TestFetchGitHubWorkflowStates_MissingOwnerOrRepo pins that an
// unaddressable path never reaches the network.
func TestFetchGitHubWorkflowStates_MissingOwnerOrRepo(t *testing.T) {
	states, known, err := FetchGitHubWorkflowStates("", "", "repo")
	if err != nil || known || states != nil {
		t.Fatalf("expected a quiet no-op, got states=%+v known=%v err=%v", states, known, err)
	}
}
