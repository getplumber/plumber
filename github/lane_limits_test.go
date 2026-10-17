package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// TestDefaultTokenLogRouteStopsAfterThreeJobsCalls pins the run-selection
// bound: on a listing of five eligible runs whose jobs endpoint answers
// nothing, the log route asks for at most three runs' jobs, then gives up.
func TestDefaultTokenLogRouteStopsAfterThreeJobsCalls(t *testing.T) {
	var jobsCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, _ *http.Request) {
		var runs []remoteRun
		for id := int64(1); id <= 5; id++ {
			runs = append(runs, pushRun(id, ".github/workflows/ci.yml"))
		}
		_ = json.NewEncoder(w).Encode(runsPage(runs...))
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/", func(w http.ResponseWriter, _ *http.Request) {
		jobsCalls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "unknown" || source != "unknown" {
		t.Errorf("write/source = %q/%q, want unknown/unknown", write, source)
	}
	if got := jobsCalls.Load(); got != 3 {
		t.Errorf("jobs calls = %d, want 3", got)
	}
}

// endlessPages serves path with a rel="next" link on every page, counting
// the requests, so a pagination loop without a cap would never stop.
func endlessPages(t *testing.T, path string, body any) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	mux := http.NewServeMux()
	var server *httptest.Server
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n > 100 {
			t.Fatalf("%s: more than 100 pages requested", path)
		}
		w.Header().Set("Link", `<`+server.URL+path+`?page=9>; rel="next"`)
		_ = json.NewEncoder(w).Encode(body)
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	swapRESTClient(t, server)
	return server, &calls
}

// TestEnvironmentsPaginationStopsAtTwentyPages pins the page cap: a
// listing that never stops answering a next page is read for twenty
// pages, then the lane answers unknown (the list it holds is not the
// whole one).
func TestEnvironmentsPaginationStopsAtTwentyPages(t *testing.T) {
	_, calls := endlessPages(t, "/repos/owner/repo/environments", environmentsPage2())
	envs, known, err := FetchGitHubEnvironments("", "owner", "repo")
	if err != nil || known || envs != nil {
		t.Errorf("got (%v, %v, %v), want (nil, false, nil)", envs, known, err)
	}
	if got := calls.Load(); got != maxLanePages {
		t.Errorf("pages = %d, want %d", got, maxLanePages)
	}
}

// TestWorkflowStatesPaginationStopsAtTwentyPages is the same cap on the
// workflow-states lane.
func TestWorkflowStatesPaginationStopsAtTwentyPages(t *testing.T) {
	_, calls := endlessPages(t, "/repos/owner/repo/actions/workflows", map[string]any{
		"workflows": []map[string]any{{"path": ".github/workflows/ci.yml", "state": "active"}},
	})
	states, known, err := FetchGitHubWorkflowStates("", "owner", "repo")
	if err != nil || known || states != nil {
		t.Errorf("got (%v, %v, %v), want (nil, false, nil)", states, known, err)
	}
	if got := calls.Load(); got != maxLanePages {
		t.Errorf("pages = %d, want %d", got, maxLanePages)
	}
}

// TestRefusedLaneLogsItsStatusAtInfo pins that a lane the API refuses
// (401, 403, 404) says so at Info, with the lane's name and the status,
// and never the token: the facts it would have read stay unknown, and an
// operator can see why.
func TestRefusedLaneLogsItsStatusAtInfo(t *testing.T) {
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)
	t.Setenv("GITHUB_TOKEN", "ghp_secretvalue")
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if _, known, _ := FetchGitHubEnvironments("", "owner", "repo"); known {
		t.Fatal("environments known on a 401")
	}

	want := map[string]int{"default token runs": 403, "default token releases": 404, "environments": 401}
	got := map[string]int{}
	for _, e := range hook.AllEntries() {
		lane, ok := e.Data["lane"].(string)
		if !ok {
			continue
		}
		if e.Level != logrus.InfoLevel {
			t.Errorf("lane %s logged at %s, want info", lane, e.Level)
		}
		status, _ := e.Data["status"].(int)
		got[lane] = status
		line, _ := e.String()
		if strings.Contains(line, "ghp_secretvalue") || strings.Contains(strings.ToLower(line), "authorization") {
			t.Errorf("lane %s log carries a credential: %s", lane, line)
		}
	}
	for lane, status := range want {
		if got[lane] != status {
			t.Errorf("lane %q logged status %d, want %d (all: %v)", lane, got[lane], status, got)
		}
	}
}
