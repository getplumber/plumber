package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// writeLogBody is a GITHUB_TOKEN Permissions block granting Contents:
// write, in the real shape GitHub Actions prints at the top of a
// job's log: every line prefixed by an ISO-8601 timestamp, the block
// wrapped in a log group.
const writeLogBody = "" +
	"2026-10-15T12:34:56.1000000Z ##[group]GITHUB_TOKEN Permissions\n" +
	"2026-10-15T12:34:56.2000000Z Contents: write\n" +
	"2026-10-15T12:34:56.3000000Z Metadata: read\n" +
	"2026-10-15T12:34:56.4000000Z Packages: read\n" +
	"2026-10-15T12:34:56.5000000Z ##[endgroup]\n" +
	"2026-10-15T12:34:57.0000000Z Some build output follows.\n"

// writeLogBodyCRLF is writeLogBody with CRLF line endings, the shape
// a log served from a Windows-originated store can carry.
const writeLogBodyCRLF = "" +
	"2026-10-15T12:34:56.1000000Z ##[group]GITHUB_TOKEN Permissions\r\n" +
	"2026-10-15T12:34:56.2000000Z Contents: write\r\n" +
	"2026-10-15T12:34:56.3000000Z Metadata: read\r\n" +
	"2026-10-15T12:34:56.4000000Z Packages: read\r\n" +
	"2026-10-15T12:34:56.5000000Z ##[endgroup]\r\n" +
	"2026-10-15T12:34:57.0000000Z Some build output follows.\r\n"

// readOnlyLogBody is the same block with every scope read-only.
const readOnlyLogBody = "" +
	"2026-10-15T12:34:56.1000000Z ##[group]GITHUB_TOKEN Permissions\n" +
	"2026-10-15T12:34:56.2000000Z Contents: read\n" +
	"2026-10-15T12:34:56.3000000Z Metadata: read\n" +
	"2026-10-15T12:34:56.4000000Z ##[endgroup]\n" +
	"2026-10-15T12:34:57.0000000Z Some build output follows.\n"

// metadataOnlyLogBody carries a block with only the Metadata scope,
// never excluded from the block itself, only from the write fold
// (scopeWrite): the parse must still succeed.
const metadataOnlyLogBody = "" +
	"2026-10-15T12:34:56.1000000Z ##[group]GITHUB_TOKEN Permissions\n" +
	"2026-10-15T12:34:56.2000000Z Metadata: read\n" +
	"2026-10-15T12:34:56.3000000Z ##[endgroup]\n"

// bareHeaderLogBody is the block without the ##[group] wrapper: some
// runners print the header bare.
const bareHeaderLogBody = "" +
	"2026-10-15T12:34:56.1000000Z GITHUB_TOKEN Permissions\n" +
	"2026-10-15T12:34:56.2000000Z Contents: write\n" +
	"2026-10-15T12:34:56.3000000Z Metadata: read\n" +
	"2026-10-15T12:34:57.0000000Z Some build output follows.\n"

// noBlockLogBody carries no GITHUB_TOKEN Permissions block at all.
const noBlockLogBody = "" +
	"2026-10-15T12:34:56.1000000Z Run actions/checkout@v4\n" +
	"2026-10-15T12:34:56.2000000Z Checking out the repository...\n"

func runsPage(runs ...remoteRun) map[string]any {
	return map[string]any{"workflow_runs": runs}
}

func jobsPage(ids ...int64) map[string]any {
	jobs := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		jobs = append(jobs, map[string]any{"id": id, "name": "build"})
	}
	return map[string]any{"jobs": jobs}
}

// eligibleOnly returns an eligible func reporting true only for paths
// in want.
func eligibleOnly(want ...string) func(string) bool {
	set := map[string]bool{}
	for _, w := range want {
		set[w] = true
	}
	return func(path string) bool { return set[path] }
}

// pushRun builds a run that passes every run-safety check on its own
// (a push to the scanned repository's "main", by a plain user): the
// baseline fixture every log-route test starts from, overridden field
// by field for the cases that must be filtered out.
func pushRun(id int64, path string) remoteRun {
	return remoteRun{
		ID: id, Path: path, Event: "push", HeadBranch: "main",
		Repository:      &remoteRepoRef{FullName: "owner/repo"},
		Actor:           &remoteActor{Login: "someone"},
		TriggeringActor: &remoteActor{Login: "someone"},
	}
}

// TestFetchGitHubDefaultTokenWrite_LogRouteSkipsIneligibleRunsAndParsesWrite
// pins the whole log route end to end: the runs listing carries an
// ineligible run first (its jobs endpoint must never be called) and an
// eligible one second; the eligible run's job log is fetched through
// the API host and its 302 is followed by hand to a second, distinct
// server (the log store) that must never see an Authorization header.
func TestFetchGitHubDefaultTokenWrite_LogRouteSkipsIneligibleRunsAndParsesWrite(t *testing.T) {
	// A real credential is available, so the API hop can be checked to
	// carry it and the log-store hop checked to NOT carry it: without
	// one in scope, both hops would trivially carry nothing and the
	// no-leak assertion below would prove nothing.
	t.Setenv("GH_TOKEN", "test-secret-token")

	var sawAPIAuth, sawLogStoreAuth string
	logStore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawLogStoreAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(writeLogBody))
	}))
	defer logStore.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(runsPage(
			pushRun(100, ".github/workflows/declared.yml"),
			pushRun(200, ".github/workflows/default.yml"),
		))
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/100/jobs", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the ineligible run's jobs must never be fetched")
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/200/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jobsPage(55))
	})
	mux.HandleFunc("/repos/owner/repo/actions/jobs/55/logs", func(w http.ResponseWriter, r *http.Request) {
		sawAPIAuth = r.Header.Get("Authorization")
		http.Redirect(w, r, logStore.URL+"/blob/55", http.StatusFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/default.yml"))
	if write != "true" || source != "log" {
		t.Errorf("write/source = %q/%q, want true/log", write, source)
	}
	if sawAPIAuth == "" {
		t.Errorf("the API logs endpoint should carry the resolved credential")
	}
	if sawLogStoreAuth != "" {
		t.Errorf("the log store must never receive an Authorization header, got %q", sawLogStoreAuth)
	}
}

// TestFetchGitHubDefaultTokenWrite_LogRouteSkipsForkAndDependabotRuns
// pins the per-run safety filter end to end: a fork pull_request run
// listed first, a push run by dependabot[bot] second, both skipped
// without their jobs ever being fetched, and the eligible push run
// third is the one actually read.
func TestFetchGitHubDefaultTokenWrite_LogRouteSkipsForkAndDependabotRuns(t *testing.T) {
	forkRun := remoteRun{
		ID: 1, Path: ".github/workflows/ci.yml", Event: "pull_request", HeadBranch: "feature",
		Repository:      &remoteRepoRef{FullName: "owner/repo"},
		HeadRepository:  &remoteRepoRef{FullName: "forker/repo"},
		Actor:           &remoteActor{Login: "forker"},
		TriggeringActor: &remoteActor{Login: "forker"},
	}
	dependabotRun := pushRun(2, ".github/workflows/ci.yml")
	dependabotRun.Actor = &remoteActor{Login: "dependabot[bot]"}
	dependabotRun.TriggeringActor = &remoteActor{Login: "dependabot[bot]"}
	eligibleRun := pushRun(3, ".github/workflows/ci.yml")

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(runsPage(forkRun, dependabotRun, eligibleRun))
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/1/jobs", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the fork pull_request run must never be fetched")
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/2/jobs", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the dependabot run must never be fetched")
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/3/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jobsPage(9))
	})
	mux.HandleFunc("/repos/owner/repo/actions/jobs/9/logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(writeLogBody))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "true" || source != "log" {
		t.Errorf("write/source = %q/%q, want true/log (the third run)", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_EmptyDefaultBranchSkipsTheLogRouteEntirely
// pins that an empty defaultBranch keeps no run at all (there is
// nothing to compare a run's own branch against), and never even
// lists runs, falling straight to the effect route.
func TestFetchGitHubDefaultTokenWrite_EmptyDefaultBranchSkipsTheLogRouteEntirely(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the log route must never list runs without a default branch to compare against")
	})
	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{"author": map[string]any{"login": "github-actions[bot]"}}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "true" || source != "effect" {
		t.Errorf("write/source = %q/%q, want true/effect (log route skipped, falls to effect)", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_LogRouteReadOnly pins the read-only
// parse: every scope in the block reads "read", so write is "false",
// not absent.
func TestFetchGitHubDefaultTokenWrite_LogRouteReadOnly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(runsPage(pushRun(1, ".github/workflows/ci.yml")))
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/1/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jobsPage(9))
	})
	mux.HandleFunc("/repos/owner/repo/actions/jobs/9/logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(readOnlyLogBody))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "false" || source != "log" {
		t.Errorf("write/source = %q/%q, want false/log", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_LogRouteReadOnlyCRLF pins the same
// read-only parse against a write sample served with CRLF line
// endings.
func TestFetchGitHubDefaultTokenWrite_LogRouteWriteCRLF(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(runsPage(pushRun(1, ".github/workflows/ci.yml")))
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/1/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jobsPage(9))
	})
	mux.HandleFunc("/repos/owner/repo/actions/jobs/9/logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(writeLogBodyCRLF))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "true" || source != "log" {
		t.Errorf("write/source = %q/%q, want true/log", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_NoBlockFallsThroughToEffect pins
// that a log with no GITHUB_TOKEN Permissions block at all abandons
// the log route (it does not try another run) and falls to the effect
// route, which here finds a github-actions[bot]-authored release.
func TestFetchGitHubDefaultTokenWrite_NoBlockFallsThroughToEffect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(runsPage(pushRun(1, ".github/workflows/ci.yml")))
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/1/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jobsPage(9))
	})
	mux.HandleFunc("/repos/owner/repo/actions/jobs/9/logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(noBlockLogBody))
	})
	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"author": map[string]any{"login": "github-actions[bot]"}},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "true" || source != "effect" {
		t.Errorf("write/source = %q/%q, want true/effect", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_JobFetchFailureSkipsToTheNextRun
// pins that a job-listing failure on an eligible run (the "match"
// failing) moves on to the next eligible run rather than abandoning
// the log route outright.
func TestFetchGitHubDefaultTokenWrite_JobFetchFailureSkipsToTheNextRun(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(runsPage(
			pushRun(1, ".github/workflows/ci.yml"),
			pushRun(2, ".github/workflows/ci.yml"),
		))
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/1/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/2/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jobsPage(9))
	})
	mux.HandleFunc("/repos/owner/repo/actions/jobs/9/logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(writeLogBody))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "true" || source != "log" {
		t.Errorf("write/source = %q/%q, want true/log (the second run's job)", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_RelativeRedirectLocationResolves
// pins that the API's redirect is resolved with resp.Location()
// rather than a bare header read: a relative Location (the shape some
// proxies rewrite it to) must still be followed, resolved against the
// request it came from.
func TestFetchGitHubDefaultTokenWrite_RelativeRedirectLocationResolves(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(runsPage(pushRun(1, ".github/workflows/ci.yml")))
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/1/jobs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jobsPage(9))
	})
	mux.HandleFunc("/repos/owner/repo/actions/jobs/9/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/blob/9")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/blob/9", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(writeLogBody))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "true" || source != "log" {
		t.Errorf("write/source = %q/%q, want true/log (relative redirect resolved)", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_EffectRoute_RunsForbidden pins the
// effect route reached because the run listing itself is unreachable
// (403): a bot-authored release still settles it.
func TestFetchGitHubDefaultTokenWrite_EffectRoute_RunsForbidden(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"author": map[string]any{"login": "someone-else"}},
			{"author": map[string]any{"login": "github-actions[bot]"}},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "true" || source != "effect" {
		t.Errorf("write/source = %q/%q, want true/effect", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_DeclaresContentsWriteSkipsEffectRoute
// pins that the effect route never runs at all when some job of the
// pipeline already declares a contents write: a bot-authored release
// would only prove that SOME token in the repository can write, never
// that the undeclared default one can.
func TestFetchGitHubDefaultTokenWrite_DeclaresContentsWriteSkipsEffectRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the effect route must never run when some job already declares a contents write")
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", true, eligibleOnly(".github/workflows/ci.yml"))
	if write != "unknown" || source != "unknown" {
		t.Errorf("write/source = %q/%q, want unknown/unknown", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_UnknownRoute_EverythingNotFound
// pins the final fallback: nothing answers at all, so the token scope
// is unknown, never a guess.
func TestFetchGitHubDefaultTokenWrite_UnknownRoute_EverythingNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	write, source := FetchGitHubDefaultTokenWrite(server.URL, "owner", "repo", "main", false, eligibleOnly(".github/workflows/ci.yml"))
	if write != "unknown" || source != "unknown" {
		t.Errorf("write/source = %q/%q, want unknown/unknown", write, source)
	}
}

// TestFetchGitHubDefaultTokenWrite_EmptyOwnerOrRepoIsUnknown pins that
// a nil or always-false eligible closure still degrades to unknown
// without the lane erroring, and that empty owner/repo never dials
// out at all.
func TestFetchGitHubDefaultTokenWrite_EmptyOwnerOrRepoIsUnknown(t *testing.T) {
	if write, source := FetchGitHubDefaultTokenWrite("", "", "repo", "main", false, eligibleOnly()); write != "unknown" || source != "unknown" {
		t.Errorf("write/source = %q/%q, want unknown/unknown", write, source)
	}
	if write, source := FetchGitHubDefaultTokenWrite("", "owner", "repo", "main", false, nil); write != "unknown" || source != "unknown" {
		t.Errorf("nil eligible: write/source = %q/%q, want unknown/unknown", write, source)
	}
}

// TestParseTokenPermissionsBlock pins the log-parsing shape against
// the real log format directly: a write sample, the same CRLF, a
// read-only sample, a bare header without the group marker, a
// Metadata-only block, and a sample without the block at all.
func TestParseTokenPermissionsBlock(t *testing.T) {
	cases := []struct {
		name string
		body string
		want map[string]string
		ok   bool
	}{
		{"write", writeLogBody, map[string]string{"Contents": "write", "Metadata": "read", "Packages": "read"}, true},
		{"write CRLF", writeLogBodyCRLF, map[string]string{"Contents": "write", "Metadata": "read", "Packages": "read"}, true},
		{"read-only", readOnlyLogBody, map[string]string{"Contents": "read", "Metadata": "read"}, true},
		{"bare header, no group marker", bareHeaderLogBody, map[string]string{"Contents": "write", "Metadata": "read"}, true},
		{"metadata only", metadataOnlyLogBody, map[string]string{"Metadata": "read"}, true},
		{"no block", noBlockLogBody, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseTokenPermissionsBlock(c.body)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && !mapsEqual(got, c.want) {
				t.Errorf("scopes = %v, want %v", got, c.want)
			}
		})
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestScopeWrite pins the write/false fold: any non-Metadata write
// scope is a write token; every scope read-only (Metadata included or
// not) is not.
func TestScopeWrite(t *testing.T) {
	if got := scopeWrite(map[string]string{"Contents": "write", "Metadata": "read"}); got != "true" {
		t.Errorf("scopeWrite(write) = %q", got)
	}
	if got := scopeWrite(map[string]string{"Contents": "read", "Metadata": "read"}); got != "false" {
		t.Errorf("scopeWrite(read-only) = %q", got)
	}
	if got := scopeWrite(map[string]string{"Metadata": "write"}); got != "false" {
		t.Errorf("scopeWrite(metadata-write-only) = %q, want false (Metadata excluded)", got)
	}
}

// TestRunSafeForDefaultToken pins the per-run safety filter directly:
// the event allowlist, the default-branch match, the head-repository
// match (fork pull_request runs excluded), and the dependabot[bot]
// exclusion on either actor field.
func TestRunSafeForDefaultToken(t *testing.T) {
	base := pushRun(1, ".github/workflows/ci.yml")
	if !runSafeForDefaultToken(base, "owner", "repo", "main") {
		t.Error("a plain push run on the default branch of the scanned repository: want safe")
	}

	wrongEvent := base
	wrongEvent.Event = "pull_request_target"
	if runSafeForDefaultToken(wrongEvent, "owner", "repo", "main") {
		t.Error("an event outside the allowlist: want unsafe")
	}

	wrongBranch := base
	wrongBranch.HeadBranch = "feature"
	if runSafeForDefaultToken(wrongBranch, "owner", "repo", "main") {
		t.Error("a run not on the default branch: want unsafe")
	}

	fork := base
	fork.HeadRepository = &remoteRepoRef{FullName: "forker/repo"}
	if runSafeForDefaultToken(fork, "owner", "repo", "main") {
		t.Error("a run whose head repository is a fork: want unsafe")
	}

	dependabotActor := base
	dependabotActor.Actor = &remoteActor{Login: "dependabot[bot]"}
	if runSafeForDefaultToken(dependabotActor, "owner", "repo", "main") {
		t.Error("a run actor of dependabot[bot]: want unsafe")
	}

	dependabotTriggering := base
	dependabotTriggering.TriggeringActor = &remoteActor{Login: "dependabot[bot]"}
	if runSafeForDefaultToken(dependabotTriggering, "owner", "repo", "main") {
		t.Error("a run triggering actor of dependabot[bot]: want unsafe")
	}
}
