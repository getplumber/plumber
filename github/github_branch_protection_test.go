package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/getplumber/plumber/internal/ir"
)

// rewriteTransport reroutes every outbound request to a fixed base
// URL, regardless of the Host the client thought it was talking to.
// Lets us point a go-gh REST client at httptest.NewServer without
// caring about TLS, certificate trust or DNS. Used only by tests in
// this file.
type rewriteTransport struct {
	base *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.base.Scheme
	req.URL.Host = r.base.Host
	req.Host = r.base.Host
	return http.DefaultTransport.RoundTrip(req)
}

// newTestRESTClient builds a go-gh REST client whose every request
// lands on the supplied httptest server, regardless of path host.
func newTestRESTClient(t *testing.T, server *httptest.Server) *api.RESTClient {
	t.Helper()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	rest, err := api.NewRESTClient(api.ClientOptions{
		Host:      "api.github.com",
		AuthToken: "test-token",
		Transport: &rewriteTransport{base: base},
	})
	if err != nil {
		t.Fatalf("rest client: %v", err)
	}
	return rest
}

// swapRESTClient replaces the package-level newGitHubRESTClient so
// production code under test (FetchGitHubBranchProtection,
// FetchGitHubDefaultBranch) gets the test client instead of going
// to api.github.com. Restores via t.Cleanup.
func swapRESTClient(t *testing.T, server *httptest.Server) {
	t.Helper()
	orig := newGitHubRESTClient
	newGitHubRESTClient = func(host string) (*api.RESTClient, error) {
		return newTestRESTClient(t, server), nil
	}
	t.Cleanup(func() { newGitHubRESTClient = orig })
}

// TestFetchGitHubBranchProtection_TargetedOnly_BypassesListing is the
// regression for the "100-branch listing hides main on a busy repo"
// bug: the function must NOT call /branches at all when the caller
// asks for exact names with no wildcards. /branches is wired to fail
// the test if it's hit.
func TestFetchGitHubBranchProtection_TargetedOnly_BypassesListing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches", func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("/branches must not be called when Listing is false")
	})
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	})
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow_force_pushes":            map[string]any{"enabled": false},
			"required_pull_request_reviews": map[string]any{"require_code_owner_reviews": true},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 || branches[0].Name != "main" || !branches[0].Protected {
		t.Fatalf("expected single protected main branch, got %+v", branches)
	}
	if !branches[0].CodeOwnerApprovalRequired {
		t.Errorf("expected CodeOwnerApprovalRequired=true, got false")
	}
}

// TestFetchGitHubBranchProtection_TargetedSkipsMissingBranches checks
// that a 404 on a configured exact name (branch doesn't exist on
// this repo) is silently dropped rather than failing or producing a
// garbage entry — the rego rule will then have nothing to flag for
// that name, which is the right contract.
func TestFetchGitHubBranchProtection_TargetedSkipsMissingBranches(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	})
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow_force_pushes":            map[string]any{"enabled": false},
			"required_pull_request_reviews": map[string]any{"require_code_owner_reviews": true},
		})
	})
	mux.HandleFunc("/repos/owner/repo/branches/master", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main", "master"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("expected 1 branch (main; master is 404), got %d: %+v", len(branches), branches)
	}
	if branches[0].Name != "main" {
		t.Errorf("expected main, got %q", branches[0].Name)
	}
}

// TestFetchGitHubBranchProtection_TargetedRedirectsToDefault checks the
// real-world GitHub quirk where /repos/.../branches/{stale-name} silently
// returns the default branch (common after the master→main rename). The
// caller asked for "master", so the returned "main" payload must be
// dropped — otherwise main ends up in `out` twice (once from the
// explicit main lookup, once from the redirected master), inflating
// BranchesMatched and falsely triggering the "protection details
// unknown" postflight on the duplicate.
func TestFetchGitHubBranchProtection_TargetedRedirectsToDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	})
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow_force_pushes":            map[string]any{"enabled": false},
			"required_pull_request_reviews": map[string]any{"require_code_owner_reviews": true},
		})
	})
	// /branches/master "silently" responds with the default branch
	// (name="main"). This mirrors the live-repo behaviour observed on
	// getplumber/plumber where /branches/master 200s with main.
	mux.HandleFunc("/repos/owner/repo/branches/master", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main", "master"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("expected 1 branch (main only; master is a default-branch redirect), got %d: %+v", len(branches), branches)
	}
	if branches[0].Name != "main" {
		t.Errorf("expected main, got %q", branches[0].Name)
	}
	if !branches[0].ProtectionDetailsKnown {
		t.Errorf("expected ProtectionDetailsKnown=true on the genuine main fetch")
	}
}

// TestFetchGitHubBranchProtection_TargetedRulesetOnlyBranch verifies
// that a branch protected via the newer Repository Rulesets API
// keeps Protected=true even though /protection 404s. Detail is not
// authoritative in this case — ProtectionDetailsKnown stays false so
// branch_non_compliant.rego abstains.
func TestFetchGitHubBranchProtection_TargetedRulesetOnlyBranch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	})
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 || !branches[0].Protected {
		t.Fatalf("expected single protected main, got %+v", branches)
	}
	if branches[0].ProtectionDetailsKnown {
		t.Errorf("expected ProtectionDetailsKnown=false on rulesets-only 404, got true")
	}
}

// TestFetchGitHubBranchProtection_TargetedDetailForbidden_KeepsEntry
// is the regression for the read-only-token bug: when the listing
// succeeds but /protection returns 403 (token lacks
// Administration:read), the entry MUST be preserved with Protected
// from the listing — losing it silently dropped ISSUE-501 too. The
// detail-known flag stays false so branch_non_compliant.rego
// abstains rather than false-positiving on zero values.
func TestFetchGitHubBranchProtection_TargetedDetailForbidden_KeepsEntry(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	})
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("expected entry preserved on /protection 403, got %d entries", len(branches))
	}
	if !branches[0].Protected {
		t.Errorf("expected Protected=true from listing")
	}
	if branches[0].ProtectionDetailsKnown {
		t.Errorf("expected ProtectionDetailsKnown=false on /protection 403")
	}
	if branches[0].AllowForcePush || branches[0].CodeOwnerApprovalRequired {
		t.Errorf("expected detail fields to stay zero on 403, got %+v", branches[0])
	}
}

// TestFetchGitHubBranchProtection_TargetedDetailSucceeds_MarksKnown
// verifies the happy path sets ProtectionDetailsKnown=true so the
// branch_non_compliant rule trusts the values.
func TestFetchGitHubBranchProtection_TargetedDetailSucceeds_MarksKnown(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	})
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow_force_pushes":            map[string]any{"enabled": true},
			"required_pull_request_reviews": map[string]any{"require_code_owner_reviews": true},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 || !branches[0].ProtectionDetailsKnown {
		t.Fatalf("expected ProtectionDetailsKnown=true on 200 detail, got %+v", branches)
	}
	if !branches[0].AllowForcePush || !branches[0].CodeOwnerApprovalRequired {
		t.Errorf("expected detail fields populated, got %+v", branches[0])
	}
}

// TestFetchGitHubBranchProtection_NoOpWhenNeitherTargetedNorListing
// asserts the cheap-when-disabled contract: zero API calls when the
// caller didn't ask for either mode.
func TestFetchGitHubBranchProtection_NoOpWhenNeitherTargetedNorListing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call: %s", r.URL.Path)
	}))
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 0 {
		t.Errorf("expected 0 branches, got %d", len(branches))
	}
}

// TestFetchGitHubBranchProtection_ListingPaginates verifies the
// listing path walks past page 1 when a page comes back full. Three
// pages are served: 100 + 100 + 50; expect 250 entries plus the
// targeted "main" already in the result, deduped.
func TestFetchGitHubBranchProtection_ListingPaginates(t *testing.T) {
	var pageHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&pageHits, 1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		var entries []map[string]any
		switch page {
		case 1:
			for i := range 100 {
				entries = append(entries, map[string]any{
					"name":      fmt.Sprintf("dependabot/npm/lib-%d", i),
					"protected": false,
				})
			}
		case 2:
			for i := range 100 {
				entries = append(entries, map[string]any{
					"name":      fmt.Sprintf("release-1.%d", i),
					"protected": true,
				})
			}
		case 3:
			for i := range 50 {
				entries = append(entries, map[string]any{
					"name":      fmt.Sprintf("hotfix-%d", i),
					"protected": false,
				})
			}
		}
		_ = json.NewEncoder(w).Encode(entries)
	})
	// Every release-* and main branch hits its protection endpoint;
	// answer them all generically.
	mux.HandleFunc("/repos/owner/repo/branches/", func(w http.ResponseWriter, r *http.Request) {
		// Targeted /branches/main itself.
		if r.URL.Path == "/repos/owner/repo/branches/main" {
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
			return
		}
		// Anything ending in /protection during the listing path.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow_force_pushes":            map[string]any{"enabled": false},
			"required_pull_request_reviews": map[string]any{"require_code_owner_reviews": false},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
		Listing:    true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Targeted main + 100 dependabot + 100 release + 50 hotfix = 251.
	if len(branches) != 251 {
		t.Fatalf("expected 251 branches (main + 250 listed), got %d", len(branches))
	}
	if got := atomic.LoadInt32(&pageHits); got != 3 {
		t.Errorf("expected exactly 3 page hits (100/100/50 stops at <100), got %d", got)
	}
}

// TestFetchGitHubBranchProtection_ListingCapsAtMaxPages keeps the
// listing path from runaway-scanning a repo with thousands of
// dependabot branches. We always return a full 100-entry page; the
// loop must stop at maxBranchListingPages.
func TestFetchGitHubBranchProtection_ListingCapsAtMaxPages(t *testing.T) {
	var pageHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&pageHits, 1)
		var entries []map[string]any
		for i := range 100 {
			entries = append(entries, map[string]any{
				"name":      fmt.Sprintf("never-ending-%d-%d", atomic.LoadInt32(&pageHits), i),
				"protected": false,
			})
		}
		_ = json.NewEncoder(w).Encode(entries)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{Listing: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 100*maxBranchListingPages {
		t.Errorf("expected %d branches (cap), got %d", 100*maxBranchListingPages, len(branches))
	}
	if got := atomic.LoadInt32(&pageHits); got != int32(maxBranchListingPages) {
		t.Errorf("expected %d page hits, got %d", maxBranchListingPages, got)
	}
}

// TestFetchGitHubBranchProtection_TargetedForbidden_DegradesToEmpty
// keeps the contract that no-auth / no-scope is silent: the rego rule
// then sees zero branches and emits no findings.
func TestFetchGitHubBranchProtection_TargetedForbidden_DegradesToEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("expected nil error on 403, got %v", err)
	}
	if len(branches) != 0 {
		t.Errorf("expected empty branches on 403, got %d", len(branches))
	}
}

// TestFetchGitHubBranchProtection_ListingForbidden_KeepsTargeted
// verifies a degraded mode where the targeted phase succeeded but
// the wildcard listing fails: we keep the targeted result rather
// than throwing away both, because the patterns the user explicitly
// named are what the rego rule cares about most.
func TestFetchGitHubBranchProtection_ListingForbidden_KeepsTargeted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	})
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow_force_pushes":            map[string]any{"enabled": false},
			"required_pull_request_reviews": map[string]any{"require_code_owner_reviews": true},
		})
	})
	mux.HandleFunc("/repos/owner/repo/branches", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
		Listing:    true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 || branches[0].Name != "main" {
		t.Fatalf("expected targeted main preserved on listing 403, got %+v", branches)
	}
}

func TestFetchGitHubBranchProtection_RejectsEmptyOwnerOrRepo(t *testing.T) {
	if _, err := FetchGitHubBranchProtection("", "", "repo", BranchFetchOptions{ExactNames: []string{"main"}}); err == nil {
		t.Error("expected error for empty owner")
	}
	if _, err := FetchGitHubBranchProtection("", "owner", "", BranchFetchOptions{ExactNames: []string{"main"}}); err == nil {
		t.Error("expected error for empty repo")
	}
}

// TestFetchGitHubBranchProtection_TargetedDedupesDuplicateNames
// covers the case where the caller passes the same name twice (e.g.
// "main" listed in namePatterns AND as the resolved default branch).
// Only one /branches/{name} fetch should happen, only one entry
// should appear in the result.
func TestFetchGitHubBranchProtection_TargetedDedupesDuplicateNames(t *testing.T) {
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": false})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main", "main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 {
		t.Errorf("expected dedup to 1 entry, got %d", len(branches))
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected 1 API call after dedup, got %d", got)
	}
}

// Sanity: an explicit ir.Branch comparison between the new targeted
// path and what the listing path yields for the same protected
// branch produces equivalent values. This is a regression guard:
// the two paths share the AllowForcePush / CodeOwnerApprovalRequired
// mapping logic, and divergence between them would silently shift
// findings depending on which mode the caller picked.
func TestFetchGitHubBranchProtection_TargetedAndListingProduceSameShape(t *testing.T) {
	encodeMain := func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "protected": true})
	}
	encodeProtection := func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow_force_pushes":            map[string]any{"enabled": true}, // bad
			"required_pull_request_reviews": map[string]any{"require_code_owner_reviews": false},
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "main", "protected": true},
		})
	})
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) { encodeMain(w) })
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) { encodeProtection(w) })
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	targeted, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{ExactNames: []string{"main"}})
	if err != nil {
		t.Fatalf("targeted: %v", err)
	}
	listed, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{Listing: true})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(targeted) != 1 || len(listed) != 1 {
		t.Fatalf("expected 1 entry from each path, got %d / %d", len(targeted), len(listed))
	}
	if targeted[0] != (ir.Branch{
		Name:                      "main",
		Protected:                 true,
		AllowForcePush:            true,
		CodeOwnerApprovalRequired: false,
		ProtectionDetailsKnown:    true,
	}) {
		t.Errorf("targeted shape unexpected: %+v", targeted[0])
	}
	if targeted[0] != listed[0] {
		t.Errorf("targeted and listing produced different ir.Branch values:\n  targeted: %+v\n  listed:   %+v", targeted[0], listed[0])
	}
}

func TestFetchGitHubDefaultBranch_HappyPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"default_branch": "develop",
			"name":           "repo",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	name, err := FetchGitHubDefaultBranch("", "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "develop" {
		t.Errorf("expected 'develop', got %q", name)
	}
}

func TestFetchGitHubDefaultBranch_404_DegradesToEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	name, err := FetchGitHubDefaultBranch("", "owner", "repo")
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if name != "" {
		t.Errorf("expected empty default branch on 404, got %q", name)
	}
}

// rulesetTestHelpers ───────────────────────────────────────────────
//
// The Rulesets fold tests share three handler stubs (classic
// protection, rules endpoint, branch entry). Each test builds its mux
// from these so the surface stays small and the assertions read
// linearly.

func handleBranchEntry(mux *http.ServeMux, owner, repo, name string, protected bool) {
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/branches/%s", owner, repo, name), func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "protected": protected})
	})
}

func handleClassicProtection(mux *http.ServeMux, owner, repo, name string, allowForcePush, codeOwner bool) {
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, name), func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow_force_pushes":            map[string]any{"enabled": allowForcePush},
			"required_pull_request_reviews": map[string]any{"require_code_owner_reviews": codeOwner},
		})
	})
}

func handleClassicProtectionStatus(mux *http.ServeMux, owner, repo, name string, status int) {
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, name), func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, http.StatusText(status), status)
	})
}

func handleEffectiveRules(mux *http.ServeMux, owner, repo, name string, rules []map[string]any) {
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/rules/branches/%s", owner, repo, name), func(w http.ResponseWriter, r *http.Request) {
		// Honour pagination: return the rules on page=1, empty on page=2+.
		page := r.URL.Query().Get("page")
		if page != "" && page != "1" {
			_ = json.NewEncoder(w).Encode([]map[string]any{})
			return
		}
		_ = json.NewEncoder(w).Encode(rules)
	})
}

func handleEffectiveRulesStatus(mux *http.ServeMux, owner, repo, name string, status int) {
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/rules/branches/%s", owner, repo, name), func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, http.StatusText(status), status)
	})
}

// TestFetchGitHubBranchProtection_RulesetOnlyCodeOwner exercises the
// Ruleset-only scenario: classic /protection 404s, but the rules
// endpoint reports a pull_request rule with require_code_owner_review.
// Without the Rulesets merge this branch landed at PDK=false and the
// rego rule abstained — silently dropping a real ISSUE-505 signal.
func TestFetchGitHubBranchProtection_RulesetOnlyCodeOwner(t *testing.T) {
	mux := http.NewServeMux()
	handleBranchEntry(mux, "owner", "repo", "main", true)
	handleClassicProtectionStatus(mux, "owner", "repo", "main", http.StatusNotFound)
	handleEffectiveRules(mux, "owner", "repo", "main", []map[string]any{
		{
			"type":                "pull_request",
			"ruleset_source_type": "Repository",
			"ruleset_id":          1,
			"parameters":          map[string]any{"require_code_owner_review": true},
		},
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("expected 1 branch, got %d: %+v", len(branches), branches)
	}
	b := branches[0]
	if !b.ProtectionDetailsKnown {
		t.Errorf("expected ProtectionDetailsKnown=true when rules endpoint succeeds even if classic 404s")
	}
	if !b.CodeOwnerApprovalRequired {
		t.Errorf("expected CodeOwnerApprovalRequired=true from ruleset pull_request rule")
	}
}

// TestFetchGitHubBranchProtection_ClassicPlusRulesetMerge confirms the
// "stricter wins" merge: classic reports force-push allowed and no
// code-owner, the ruleset adds non_fast_forward + a code-owner rule.
// The final IR must reflect the strict end of both.
func TestFetchGitHubBranchProtection_ClassicPlusRulesetMerge(t *testing.T) {
	mux := http.NewServeMux()
	handleBranchEntry(mux, "owner", "repo", "main", true)
	handleClassicProtection(mux, "owner", "repo", "main", true, false)
	handleEffectiveRules(mux, "owner", "repo", "main", []map[string]any{
		{"type": "non_fast_forward"},
		{"type": "pull_request", "parameters": map[string]any{"require_code_owner_review": true}},
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("expected 1 branch, got %d", len(branches))
	}
	b := branches[0]
	if b.AllowForcePush {
		t.Errorf("expected AllowForcePush=false (non_fast_forward overrides classic), got true")
	}
	if !b.CodeOwnerApprovalRequired {
		t.Errorf("expected CodeOwnerApprovalRequired=true via ruleset, got false")
	}
	if !b.ProtectionDetailsKnown {
		t.Errorf("expected ProtectionDetailsKnown=true")
	}
}

// TestFetchGitHubBranchProtection_MultipleRulesetsBothHaveCodeOwner
// covers the "two rulesets cover the same branch" case. The endpoint
// returns the union — same rule type twice with the strict parameter.
// Idempotent OR semantics keep the merge clean.
func TestFetchGitHubBranchProtection_MultipleRulesetsBothHaveCodeOwner(t *testing.T) {
	mux := http.NewServeMux()
	handleBranchEntry(mux, "owner", "repo", "main", true)
	handleClassicProtectionStatus(mux, "owner", "repo", "main", http.StatusNotFound)
	handleEffectiveRules(mux, "owner", "repo", "main", []map[string]any{
		{"type": "pull_request", "ruleset_id": 1, "parameters": map[string]any{"require_code_owner_review": true}},
		{"type": "pull_request", "ruleset_id": 2, "parameters": map[string]any{"require_code_owner_review": true}},
		{"type": "non_fast_forward", "ruleset_id": 2},
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !branches[0].CodeOwnerApprovalRequired || branches[0].AllowForcePush || !branches[0].ProtectionDetailsKnown {
		t.Errorf("expected coda=true, afp=false, pdk=true; got %+v", branches[0])
	}
}

// TestFetchGitHubBranchProtection_RulesetsForbidden_ClassicSucceeds
// — when the rules endpoint 403s (typical with a token that has
// content scope but not Administration:Read on a private repo) we
// must still keep the classic-derived data and stay PDK=true. The
// "rulesets adds info on top of classic" branch must not regress to
// the "both endpoints 403 ⇒ abstain" path.
func TestFetchGitHubBranchProtection_RulesetsForbidden_ClassicSucceeds(t *testing.T) {
	mux := http.NewServeMux()
	handleBranchEntry(mux, "owner", "repo", "main", true)
	handleClassicProtection(mux, "owner", "repo", "main", false, true)
	handleEffectiveRulesStatus(mux, "owner", "repo", "main", http.StatusForbidden)
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b := branches[0]
	if !b.ProtectionDetailsKnown {
		t.Errorf("expected PDK=true via classic alone, got false")
	}
	if !b.CodeOwnerApprovalRequired {
		t.Errorf("expected code-owner=true from classic, got false")
	}
	if b.AllowForcePush {
		t.Errorf("expected force-push=false from classic, got true")
	}
}

// TestFetchGitHubBranchProtection_BothForbidden — both endpoints
// degrade. PDK must stay false so the rego rule abstains and the
// honest-postflight code path surfaces the partial state.
func TestFetchGitHubBranchProtection_BothForbidden(t *testing.T) {
	mux := http.NewServeMux()
	handleBranchEntry(mux, "owner", "repo", "main", true)
	handleClassicProtectionStatus(mux, "owner", "repo", "main", http.StatusForbidden)
	handleEffectiveRulesStatus(mux, "owner", "repo", "main", http.StatusForbidden)
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b := branches[0]
	if b.ProtectionDetailsKnown {
		t.Errorf("expected PDK=false when both endpoints 403, got true")
	}
}

// TestFetchGitHubBranchProtection_RulesetsEmpty — the rules endpoint
// authoritatively says "no active rules" (200 with []). PDK turns
// true on the back of the successful call alone; the IR flags come
// from classic.
func TestFetchGitHubBranchProtection_RulesetsEmpty(t *testing.T) {
	mux := http.NewServeMux()
	handleBranchEntry(mux, "owner", "repo", "main", true)
	handleClassicProtection(mux, "owner", "repo", "main", false, true)
	handleEffectiveRules(mux, "owner", "repo", "main", []map[string]any{})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b := branches[0]
	if !b.ProtectionDetailsKnown || !b.CodeOwnerApprovalRequired || b.AllowForcePush {
		t.Errorf("expected pdk=true coda=true afp=false (classic-only), got %+v", b)
	}
}

// TestFetchGitHubBranchProtection_OrgLevelRuleset — the endpoint
// flags org-level rulesets with ruleset_source_type=Organization.
// We do not filter on source: the merge logic should be identical.
func TestFetchGitHubBranchProtection_OrgLevelRuleset(t *testing.T) {
	mux := http.NewServeMux()
	handleBranchEntry(mux, "owner", "repo", "main", true)
	handleClassicProtectionStatus(mux, "owner", "repo", "main", http.StatusNotFound)
	handleEffectiveRules(mux, "owner", "repo", "main", []map[string]any{
		{
			"type":                "pull_request",
			"ruleset_source_type": "Organization",
			"ruleset_source":      "owner",
			"ruleset_id":          99,
			"parameters":          map[string]any{"require_code_owner_review": true},
		},
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	branches, err := FetchGitHubBranchProtection("", "owner", "repo", BranchFetchOptions{
		ExactNames: []string{"main"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b := branches[0]
	if !b.CodeOwnerApprovalRequired || !b.ProtectionDetailsKnown {
		t.Errorf("expected org-level ruleset to be honoured, got %+v", b)
	}
}

func TestFetchGitHubDefaultBranch_403_DegradesToEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	name, err := FetchGitHubDefaultBranch("", "owner", "repo")
	if err != nil {
		t.Fatalf("expected nil error on 403, got %v", err)
	}
	if name != "" {
		t.Errorf("expected empty default branch on 403, got %q", name)
	}
}
