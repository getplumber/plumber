package gitlab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// TestFetchProjectMRApprovalRules_Paginates guards the truncation-to-false-pass
// regression: the approval_rules endpoint paginates (default per_page 20), and
// the caller marks the listing authoritative, so a rule on a later page must
// still be returned. The page-2 rule here requires only 1 approval — exactly the
// weak rule a truncated fetch would drop and turn into a false pass for ISSUE-502.
func TestFetchProjectMRApprovalRules_Paginates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/42/approval_rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Header().Set("X-Next-Page", "2")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 1, "name": "page1-rule", "approvals_required": 2, "applies_to_all_protected_branches": true},
			})
		case "2":
			// Final page: no X-Next-Page -> NextPage 0 -> loop terminates.
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 2, "name": "page2-rule", "approvals_required": 1, "applies_to_all_protected_branches": true},
			})
		default:
			t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	conf := &configuration.Configuration{HTTPClientTimeout: 30 * time.Second}

	rules, _, err := FetchProjectMRApprovalRules(42, "glpat-test", srv.URL, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name] = true
	}
	if len(rules) != 2 || !names["page1-rule"] || !names["page2-rule"] {
		t.Fatalf("expected the union of both pages, got %d rules: %v", len(rules), names)
	}
}

// TestFetchProjectMRApprovalRules_SinglePageTerminates: with no X-Next-Page the
// loop must stop after one request (no infinite loop / no extra call).
func TestFetchProjectMRApprovalRules_SinglePageTerminates(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/42/approval_rules", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1, "name": "only", "approvals_required": 2}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	conf := &configuration.Configuration{HTTPClientTimeout: 30 * time.Second}

	rules, _, err := FetchProjectMRApprovalRules(42, "t", srv.URL, conf)
	if err != nil || len(rules) != 1 {
		t.Fatalf("got (%d rules, %v), want (1, nil)", len(rules), err)
	}
	if calls != 1 {
		t.Errorf("expected the loop to terminate after 1 page, made %d calls", calls)
	}
}

// TestFetchProjectMRApprovalRules_ErrorPropagates: a mid-fetch API error must
// return a non-nil error so the caller leaves MRApprovalRulesKnown=false
// (not-evaluable) rather than treating a partial/empty list as authoritative.
func TestFetchProjectMRApprovalRules_ErrorPropagates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/42/approval_rules", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	conf := &configuration.Configuration{HTTPClientTimeout: 30 * time.Second}

	if _, _, err := FetchProjectMRApprovalRules(42, "t", srv.URL, conf); err == nil {
		t.Fatal("expected a non-nil error so the caller leaves MRApprovalRulesKnown=false")
	}
}
