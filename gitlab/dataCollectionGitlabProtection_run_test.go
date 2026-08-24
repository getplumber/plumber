package gitlab

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// protectionRunServer stands up a mux covering every endpoint
// GitlabProtectionDataCollection.Run touches, with the approval_rules endpoint's
// HTTP status parameterised so each test can drive the MRApprovalRulesKnown
// mapping without the other fetches aborting the run.
func protectionRunServer(approvalRulesStatus int, approvalRulesBody string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/approval_rules"):
			if approvalRulesStatus != http.StatusOK {
				w.WriteHeader(approvalRulesStatus)
				return
			}
			_, _ = w.Write([]byte(approvalRulesBody))
		case strings.HasSuffix(p, "/approvals"):
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(p, "/repository/branches"):
			_, _ = w.Write([]byte(`[{"name":"main"}]`))
		case strings.HasSuffix(p, "/protected_branches"):
			_, _ = w.Write([]byte(`[]`))
		case strings.HasSuffix(p, "/members/all"):
			_, _ = w.Write([]byte(`[]`))
		default: // GET /projects/:id — the project payload
			_, _ = w.Write([]byte(`{"id":42,"name":"proj"}`))
		}
	})
	return httptest.NewServer(mux)
}

// TestProtectionRun_ApprovalRulesKnownMapping pins the crux of the
// not-evaluable-vs-false-pass design: Run records MRApprovalRulesKnown=true only
// on a real success, false on a 403/404 (premium-gated, continue), and aborts
// the whole collection on any other error. None of the individual pieces
// (FetchProjectMRApprovalRules, buildApprovalRules, StatusFor) exercise this glue.
func TestProtectionRun_ApprovalRulesKnownMapping(t *testing.T) {
	proj := &ProjectInfo{ID: 42, Path: "group/project"}
	dc := &GitlabProtectionDataCollection{}

	t.Run("success -> Known=true with the rules", func(t *testing.T) {
		srv := protectionRunServer(http.StatusOK, `[{"id":7,"name":"r","approvals_required":1,"applies_to_all_protected_branches":true}]`)
		defer srv.Close()
		conf := &configuration.Configuration{GitlabURL: srv.URL, HTTPClientTimeout: 30 * time.Second}
		data, _, err := dc.Run(proj, "tok", conf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !data.MRApprovalRulesKnown {
			t.Fatal("a successful approval-rules fetch must set MRApprovalRulesKnown=true")
		}
		if len(data.MRApprovalRules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(data.MRApprovalRules))
		}
	})

	t.Run("403 (non-premium) -> Known=false, run continues", func(t *testing.T) {
		srv := protectionRunServer(http.StatusForbidden, "")
		defer srv.Close()
		conf := &configuration.Configuration{GitlabURL: srv.URL, HTTPClientTimeout: 30 * time.Second}
		data, _, err := dc.Run(proj, "tok", conf)
		if err != nil {
			t.Fatalf("a 403 on approval_rules must not abort the run: %v", err)
		}
		if data.MRApprovalRulesKnown {
			t.Fatal("a 403 approval-rules fetch must leave MRApprovalRulesKnown=false (not-evaluable), not a false pass")
		}
	})

	t.Run("404 (feature unavailable) -> Known=false, run continues", func(t *testing.T) {
		srv := protectionRunServer(http.StatusNotFound, "")
		defer srv.Close()
		conf := &configuration.Configuration{GitlabURL: srv.URL, HTTPClientTimeout: 30 * time.Second}
		data, _, err := dc.Run(proj, "tok", conf)
		if err != nil {
			t.Fatalf("a 404 on approval_rules must not abort the run: %v", err)
		}
		if data.MRApprovalRulesKnown {
			t.Fatal("a 404 approval-rules fetch must leave MRApprovalRulesKnown=false (not-evaluable), not a false pass")
		}
	})

	t.Run("other error (non-403/404) -> aborts the whole collection", func(t *testing.T) {
		// 400 rather than 500: a 5xx would trigger the client's retry/backoff
		// (slow); any non-403/404 status exercises the same abort branch in Run.
		srv := protectionRunServer(http.StatusBadRequest, "")
		defer srv.Close()
		conf := &configuration.Configuration{GitlabURL: srv.URL, HTTPClientTimeout: 30 * time.Second}
		if _, _, err := dc.Run(proj, "tok", conf); err == nil {
			t.Fatal("a non-403/404 error on approval_rules must abort the collection (return an error)")
		}
	})
}
