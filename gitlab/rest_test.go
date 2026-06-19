package gitlab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// TestBranchExists backs the #222 fix: a non-existent --branch must be
// distinguishable from "branch exists but has no .gitlab-ci.yml" so the
// former can fail loudly instead of rendering a confusing limited report.
func TestBranchExists(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/42/repository/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "main"})
	})
	mux.HandleFunc("/api/v4/projects/42/repository/branches/ghost", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "404 Branch Not Found"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	conf := &configuration.Configuration{HTTPClientTimeout: 30 * time.Second}

	if got, err := BranchExists(42, "main", "glpat-test", srv.URL, conf); err != nil || !got {
		t.Errorf("existing branch: got (%v, %v), want (true, nil)", got, err)
	}
	if got, err := BranchExists(42, "ghost", "glpat-test", srv.URL, conf); err != nil || got {
		t.Errorf("missing branch: got (%v, %v), want (false, nil)", got, err)
	}
}
