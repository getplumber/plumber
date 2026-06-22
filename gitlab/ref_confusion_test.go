package gitlab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// TestRefResolvesAsTagAndBranch covers the ref-confusion (ISSUE-710) probe:
// it must report tag/branch existence independently and, critically, fire
// "both true" only when the ref genuinely resolves as a tag AND a branch.
// A 404 on either namespace is "not that kind of ref" (false, no error),
// so a clean tag pin or a clean branch ref never reads as ambiguous.
func TestRefResolvesAsTagAndBranch(t *testing.T) {
	conf := &configuration.Configuration{HTTPClientTimeout: 30 * time.Second}

	// The fixture project has v1 as BOTH a tag and a branch (the collision),
	// v3 as a tag only, and main as a branch only.
	tagRefs := map[string]bool{"v1": true, "v3": true}
	branchRefs := map[string]bool{"v1": true, "main": true}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		ref := p[strings.LastIndex(p, "/")+1:]
		isTag := strings.Contains(p, "/repository/tags/")
		isBranch := strings.Contains(p, "/repository/branches/")
		if (isTag && tagRefs[ref]) || (isBranch && branchRefs[ref]) {
			_ = json.NewEncoder(w).Encode(map[string]any{"name": ref})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "404 Not Found"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cases := []struct {
		ref             string
		wantTag, wantBr bool
	}{
		{"v1", true, true},    // tag + branch collision -> ambiguous
		{"v3", true, false},   // tag only -> clean
		{"main", false, true}, // branch only -> clean
		{"missing", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			tag, br, err := RefResolvesAsTagAndBranch("my-org/comp", tc.ref, "glpat-test", srv.URL, conf)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tag != tc.wantTag || br != tc.wantBr {
				t.Fatalf("ref %q: got (tag=%v, branch=%v), want (tag=%v, branch=%v)",
					tc.ref, tag, br, tc.wantTag, tc.wantBr)
			}
		})
	}
}
