package gitlab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// TestGetSecurityPolicyProject pins the four read outcomes the ISSUE-601
// not-evaluable design depends on: a linked project, no linkage, the
// field-unavailable case, and an auth error.
func TestGetSecurityPolicyProject(t *testing.T) {
	conf := &configuration.Configuration{HTTPClientTimeout: 30 * time.Second}

	t.Run("linked -> parsed id/path, known", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"project": map[string]any{"securityPolicyProject": map[string]any{
					"id": "gid://gitlab/Project/4242", "fullPath": "grp/security-policies",
				}},
			}})
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		link, known, err := GetSecurityPolicyProject("grp/app", "tok", srv.URL, conf)
		if err != nil || !known {
			t.Fatalf("expected a known success, got known=%v err=%v", known, err)
		}
		if link == nil || link.ID != 4242 || link.FullPath != "grp/security-policies" {
			t.Fatalf("unexpected link: %+v", link)
		}
	})

	t.Run("none linked -> nil link, known", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"project": map[string]any{"securityPolicyProject": nil},
			}})
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		link, known, err := GetSecurityPolicyProject("grp/app", "tok", srv.URL, conf)
		if err != nil || !known || link != nil {
			t.Fatalf("none linked: expected (nil, true, nil), got (%+v, %v, %v)", link, known, err)
		}
	})

	t.Run("field unavailable -> not-evaluable, no error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{
				{"message": "Field 'securityPolicyProject' doesn't exist on type 'Project'"},
			}})
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		link, known, err := GetSecurityPolicyProject("grp/app", "tok", srv.URL, conf)
		if err != nil || known || link != nil {
			t.Fatalf("field unavailable: expected (nil, false, nil), got (%+v, %v, %v)", link, known, err)
		}
	})

	t.Run("auth error -> not-evaluable with error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		link, known, err := GetSecurityPolicyProject("grp/app", "tok", srv.URL, conf)
		if err == nil || known || link != nil {
			t.Fatalf("auth error: expected (nil, false, err), got (%+v, %v, %v)", link, known, err)
		}
	})
}

func TestParseGitlabGID(t *testing.T) {
	cases := map[string]int{
		"gid://gitlab/Project/12345": 12345,
		"gid://gitlab/Project/1":     1,
		"":                           0,
		"gid://gitlab/Project/":      0,
		"not-a-gid":                  0,
		"gid://gitlab/Project/abc":   0,
	}
	for in, want := range cases {
		if got := parseGitlabGID(in); got != want {
			t.Errorf("parseGitlabGID(%q) = %d, want %d", in, got, want)
		}
	}
}
