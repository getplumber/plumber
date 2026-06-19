package gitlab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// TestGetGitlabCIComponentResource covers the targeted per-component catalog
// lookup that replaces the instance-wide enumeration (#156): it must parse the
// resource + nested versions/components, and return (nil, nil) when no catalog
// resource exists at the path.
func TestGetGitlabCIComponentResource(t *testing.T) {
	conf := &configuration.Configuration{HTTPClientTimeout: 30 * time.Second}

	// Resolvable catalog resource.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"ciCatalogResource": map[string]any{
				"id": "gid://gitlab/Ci::Catalog::Resource/1", "name": "pre-commit-crocodile",
				"fullPath": "RadianDevCore/tools/pre-commit-crocodile",
				"webPath":  "/RadianDevCore/tools/pre-commit-crocodile",
				"versions": map[string]any{"nodes": []map[string]any{
					{"name": "8.2.1", "components": map[string]any{"nodes": []map[string]any{
						{"id": "1", "name": "commits", "includePath": "$CI_SERVER_FQDN/RadianDevCore/tools/pre-commit-crocodile/commits@8.2.1"},
					}}},
					{"name": "8.2.0", "components": map[string]any{"nodes": []map[string]any{
						{"id": "2", "name": "commits", "includePath": "$CI_SERVER_FQDN/RadianDevCore/tools/pre-commit-crocodile/commits@8.2.0"},
					}}},
				}},
			},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := GetGitlabCIComponentResource("RadianDevCore/tools/pre-commit-crocodile", "glpat-test", srv.URL, conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res == nil || res.Name != "pre-commit-crocodile" || len(res.Versions) != 2 {
		t.Fatalf("unexpected resource: %+v", res)
	}
	if res.Versions[0].Name != "8.2.1" || len(res.Versions[0].Components) != 1 || res.Versions[0].Components[0].Name != "commits" {
		t.Errorf("version/component mapping wrong: %+v", res.Versions[0])
	}

	// No catalog resource at this path -> (nil, nil) so the caller falls back to tags.
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/api/graphql", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciCatalogResource": nil}})
	})
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	res2, err2 := GetGitlabCIComponentResource("nope/nope", "glpat-test", srv2.URL, conf)
	if err2 != nil || res2 != nil {
		t.Errorf("non-catalog path: got (%v, %v), want (nil, nil)", res2, err2)
	}
}
