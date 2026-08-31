package gitlab

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// TestFetchProjectDetailsProjectsMergeSettings pins the eight merge-request
// settings onto the project projection.
//
// They are not read by this repository's own collection path, which takes
// them from FetchGitlabProject instead - so nothing here would notice if
// they silently stopped being populated. They exist for the embedding host:
// the Plumber platform imports this package to build its collector and
// serves them as `project_details`, which is the only way ISSUE-506 can be
// evaluated without the runner holding a token (#368 ask 4).
//
// They come from the same Projects.GetProject response as every other field
// above, so this costs no request. That is the point.
func TestFetchProjectDetailsProjectsMergeSettings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v4/projects/group%2Fproject/repository/commits" ||
			r.URL.Path == "/api/v4/projects/group/project/repository/commits" {
			_, _ = w.Write([]byte(`[{"id":"abc123"}]`))
			return
		}
		_, _ = w.Write([]byte(`{
			"id": 42,
			"name": "project",
			"path_with_namespace": "group/project",
			"default_branch": "main",
			"merge_method": "ff",
			"squash_option": "default_on",
			"merge_pipelines_enabled": true,
			"merge_trains_enabled": true,
			"allow_merge_on_skipped_pipeline": true,
			"resolve_outdated_diff_discussions": true,
			"printing_merge_request_link_enabled": true,
			"remove_source_branch_after_merge": true
		}`))
	}))
	defer srv.Close()

	conf := &configuration.Configuration{GitlabURL: srv.URL, HTTPClientTimeout: 10 * time.Second}
	project, err := FetchProjectDetails("group/project", "glpat-x", srv.URL, conf)
	if err != nil {
		t.Fatalf("FetchProjectDetails: %v", err)
	}

	if project.MergeMethod != "ff" {
		t.Errorf("MergeMethod = %q, want ff", project.MergeMethod)
	}
	if project.SquashOption != "default_on" {
		t.Errorf("SquashOption = %q, want default_on", project.SquashOption)
	}
	for name, got := range map[string]bool{
		"MergePipelinesEnabled":           project.MergePipelinesEnabled,
		"MergeTrainsEnabled":              project.MergeTrainsEnabled,
		"AllowMergeOnSkippedPipeline":     project.AllowMergeOnSkippedPipeline,
		"ResolveOutdatedDiffDiscussions":  project.ResolveOutdatedDiffDiscussions,
		"PrintingMergeRequestLinkEnabled": project.PrintingMergeRequestLinkEnabled,
		"RemoveSourceBranchAfterMerge":    project.RemoveSourceBranchAfterMerge,
	} {
		if !got {
			t.Errorf("%s was not projected from the API response", name)
		}
	}
}
