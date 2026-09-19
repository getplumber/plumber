package gitlab

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/platform"
	"github.com/sirupsen/logrus"
)

// pipelineOriginServer stands up a mux covering the two GitLab endpoints a
// standalone (non-platform) run touches to reach a versioned project
// include: the GraphQL merged-config query, and the source project's tag
// listing. tagsStatus lets each test drive the tag listing's outcome
// (200 vs. 403) without touching the merged-config side.
func pipelineOriginServer(t *testing.T, sourceProject string, tagsStatus int) *httptest.Server {
	t.Helper()
	return pipelineOriginServerWithTags(t, sourceProject, tagsStatus, `[{"name":"templates/trivy/trivy@0.2.0"}]`)
}

// pipelineOriginServerWithTags is pipelineOriginServer with the 200 tag
// listing body under the caller's control, so a test can drive a listing
// that succeeds but holds no tag matching the include's prefix.
func pipelineOriginServerWithTags(t *testing.T, sourceProject string, tagsStatus int, tagsBody string) *httptest.Server {
	t.Helper()

	const mergedYaml = `stages:
  - test
trivy-scan:
  stage: test
  script:
    - echo scan
`

	graphqlBody := fmt.Sprintf(`{"data":{"ciConfig":{
		"mergedYaml":%q,
		"errors":[],
		"warnings":[],
		"status":"VALID",
		"includes":[{
			"location":"my-org/templates/trivy.yml",
			"type":"file",
			"contextProject":"my/project",
			"extra":{"project":%q,"ref":"templates/trivy/trivy@0.1.0"},
			"jobs_known":true,
			"jobs":[],
			"ref_exists_as_tag":false,
			"ref_exists_as_branch":false
		}],
		"stages":{"nodes":[]}
	}}}`, mergedYaml, sourceProject)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(graphqlBody))
	})
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repository/tags") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if tagsStatus != http.StatusOK {
			w.WriteHeader(tagsStatus)
			return
		}
		_, _ = w.Write([]byte(tagsBody))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// findProjectOrigin returns the sole "project" (external file) origin out of
// a run's Origins, failing the test if there is not exactly one. The run
// also reports a "hardcoded" origin for the project's own jobs, which is
// outside what these tests exercise.
func findProjectOrigin(t *testing.T, origins []GitlabPipelineOriginDataFull) GitlabPipelineOriginDataFull {
	t.Helper()
	var found []GitlabPipelineOriginDataFull
	for _, o := range origins {
		if o.OriginType == originProject {
			found = append(found, o)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one %q origin, got %d: %+v", originProject, len(found), origins)
	}
	return found[0]
}

// TestVersionedProjectIncludeKeepsIdentityWhenTagListingFails covers the
// case reported against a private template repository: a versioned project
// include (templates/trivy/trivy@0.1.0) must still be recognised for what
// it is, even when the source project's tag listing cannot be read (403,
// insufficient rights). The ref alone carries the identity; the tag listing
// only ever decided whether the pin was current.
func TestVersionedProjectIncludeKeepsIdentityWhenTagListingFails(t *testing.T) {
	const sourceProject = "my-org/templates"
	srv := pipelineOriginServer(t, sourceProject, http.StatusForbidden)

	conf := &configuration.Configuration{
		HTTPClientTimeout:    30 * time.Second,
		GitlabURL:            srv.URL,
		LocalCIConfigContent: []byte("stages:\n  - test\n"),
	}

	dc := &GitlabPipelineOriginDataCollection{}
	data, metrics, err := dc.Run(&ProjectInfo{
		ID:                  42,
		Path:                "my/project",
		DefaultBranch:       "main",
		AnalyzeBranch:       "main",
		CiConfPath:          ".gitlab-ci.yml",
		LatestHeadCommitSha: "1111111111111111111111111111111111111111",
	}, "glpat-test", conf)
	if err != nil {
		t.Fatalf("collection: %v", err)
	}

	origin := findProjectOrigin(t, data.Origins)

	if !origin.FromPlumber {
		t.Error("a versioned project include must be identified as a Plumber template even when the tag listing fails")
	}
	if origin.PlumberOrigin.Path != "templates/trivy/trivy" {
		t.Errorf("PlumberOrigin.Path = %q, want %q", origin.PlumberOrigin.Path, "templates/trivy/trivy")
	}
	if origin.Version != "0.1.0" {
		t.Errorf("Version = %q, want %q", origin.Version, "0.1.0")
	}
	if origin.PlumberOrigin.LatestVersion != "" {
		t.Errorf("LatestVersion = %q, want empty (the listing failed)", origin.PlumberOrigin.LatestVersion)
	}
	if origin.UpToDate {
		t.Error("UpToDate must be false when the latest version could not be determined")
	}
	if !containsString(data.VersionLookupsFailed, sourceProject) {
		t.Errorf("expected %q in VersionLookupsFailed, got %v", sourceProject, data.VersionLookupsFailed)
	}
	// The zero-valued UpToDate must not be read as a genuine "outdated"
	// verdict: with no latest version resolved, this include was never
	// compared against anything.
	if metrics.OriginOutdated != 0 {
		t.Errorf("OriginOutdated = %d, want 0 (no latest version was ever resolved)", metrics.OriginOutdated)
	}
}

// TestVersionedProjectIncludeUpToDateWhenTagListingSucceeds is the control:
// the same include, this time with a readable tag listing, still resolves
// LatestVersion and UpToDate as before. It pins that gating the readers on a
// successful listing did not disturb the success path.
func TestVersionedProjectIncludeUpToDateWhenTagListingSucceeds(t *testing.T) {
	const sourceProject = "my-org/templates"
	srv := pipelineOriginServer(t, sourceProject, http.StatusOK)

	conf := &configuration.Configuration{
		HTTPClientTimeout:    30 * time.Second,
		GitlabURL:            srv.URL,
		LocalCIConfigContent: []byte("stages:\n  - test\n"),
	}

	dc := &GitlabPipelineOriginDataCollection{}
	data, metrics, err := dc.Run(&ProjectInfo{
		ID:                  42,
		Path:                "my/project",
		DefaultBranch:       "main",
		AnalyzeBranch:       "main",
		CiConfPath:          ".gitlab-ci.yml",
		LatestHeadCommitSha: "1111111111111111111111111111111111111111",
	}, "glpat-test", conf)
	if err != nil {
		t.Fatalf("collection: %v", err)
	}
	origin := findProjectOrigin(t, data.Origins)

	if !origin.FromPlumber {
		t.Error("expected FromPlumber = true")
	}
	if origin.PlumberOrigin.LatestVersion != "0.2.0" {
		t.Errorf("LatestVersion = %q, want %q", origin.PlumberOrigin.LatestVersion, "0.2.0")
	}
	if origin.UpToDate {
		t.Error("0.1.0 is behind 0.2.0, UpToDate must be false")
	}
	if containsString(data.VersionLookupsFailed, sourceProject) {
		t.Errorf("the listing succeeded; %q must not be in VersionLookupsFailed", sourceProject)
	}
	if metrics.OriginOutdated != 1 {
		t.Errorf("OriginOutdated = %d, want 1 (a known latest version that the pin is behind)", metrics.OriginOutdated)
	}
}

// TestVersionedProjectIncludeKeepsIdentityWhenNoTagMatchesThePrefix pins that
// the identity comes from the ref even when the listing succeeds but holds
// no tag matching the include's prefix: a readable listing with nothing to
// compare against must read exactly like a failed one for LatestVersion and
// UpToDate, while still counting as an ESTABLISHED listing (unlike a 403,
// this project is not itself missing a version lookup).
func TestVersionedProjectIncludeKeepsIdentityWhenNoTagMatchesThePrefix(t *testing.T) {
	const sourceProject = "my-org/templates"
	srv := pipelineOriginServerWithTags(t, sourceProject, http.StatusOK, `[{"name":"v1.0.0"},{"name":"other@2.0.0"}]`)

	conf := &configuration.Configuration{
		HTTPClientTimeout:    30 * time.Second,
		GitlabURL:            srv.URL,
		LocalCIConfigContent: []byte("stages:\n  - test\n"),
	}

	dc := &GitlabPipelineOriginDataCollection{}
	data, _, err := dc.Run(&ProjectInfo{
		ID:                  42,
		Path:                "my/project",
		DefaultBranch:       "main",
		AnalyzeBranch:       "main",
		CiConfPath:          ".gitlab-ci.yml",
		LatestHeadCommitSha: "1111111111111111111111111111111111111111",
	}, "glpat-test", conf)
	if err != nil {
		t.Fatalf("collection: %v", err)
	}

	origin := findProjectOrigin(t, data.Origins)

	if !origin.FromPlumber {
		t.Error("a versioned project include must be identified as a Plumber template even when no tag matches its prefix")
	}
	if origin.PlumberOrigin.Path != "templates/trivy/trivy" {
		t.Errorf("PlumberOrigin.Path = %q, want %q", origin.PlumberOrigin.Path, "templates/trivy/trivy")
	}
	if origin.Version != "0.1.0" {
		t.Errorf("Version = %q, want %q", origin.Version, "0.1.0")
	}
	if origin.PlumberOrigin.LatestVersion != "" {
		t.Errorf("LatestVersion = %q, want empty (no tag matched the prefix)", origin.PlumberOrigin.LatestVersion)
	}
	if origin.UpToDate {
		t.Error("UpToDate must be false when no latest version could be determined")
	}
	if containsString(data.VersionLookupsFailed, sourceProject) {
		t.Errorf("the listing was established (just empty of a match); %q must not be in VersionLookupsFailed", sourceProject)
	}
}

// TestPipelineOrigin_LinkedRunKeepsVersionedProjectIncludeIdentityWithoutListingTags
// covers the platform-engaged path for a VERSIONED PROJECT include, which no
// existing linked test reached: every other linked test uses a component
// include, and the three collector tests above build a plain (non-platform)
// configuration. In platform mode, searchSourceProjectTags refuses to reach
// the include's source project at all - a pipeline job with no credential
// for it would only turn the missing listing into a 401 - so the tag listing
// is always unknown here, never attempted, regardless of what the platform
// served. The identity must still stand on the ref alone.
func TestPipelineOrigin_LinkedRunKeepsVersionedProjectIncludeIdentityWithoutListingTags(t *testing.T) {
	hook := captureLogrus(t)
	srv := refusingServer(t)

	const sourceProject = "my-org/templates"
	const includeLocation = "templates/trivy/trivy.yml"

	served, err := json.Marshal(MergedCIConfResponseInclude{
		Location:       includeLocation,
		Type:           glOriginProject,
		ContextProject: "my/project",
		Extra: struct {
			Project string `json:"project,omitempty"`
			Ref     string `json:"ref,omitempty"`
		}{Project: sourceProject, Ref: "templates/trivy/trivy@0.1.0"},
		// The job attribution is served (this include contributes no jobs of
		// its own here), so the run does not also abstain on that account -
		// what this test pins is the version lookup, served or not.
		JobsKnown: true,
		Jobs:      []string{},
	})
	if err != nil {
		t.Fatalf("marshal the served include: %v", err)
	}

	conf := linkedConf(srv.URL)
	conf.PlatformRun.Context.Snapshot = platform.Snapshot{Data: &platform.SnapshotData{
		SchemaVersion: "2",
		Includes:      []json.RawMessage{served},
	}}
	conf.PlatformRun.Config.MergedYAML = "stages:\n  - test\ntrivy-scan:\n  stage: test\n  script:\n    - echo scan\n"
	conf.LocalCIConfigContent = []byte("include:\n  - project: " + sourceProject + "\n    file: trivy.yml\n    ref: templates/trivy/trivy@0.1.0\n")

	dc := &GitlabPipelineOriginDataCollection{}
	data, _, err := dc.Run(&ProjectInfo{
		ID:                  42,
		Path:                "my/project",
		DefaultBranch:       "main",
		AnalyzeBranch:       "main",
		CiConfPath:          ".gitlab-ci.yml",
		LatestHeadCommitSha: "1111111111111111111111111111111111111111",
	}, "", conf)
	if err != nil {
		t.Fatalf("collection: %v", err)
	}

	// No request was made: the refusing server fails the test itself if it
	// is ever contacted (see refusingServer), so reaching this point at all
	// is part of the assertion.
	for _, entry := range hook.AllEntries() {
		if entry.Level <= logrus.WarnLevel {
			t.Errorf("a gap in what the platform served is not this job's fault to report: %s %q", entry.Level, entry.Message)
		}
	}

	origin := findProjectOrigin(t, data.Origins)
	if !origin.FromPlumber {
		t.Error("a versioned project include must be identified as a Plumber template even in platform mode, where the listing is never attempted")
	}
	if origin.PlumberOrigin.Path != "templates/trivy/trivy" {
		t.Errorf("PlumberOrigin.Path = %q, want %q", origin.PlumberOrigin.Path, "templates/trivy/trivy")
	}
	if origin.PlumberOrigin.LatestVersion != "" {
		t.Errorf("LatestVersion = %q, want empty (the listing is never attempted in platform mode)", origin.PlumberOrigin.LatestVersion)
	}
	// Platform mode never lists tags at all - the query is the platform's
	// to make and it did not make this one - so this reads as a fact the
	// platform did not serve, not as a probe this run attempted and failed.
	if !containsString(data.VersionObservationsMissing, sourceProject) {
		t.Errorf("expected %q in VersionObservationsMissing (platform mode never lists tags), got %v", sourceProject, data.VersionObservationsMissing)
	}
	if containsString(data.VersionLookupsFailed, sourceProject) {
		t.Errorf("nothing failed: the platform did not serve the listing, and the two must not read the same; got %v", data.VersionLookupsFailed)
	}
	// The served include carries no ref-existence observation, so the
	// ref-confusion probe (a separate concern from the version lookup) also
	// abstains rather than reaching for the network in this job's stead.
	if !containsString(data.ObservationsMissing, includeLocation) {
		t.Errorf("expected %q in ObservationsMissing (no ref observation was served), got %v", includeLocation, data.ObservationsMissing)
	}
}
