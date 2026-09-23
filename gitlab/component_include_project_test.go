package gitlab

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/platform"
)

// componentOriginHashBeforeTheProjectWasCarried is the include origin hash the
// collector produced for the unmatched-instance fixture below, captured by
// running this file's helper against the code as it stood BEFORE a component
// include carried its project. It is pinned as a literal on purpose: the hash
// identifies an include across runs, findings and per-include inputs are
// looked up by it, so carrying the project must not re-key anything.
// Recomputing the expectation from the current code would assert nothing.
const componentOriginHashBeforeTheProjectWasCarried uint64 = 3996324544110821683

// componentFixtureCatalog is a catalogue listing for the fixture component's
// source project, holding one released version that still carries the
// component. Served on the include, it is what makes the run catalog-resolved
// without a single request.
func componentFixtureCatalog() *CICatalogResource {
	return &CICatalogResource{
		Name:     "comp",
		FullPath: "vendor/comp",
		WebPath:  "/vendor/comp",
		Versions: []CICatalogResourceVersion{
			{Name: "2.0.0", Components: []CIComponent{{Name: "build"}}},
		},
	}
}

// unmatchedInstanceLocation writes the component include the way the existing
// linked tests do: an instance prefix that is NOT the run's GitLab URL, so
// ParseGitlabComponentPath leaves it on the clean path. The location it
// produces is independent of the test server's port, which is what lets the
// hash above be pinned as a literal.
func unmatchedInstanceLocation(string) string { return "gitlab.com/vendor/comp/build@1.0.0" }

// matchingInstanceLocation writes it the way a real pipeline does, with the
// run's own instance in front - the shape of the capture that exposed this
// defect (gitlab.com/getplumber/plumber/plumber on a gitlab.com run).
func matchingInstanceLocation(instanceHost string) string {
	return instanceHost + "/vendor/comp/build@1.0.0"
}

// collectComponentOrigin runs the whole collector over one platform-served
// component include and returns the component origin it produced. The run is
// the linked (platform-engaged) one so nothing reaches the network: the
// merged YAML, the job attribution, the ref observation and, when the caller
// supplies one, the source catalogue all arrive on the served include.
func collectComponentOrigin(t *testing.T, catalog *CICatalogResource, locationFor func(instanceHost string) string) GitlabPipelineOriginDataFull {
	t.Helper()
	srv := refusingServer(t)

	instanceHost := strings.TrimPrefix(srv.URL, "http://")
	includeLocation := locationFor(instanceHost)
	refExists := false

	served, err := json.Marshal(MergedCIConfResponseInclude{
		Location:          includeLocation,
		Type:              glOriginComponent,
		ContextProject:    "my/project",
		JobsKnown:         true,
		Jobs:              []string{},
		RefExistsAsTag:    &refExists,
		RefExistsAsBranch: &refExists,
		SourceCatalog:     catalog,
	})
	if err != nil {
		t.Fatalf("marshal the served include: %v", err)
	}

	conf := linkedConf(srv.URL)
	conf.PlatformRun.Context.Snapshot = platform.Snapshot{Data: &platform.SnapshotData{
		SchemaVersion: "2",
		Includes:      []json.RawMessage{served},
	}}
	conf.PlatformRun.Config.MergedYAML = "stages:\n  - build\nbuild-job:\n  stage: build\n  script:\n    - echo built\n"
	conf.LocalCIConfigContent = []byte("include:\n  - component: " + includeLocation + "\n")

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

	var found []GitlabPipelineOriginDataFull
	for _, o := range data.Origins {
		if o.OriginType == originComponent {
			found = append(found, o)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one %q origin, got %d: %+v", originComponent, len(found), data.Origins)
	}
	return found[0]
}

// TestComponentIncludeCarriesItsProject covers the bill of materials' headline
// case (dependencies-graph design spec 4.1): the platform keys a component
// node on project + component_name, so a component include that reaches it
// with an empty project is unkeyable and never appears in the graph. The
// collector already splits the component path into a project and a component
// name to resolve the catalogue; the project half must be recorded on the
// include origin for EVERY component include, catalog-resolved or not - the
// real capture that exposed this was catalog-resolved and still arrived
// projectless.
//
// The project recorded is exactly the one the catalogue lookup used, so the
// two never disagree: with the run's own instance in front it is the bare
// project path, and with a foreign instance prefix (which
// ParseGitlabComponentPath leaves on the clean path) it keeps that prefix.
func TestComponentIncludeCarriesItsProject(t *testing.T) {
	cases := []struct {
		name        string
		catalog     *CICatalogResource
		locationFor func(string) string
		wantProject func(instanceHost string) string
	}{
		{
			name:        "own instance, catalog resolved",
			catalog:     componentFixtureCatalog(),
			locationFor: matchingInstanceLocation,
			wantProject: func(string) string { return "vendor/comp" },
		},
		{
			name:        "own instance, no catalogue served",
			catalog:     nil,
			locationFor: matchingInstanceLocation,
			wantProject: func(string) string { return "vendor/comp" },
		},
		{
			name:        "foreign instance prefix, catalog resolved",
			catalog:     componentFixtureCatalog(),
			locationFor: unmatchedInstanceLocation,
			wantProject: func(string) string { return "gitlab.com/vendor/comp" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var instanceHost string
			origin := collectComponentOrigin(t, tc.catalog, func(host string) string {
				instanceHost = host
				return tc.locationFor(host)
			})

			want := tc.wantProject(instanceHost)
			if origin.GitlabIncludeOrigin.Project != want {
				t.Errorf("GitlabIncludeOrigin.Project = %q, want %q: the platform cannot key a component node without it",
					origin.GitlabIncludeOrigin.Project, want)
			}
			// Nothing else about the include moves: the location stays the
			// version-stripped one the SQL group-by depends on, the version
			// is still read off the ref, and the component name is untouched.
			wantLocation := strings.TrimSuffix(tc.locationFor(instanceHost), "@1.0.0")
			if !strings.HasSuffix(origin.GitlabIncludeOrigin.Location, wantLocation) {
				t.Errorf("GitlabIncludeOrigin.Location = %q, want the version-stripped location %q",
					origin.GitlabIncludeOrigin.Location, wantLocation)
			}
			if origin.Version != "1.0.0" {
				t.Errorf("Version = %q, want %q", origin.Version, "1.0.0")
			}
			wantComponentName := ""
			if tc.catalog != nil {
				wantComponentName = "build"
			}
			if origin.FromGitlabCatalog != (tc.catalog != nil) {
				t.Errorf("FromGitlabCatalog = %v, want %v", origin.FromGitlabCatalog, tc.catalog != nil)
			}
			if origin.GitlabComponent.ComponentName != wantComponentName {
				t.Errorf("GitlabComponent.ComponentName = %q, want %q", origin.GitlabComponent.ComponentName, wantComponentName)
			}
		})
	}
}

// TestComponentIncludeOriginHashIgnoresTheProject is the invariant that makes
// the fix above safe to ship. The origin hash is regenerated from a marshal of
// the include origin right after the version is stripped from the location,
// and it is the stable identifier findings and per-include inputs are looked
// up by (includeOriginHash mirrors it from the merged response). Setting the
// project AFTER that regeneration is what keeps the hash byte-identical; move
// it before, and this test fails rather than every existing component finding
// silently re-keying.
func TestComponentIncludeOriginHashIgnoresTheProject(t *testing.T) {
	for _, tc := range []struct {
		name    string
		catalog *CICatalogResource
	}{
		{name: "catalog resolved", catalog: componentFixtureCatalog()},
		{name: "no catalogue served", catalog: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := collectComponentOrigin(t, tc.catalog, unmatchedInstanceLocation)
			if origin.GitlabIncludeOrigin.Project == "" {
				t.Fatal("fixture no longer carries a project: the hash assertion below would prove nothing")
			}
			if origin.OriginHash != componentOriginHashBeforeTheProjectWasCarried {
				t.Errorf("OriginHash = %d, want %d (the hash predates the project and must not move with it)",
					origin.OriginHash, componentOriginHashBeforeTheProjectWasCarried)
			}
		})
	}
}
