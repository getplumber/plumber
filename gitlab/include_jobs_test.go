package gitlab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/utils"
)

// loopOriginHash is the origin loop's hash computation, transcribed from
// dataCollectionGitlabPipelineOrigin.go. It exists so the test can compare the
// exported path against the in-place one rather than against a constant: a
// constant only catches a change to includeOriginHash, and the failure mode
// that matters is the two DRIFTING.
//
// If this stops matching the loop, this test is the thing to fix first.
func loopOriginHash(t *testing.T, inc MergedCIConfResponseInclude, instanceURL string) uint64 {
	t.Helper()
	origin := IncludeOriginWithoutRef{
		Location: inc.Location,
		Type:     inc.Type,
		Project:  inc.Extra.Project,
	}
	b, err := json.Marshal(origin)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	hash := utils.GenerateFNVHash(b)

	if inc.Type == glOriginComponent {
		instance, cleanPath, _ := ParseGitlabComponentPath(origin.Location, instanceURL)
		origin.Location = instance + "/" + cleanPath
		b, err = json.Marshal(origin)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		hash = utils.GenerateFNVHash(b)
	}
	return hash
}

// TestIncludeOriginHashMatchesTheOriginLoop is the guard on the whole export.
//
// The inputs map is keyed by this hash. A key that misses does not error: the
// include is fetched with NO inputs, comes back unparameterised, and an
// overridden component job is then misreported as project-authored. That is
// ISSUE-401 fired on a correct pipeline, and it is exactly what #286 was.
func TestIncludeOriginHashMatchesTheOriginLoop(t *testing.T) {
	const instance = "https://gitlab.com"

	cases := map[string]MergedCIConfResponseInclude{
		"component with version": {
			Location: "gitlab.com/vendor/components/build@1.2.3",
			Type:     glOriginComponent,
		},
		"same component, other version": {
			Location: "gitlab.com/vendor/components/build@2.0.0",
			Type:     glOriginComponent,
		},
		"project include": {
			Location: "templates/go.yml",
			Type:     glOriginProject,
			Extra: struct {
				Project string `json:"project,omitempty"`
				Ref     string `json:"ref,omitempty"`
			}{Project: "vendor/templates", Ref: "v1"},
		},
		"local include": {
			Location: ".gitlab/ci/build.yml",
			Type:     glOriginLocal,
		},
		"remote include": {
			Location: "https://example.test/ci.yml",
			Type:     glOriginRemote,
		},
	}

	for name, inc := range cases {
		t.Run(name, func(t *testing.T) {
			want := loopOriginHash(t, inc, instance)
			if got := includeOriginHash(inc, instance); got != want {
				t.Fatalf("hash drift: exported %d, origin loop %d", got, want)
			}
		})
	}

	// The version strip is the point of the component's second pass: two
	// versions of one component must share a key, or an upgrade looks like a
	// different include and loses its inputs.
	a := includeOriginHash(cases["component with version"], instance)
	b := includeOriginHash(cases["same component, other version"], instance)
	if a != b {
		t.Errorf("two versions of the same component must hash alike, got %d and %d", a, b)
	}
}

// TestDeriveIncludeJobsNestedContributesNothing pins the one case that is a
// determined empty rather than a failure. A nested include's jobs belong to
// the include that pulled it in, so it contributes none HERE - and that is an
// answer, not an absence.
func TestDeriveIncludeJobsNestedContributesNothing(t *testing.T) {
	srv := refusingServer(t)
	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         srv.URL,
	}

	got, err := DeriveIncludeJobs(IncludeJobsRequest{
		Includes: []MergedCIConfResponseInclude{
			{Location: "a.yml", Type: glOriginLocal, ContextProject: "other/project"},
		},
		ProjectPath: "my/project",
		Conf:        conf,
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want one record per include, got %d", len(got))
	}
	if !got[0].Nested {
		t.Error("an include whose ContextProject differs is nested")
	}
	if !got[0].Known {
		t.Error("a nested include contributes nothing, which is a KNOWN answer")
	}
	if len(got[0].Jobs) != 0 {
		t.Errorf("want no jobs, got %v", got[0].Jobs)
	}
}

// TestDeriveIncludeJobsUnresolvableIsUnknown covers the distinction the whole
// Known flag exists for. An include that could not be resolved still put its
// jobs in the merged pipeline; reading the empty list as "contributed nothing"
// makes those jobs look project-authored.
func TestDeriveIncludeJobsUnresolvableIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"403 Forbidden"}`))
	}))
	defer srv.Close()

	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         srv.URL,
	}

	got, err := DeriveIncludeJobs(IncludeJobsRequest{
		Includes: []MergedCIConfResponseInclude{
			{Location: "gitlab.com/v/c/build@1.0.0", Type: glOriginComponent, ContextProject: "my/project"},
		},
		ProjectPath: "my/project",
		Conf:        conf,
	})
	if err != nil {
		t.Fatalf("derive must not fail the whole batch for one include: %v", err)
	}
	if got[0].Known {
		t.Error("an include that could not be resolved must be unknown, not an empty answer")
	}
}

// TestDeriveIncludeJobsPreservesOrder pins the join key. The caller matches
// records to includes by index, so a dropped or reordered entry silently
// attributes one include's jobs to another.
func TestDeriveIncludeJobsPreservesOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"403"}`))
	}))
	defer srv.Close()

	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         srv.URL,
	}

	includes := []MergedCIConfResponseInclude{
		{Location: "one.yml", Type: glOriginLocal, ContextProject: "other/project"},
		{Location: "two.yml", Type: glOriginLocal, ContextProject: "my/project"},
		{Location: "three.yml", Type: glOriginLocal, ContextProject: "other/project"},
	}
	got, err := DeriveIncludeJobs(IncludeJobsRequest{
		Includes: includes, ProjectPath: "my/project", Conf: conf,
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got) != len(includes) {
		t.Fatalf("want %d records, got %d", len(includes), len(got))
	}
	if !got[0].Nested || got[1].Nested || !got[2].Nested {
		t.Errorf("records are out of order: nested = %v, %v, %v", got[0].Nested, got[1].Nested, got[2].Nested)
	}
	if strings.TrimSpace(includes[1].Location) != "two.yml" {
		t.Error("the request must not be mutated")
	}
}
