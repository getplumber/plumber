package gitlab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/platform"
)

func boolPtr(b bool) *bool { return &b }

// linkedConf builds a configuration whose platform run is ENGAGED: a context
// was fetched, so the platform owns the lanes it serves. gitlabURL points at
// the server a test expects never to be contacted.
func linkedConf(gitlabURL string) *configuration.Configuration {
	return &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         gitlabURL,
		PlatformRun: &platform.RunContext{
			Endpoint:    "https://platform.example.com",
			ProjectPath: "my/project",
			Context:     &platform.ProjectContext{},
			Config: &platform.ConfigResolution{
				Source: platform.SourceSnapshot,
				Valid:  true,
			},
		},
	}
}

// refusingServer fails the test if it is ever contacted. Several tests below
// assert an absence of traffic rather than a returned value: the point of a
// host-supplied observation is that a tokenless runner answers WITHOUT
// reaching the source project, and a test that only checked the return value
// would still pass if the CLI quietly asked anyway.
func refusingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request should have been made, got %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestSuppliedRefExistenceAnswersWithoutAsking is the whole point of the
// observation fields: a run with no credential for the source project still
// gets a verdict, because the host that had one already looked.
func TestSuppliedRefExistenceAnswersWithoutAsking(t *testing.T) {
	srv := refusingServer(t)
	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         srv.URL,
	}
	l := logger.WithField("test", t.Name())

	inc := MergedCIConfResponseInclude{
		RefExistsAsTag:    boolPtr(true),
		RefExistsAsBranch: boolPtr(true),
	}
	tag, branch, known, _ := refExistence(inc, "group/proj", "v1", "", conf, l)
	if !known {
		t.Fatal("a supplied pair must be known")
	}
	if !tag || !branch {
		t.Fatalf("want tag+branch true, got tag=%v branch=%v", tag, branch)
	}
}

// TestSuppliedFalseIsAnAnswer separates the two states a bare boolean cannot:
// a determined false (this ref is genuinely not a tag) is a RESULT, and the
// control must render a verdict from it. Only an absent observation is
// unknown. Collapsing these is what makes a rate limit read as a clean pass.
func TestSuppliedFalseIsAnAnswer(t *testing.T) {
	srv := refusingServer(t)
	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         srv.URL,
	}
	l := logger.WithField("test", t.Name())

	inc := MergedCIConfResponseInclude{
		RefExistsAsTag:    boolPtr(true),
		RefExistsAsBranch: boolPtr(false),
	}
	tag, branch, known, _ := refExistence(inc, "group/proj", "v1", "", conf, l)
	if !known {
		t.Fatal("a determined false is still an answer; known must be true")
	}
	if !tag || branch {
		t.Fatalf("want tag=true branch=false, got tag=%v branch=%v", tag, branch)
	}
	if tag && branch {
		t.Fatal("this ref must not read as ambiguous")
	}
}

// TestPartialRefObservationIsIgnored guards the tempting shortcut of taking
// the half that arrived and defaulting the other. Ambiguity needs BOTH halves
// true, so a missing half could swing the verdict either way; taking one and
// defaulting the other manufactures a determined "not ambiguous" that nothing
// established.
//
// The assertion is deliberately stronger than "known is false": the upstream
// probe reports the OPPOSITE of the supplied half, so a run that leaked the
// partial observation into the result is visible as a wrong value rather than
// merely a missing one.
func TestPartialRefObservationIsIgnored(t *testing.T) {
	// The source project has v1 as neither a tag nor a branch.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "404 Not Found"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         srv.URL,
	}
	l := logger.WithField("test", t.Name())

	for name, inc := range map[string]MergedCIConfResponseInclude{
		"only tag":    {RefExistsAsTag: boolPtr(true)},
		"only branch": {RefExistsAsBranch: boolPtr(true)},
	} {
		t.Run(name, func(t *testing.T) {
			tag, branch, known, _ := refExistence(inc, "group/proj", "v1", "", conf, l)
			if !known {
				t.Fatal("the fallback probe answered, so the pair is known")
			}
			if tag || branch {
				t.Fatalf("the supplied half leaked into the result: tag=%v branch=%v", tag, branch)
			}
		})
	}
}

// TestUnreachableUpstreamIsUnknownNotFalse covers the state a bare boolean
// cannot carry. With nothing supplied and the source project unreachable,
// nothing established anything, and the caller must record that rather than
// consume the zero values. This is the silent pass ISSUE-402 exists to catch:
// a ref that could not be checked is not an unambiguous ref.
func TestUnreachableUpstreamIsUnknownNotFalse(t *testing.T) {
	// An unusable instance URL fails at client construction, before any
	// dial. A closed port would exercise the same branch in refExistence but
	// spends the retry transport's budget getting there, which is twelve
	// seconds of nothing for a test about a return value.
	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         "://not-a-url",
	}
	l := logger.WithField("test", t.Name())

	_, _, known, _ := refExistence(MergedCIConfResponseInclude{}, "group/proj", "v1", "", conf, l)
	if known {
		t.Fatal("an unreachable source project must be unknown, not a determined false")
	}
}

// TestAbsentObservationsStillProbeUpstream pins the compatibility promise: a
// run that receives no observations behaves exactly as it did before the
// fields existed. Every standalone CLI run is this case, so a regression here
// would be silent and universal.
func TestAbsentObservationsStillProbeUpstream(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		hits++
		// Both namespaces answer, so the ref genuinely is ambiguous and the
		// probe's own result - not a supplied one - drives the verdict.
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "v1"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         srv.URL,
	}
	l := logger.WithField("test", t.Name())

	tag, branch, known, _ := refExistence(MergedCIConfResponseInclude{}, "group/proj", "v1", "", conf, l)
	if hits == 0 {
		t.Fatal("with nothing supplied the CLI must ask upstream itself")
	}
	if !known || !tag || !branch {
		t.Fatalf("want a live-probed ambiguous ref, got tag=%v branch=%v known=%v", tag, branch, known)
	}
}

// TestIncludeObservationsDecodeTriState checks the wire contract the platform
// implements against. The distinction that matters is `false` versus absent:
// both are falsy in Go, and only the pointer keeps them apart.
func TestIncludeObservationsDecodeTriState(t *testing.T) {
	var inc MergedCIConfResponseInclude
	raw := `{
		"location": "gitlab.com/g/p/c@1.0.0",
		"ref_exists_as_tag": false,
		"source_catalog": {"versions": [{"name": "1.0.0", "components": [{"name": "c"}]}]}
	}`
	if err := json.Unmarshal([]byte(raw), &inc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if inc.RefExistsAsTag == nil {
		t.Fatal("a determined false must decode as a non-nil pointer, not absence")
	}
	if *inc.RefExistsAsTag {
		t.Fatal("want the determined value false")
	}
	if inc.RefExistsAsBranch != nil {
		t.Fatal("an omitted observation must decode as nil, not false")
	}
	if inc.SourceCatalog == nil || len(inc.SourceCatalog.Versions) != 1 {
		t.Fatalf("source_catalog did not decode: %+v", inc.SourceCatalog)
	}
}

// TestSuppliedCatalogueKeepsTheVersionRuleHere is the divergence this whole
// contract exists to prevent, expressed as a test.
//
// The catalogue publishes 2.0.0, but 2.0.0 dropped component "c". Reducing
// the listing to "newest version" - which is what a host serving a
// latest_version field must do - yields 2.0.0 and reports a component as
// upgradeable to a version that does not contain it. Applying the rule HERE,
// against the raw listing, yields 1.2.0.
//
// This is why the field is served verbatim.
func TestSuppliedCatalogueKeepsTheVersionRuleHere(t *testing.T) {
	var inc MergedCIConfResponseInclude
	raw := `{"source_catalog": {"versions": [
		{"name": "2.0.0", "components": [{"name": "other"}]},
		{"name": "1.2.0", "components": [{"name": "c"}, {"name": "other"}]},
		{"name": "1.0.0", "components": [{"name": "c"}]}
	]}}`
	if err := json.Unmarshal([]byte(raw), &inc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := latestCatalogVersion(inc.SourceCatalog, "c"); got != "1.2.0" {
		t.Fatalf("want 1.2.0, the newest version still carrying the component, got %q", got)
	}
	if got := latestCatalogVersion(inc.SourceCatalog, "other"); got != "2.0.0" {
		t.Fatalf("want 2.0.0 for a component that IS in the newest version, got %q", got)
	}
	if got := latestCatalogVersion(inc.SourceCatalog, "absent"); got != "" {
		t.Fatalf("a component in no version has no latest, got %q", got)
	}
}

// TestSourceCatalogThreeStates pins the wire contract for a catalogue lookup,
// including the case a project that is not a catalogue resource at all
// produces.
//
// GetGitlabCIComponentResource returns (nil, nil) there: a DETERMINED absence,
// not a failure. It has to reach us as present-but-empty, because our decoder
// reads absence as "not supplied" and falls through to its own lookup - which
// in the run this exists for has no credential and degrades the control. A
// determined "publishes nothing" must evaluate, not abstain.
func TestSourceCatalogThreeStates(t *testing.T) {
	decode := func(t *testing.T, raw string) MergedCIConfResponseInclude {
		t.Helper()
		var inc MergedCIConfResponseInclude
		if err := json.Unmarshal([]byte(raw), &inc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return inc
	}

	t.Run("determined: publishes this component", func(t *testing.T) {
		inc := decode(t, `{"source_catalog":{"versions":[{"name":"1.0.0","components":[{"name":"build"}]}]}}`)
		if inc.SourceCatalog == nil {
			t.Fatal("a served catalogue must decode as present")
		}
		if got := latestCatalogVersion(inc.SourceCatalog, "build"); got != "1.0.0" {
			t.Fatalf("want 1.0.0, got %q", got)
		}
	})

	t.Run("determined: not a catalogue resource", func(t *testing.T) {
		// The shape the platform must serve for GetGitlabCIComponentResource
		// returning (nil, nil). Present, so the CLI does not re-look-up;
		// empty, so there is no latest version to be behind.
		inc := decode(t, `{"source_catalog":{"versions":[]}}`)
		if inc.SourceCatalog == nil {
			t.Fatal("a determined absence must be PRESENT-but-empty, not omitted")
		}
		if got := latestCatalogVersion(inc.SourceCatalog, "build"); got != "" {
			t.Fatalf("nothing published means no latest version, got %q", got)
		}
	})

	t.Run("not determined: omitted", func(t *testing.T) {
		inc := decode(t, `{"location":"gitlab.com/g/p/c@1.0.0"}`)
		if inc.SourceCatalog != nil {
			t.Fatal("an omitted key must decode as nil so the CLI knows it was never answered")
		}
	})
}

// TestRefExistence_Linked_AbsentObservationNeverProbes covers the run this
// whole seam exists for: a pipeline on a branch nobody onboarded, whose job
// holds no credential for anything but its own project.
//
// The platform served this include and did not serve the ref observation
// with it. The fallback probe is then not a second chance, it is a request
// carrying an empty token: it answers 401, logs an error the operator cannot
// act on, and ends where it started - unknown. The question belongs to the
// lane the platform owns, so the CLI records that it went unanswered and
// asks nobody.
func TestRefExistence_Linked_AbsentObservationNeverProbes(t *testing.T) {
	srv := refusingServer(t)
	conf := linkedConf(srv.URL)
	l := logger.WithField("test", t.Name())

	tag, branch, known, observationMissing := refExistence(MergedCIConfResponseInclude{
		Location: "gitlab.com/vendor/comp/build@1.0.0",
		Type:     glOriginComponent,
	}, "vendor/comp", "1.0.0", "", conf, l)

	if known {
		t.Fatal("an observation the platform did not serve must be unknown, never a determined answer")
	}
	if tag || branch {
		t.Fatalf("nothing was established, so nothing may be reported: tag=%v branch=%v", tag, branch)
	}
	if !observationMissing {
		t.Fatal("the caller must be able to tell an unserved observation from a probe that failed")
	}
}
