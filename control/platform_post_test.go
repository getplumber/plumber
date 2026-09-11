package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// platformSummaryFixture is a two-policy platform verdict: one evaluated and
// not blocking, one the CLI could not evaluate and that the platform blocks
// on anyway (its live monitoring, not this run).
func platformSummaryFixture() *PlatformPostSummary {
	return &PlatformPostSummary{
		GlobalLetter: "B",
		GlobalPoints: 83,
		HasGlobal:    true,
		Policies: []PlatformPolicyLine{
			{Name: "Baseline", Enforcement: "report", Letter: "C", FinalPoints: 66},
			{Name: "Prod", Enforcement: "block", Blocking: true},
		},
	}
}

// Spec s5: the merge-request comment's headline is the platform's global
// score and the body is the per-policy table. No local grade appears, because
// in platform mode there is none.
func TestGenerateMRComment_PlatformMode_HeadlineAndPolicyTable(t *testing.T) {
	body := generateMRComment(&AnalysisResult{CiValid: true}, mrCommentPC(), true,
		"enforcement comes from the platform's policies", nil, false, false, nil, nil, platformSummaryFixture())

	if !strings.Contains(body, ScoreBadgeURL("B")) {
		t.Errorf("the badge must show the platform's global letter:\n%s", body)
	}
	for _, want := range []string{
		"83 / 100",
		"| Policy | Enforcement | Score | Blocking |",
		"| Baseline | report | C - 66 / 100 | no |",
		"| Prod | block | _not evaluated_ | **yes** |",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	// The local controls table and issue details describe the LOCAL
	// configuration's evaluation, which platform mode does not publish.
	if strings.Contains(body, "### Controls") {
		t.Errorf("the local controls table must not be posted in platform mode:\n%s", body)
	}
}

// A push that returned no global score says so; it never falls back to a
// locally computed figure, and never prints a blank letter as if it were one.
func TestGenerateMRComment_PlatformMode_ScoreUnavailable(t *testing.T) {
	s := platformSummaryFixture()
	s.HasGlobal, s.GlobalLetter, s.GlobalPoints = false, "", 0

	body := generateMRComment(&AnalysisResult{CiValid: true}, mrCommentPC(), true, "gate", nil, false, false, nil, nil, s)

	if !strings.Contains(body, "score unavailable") {
		t.Errorf("want the score-unavailable headline:\n%s", body)
	}
	if strings.Contains(body, "img.shields.io") {
		t.Errorf("no badge may be rendered without a platform score:\n%s", body)
	}
	// The policy rows are still the run's own answer and stay.
	if !strings.Contains(body, "| Baseline | report | C - 66 / 100 | no |") {
		t.Errorf("the per-policy table survives a missing global score:\n%s", body)
	}
}

// A policy name is platform-controlled text landing in a Markdown table
// posted with Plumber's identity: a pipe or a newline in it must not be able
// to forge a row.
func TestGenerateMRComment_PlatformMode_SanitizesPolicyNames(t *testing.T) {
	s := &PlatformPostSummary{Policies: []PlatformPolicyLine{{Name: "a|b\nc", Enforcement: "report"}}}

	body := generateMRComment(&AnalysisResult{CiValid: true}, mrCommentPC(), true, "gate", nil, false, false, nil, nil, s)

	if strings.Contains(body, "| a|b") {
		t.Errorf("an unescaped pipe forged a table cell:\n%s", body)
	}
}

// A standalone comment is unchanged: no platform summary, no policy table.
func TestGenerateMRComment_StandaloneUnchangedByThePlatformBranch(t *testing.T) {
	body := generateMRComment(&AnalysisResult{CiValid: true}, mrCommentPC(), true, "gate",
		&PlumberScoreResult{Score: "A", FinalPoints: 100}, true, false, nil, nil, nil)

	if !strings.Contains(body, "### Controls") {
		t.Errorf("the standalone comment keeps its controls table:\n%s", body)
	}
	if strings.Contains(body, "| Policy | Enforcement | Score | Blocking |") {
		t.Errorf("a standalone run has no policy table:\n%s", body)
	}
}

// badgeServer answers the two calls a badge write makes and records the image
// URL it was asked to publish.
func badgeServer(t *testing.T, got *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var payload struct {
				ImageURL string `json:"image_url"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			*got = payload.ImageURL
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":1}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
}

// Spec s5: the badge letter is the platform's global letter.
func TestManageProjectBadgePlatform_UsesTheGlobalLetter(t *testing.T) {
	var published string
	srv := badgeServer(t, &published)
	defer srv.Close()
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL, conf.GitlabToken = srv.URL, "glpat-test"

	if err := ManageProjectBadgePlatform(42, conf, platformSummaryFixture()); err != nil {
		t.Fatalf("ManageProjectBadgePlatform: %v", err)
	}
	if published != ScoreBadgeURL("B") {
		t.Fatalf("published badge = %q, want the platform's global letter B", published)
	}
}

// No global score means NO badge write at all: the last good badge stays, and
// nothing locally computed replaces it.
func TestManageProjectBadgePlatform_NoGlobalScoreLeavesTheBadgeAlone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the badge API was called with no platform score: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL, conf.GitlabToken = srv.URL, "glpat-test"

	for name, s := range map[string]*PlatformPostSummary{
		"no summary":   nil,
		"no global":    {Policies: []PlatformPolicyLine{{Name: "A"}}},
		"blank letter": {HasGlobal: true, GlobalLetter: ""},
	} {
		if err := ManageProjectBadgePlatform(42, conf, s); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The global letter is platform-controlled text that reaches a Markdown
// image AND link target ("[![Plumber](<url>)](<url>)") and the shields.io
// badge URL, both built by string interpolation. Anything outside the closed
// A-E set the score has is not a score: the comment says "score unavailable"
// and the badge is left alone, rather than publishing a forged link with
// Plumber's identity on it.
func TestPlatformGlobalLetter_OutsideTheClosedSetIsNotAScore(t *testing.T) {
	hostile := "A)](https://evil.example.com)"

	t.Run("the merge-request comment refuses it", func(t *testing.T) {
		s := platformSummaryFixture()
		s.GlobalLetter = hostile

		body := generateMRComment(&AnalysisResult{CiValid: true}, mrCommentPC(), true, "gate", nil, false, false, nil, nil, s)

		if !strings.Contains(body, "score unavailable") {
			t.Errorf("want the score-unavailable headline for a letter that is not one:\n%s", body)
		}
		if strings.Contains(body, "evil.example.com") {
			t.Errorf("the hostile letter reached the comment:\n%s", body)
		}
		if strings.Contains(body, "img.shields.io") {
			t.Errorf("no badge may be rendered from a letter that is not a score:\n%s", body)
		}
		// The per-policy table is the run's own answer and is unaffected.
		if !strings.Contains(body, "| Baseline | report | C - 66 / 100 | no |") {
			t.Errorf("the policy rows survive an unusable global letter:\n%s", body)
		}
	})

	t.Run("the badge is not written", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("the badge API was called with a letter outside A-E: %s %s", r.Method, r.URL.Path)
		}))
		defer srv.Close()
		conf := configuration.NewDefaultConfiguration()
		conf.GitlabURL, conf.GitlabToken = srv.URL, "glpat-test"

		s := platformSummaryFixture()
		s.GlobalLetter = hostile

		if err := ManageProjectBadgePlatform(42, conf, s); err != nil {
			t.Fatalf("ManageProjectBadgePlatform: %v", err)
		}
	})

	t.Run("every letter the score actually has is still published", func(t *testing.T) {
		for _, letter := range []string{"A", "B", "C", "D", "E"} {
			var published string
			srv := badgeServer(t, &published)
			conf := configuration.NewDefaultConfiguration()
			conf.GitlabURL, conf.GitlabToken = srv.URL, "glpat-test"

			s := platformSummaryFixture()
			s.GlobalLetter = letter
			if err := ManageProjectBadgePlatform(42, conf, s); err != nil {
				t.Fatalf("%s: %v", letter, err)
			}
			if published != ScoreBadgeURL(letter) {
				t.Errorf("letter %s published %q, want the badge for that letter", letter, published)
			}
			srv.Close()
		}
	})
}
