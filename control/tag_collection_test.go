package control

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
)

// tagControlOn enables tagMustBeProtected on one provider; an absent
// control block collects nothing.
func tagControlOn(provider string) *configuration.PlumberConfig {
	on := true
	pc := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{}, GitHub: &configuration.ProviderConfig{}}
	c := &configuration.TagProtectionControlConfig{Enabled: &on}
	if provider == configuration.ProviderGitLab {
		pc.GitLab.Controls.TagMustBeProtected = c
	} else {
		pc.GitHub.Controls.TagMustBeProtected = c
	}
	return pc
}

func hasTagDegradedReason(r *AnalysisResult) bool {
	for _, reason := range r.DegradedReasons {
		if strings.HasPrefix(reason, degradedReasonTagProtectionPrefix) {
			return true
		}
	}
	return false
}

// The GitLab tag collection splits its failures like the other GitLab
// collectors: a network failure degrades the run, a permission failure
// only leaves tagMustBeProtected not evaluated. Run against the real
// collector so the error classification is tested end to end.
func TestCollectGitLabTagProtection(t *testing.T) {
	l := logrus.NewEntry(logrus.New())
	var hits atomic.Int32
	server := func(protectedStatus int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if strings.HasSuffix(r.URL.Path, "/protected_tags") && protectedStatus != http.StatusOK {
				w.WriteHeader(protectedStatus)
				return
			}
			_, _ = w.Write([]byte(`[]`))
		}))
	}
	conf := func(url string) *configuration.Configuration {
		return &configuration.Configuration{
			GitlabURL:         url,
			ProjectPath:       "group/project",
			HTTPClientTimeout: 5 * time.Second,
			PlumberConfig:     tagControlOn(configuration.ProviderGitLab),
		}
	}
	// notEvaluable runs the gap marker the way RunAnalysis does once the
	// engine has the collection in its pipeline.
	notEvaluable := func(data *gitlab.GitlabTagProtectionData) (string, bool) {
		r := &AnalysisResult{Pipeline: &ir.NormalizedPipeline{TagProtection: gitlab.BuildTagProtection(data)}}
		markTagProtectionGap(r, []ControlEntry{{ControlName: controlTagMustBeProtected}})
		reason, ok := r.NotEvaluable[controlTagMustBeProtected]
		return reason, ok
	}

	t.Run("network failure degrades the run", func(t *testing.T) {
		srv := server(http.StatusOK)
		url := srv.URL
		srv.Close() // connection refused

		result := &AnalysisResult{}
		data := collectGitLabTagProtection(l, conf(url), result)
		if data == nil || data.Known {
			t.Fatalf("want Known=false, got %+v", data)
		}
		if !result.DataCollectionDegraded || !hasTagDegradedReason(result) {
			t.Fatalf("want the run degraded with a tag reason, got degraded=%v reasons=%v", result.DataCollectionDegraded, result.DegradedReasons)
		}
		if reason, ok := notEvaluable(data); !ok || reason != ReasonCollectionFailed {
			t.Errorf("want not evaluable (%s), got %q, %v", ReasonCollectionFailed, reason, ok)
		}
	})

	t.Run("permission failure only leaves the control not evaluated", func(t *testing.T) {
		srv := server(http.StatusForbidden)
		defer srv.Close()

		result := &AnalysisResult{}
		data := collectGitLabTagProtection(l, conf(srv.URL), result)
		if data == nil || data.Known {
			t.Fatalf("want Known=false, got %+v", data)
		}
		if result.DataCollectionDegraded {
			t.Fatalf("a 403 must not degrade the run, got reasons %v", result.DegradedReasons)
		}
		if reason, ok := notEvaluable(data); !ok || reason != ReasonCollectionFailed {
			t.Errorf("want not evaluable (%s), got %q, %v", ReasonCollectionFailed, reason, ok)
		}
	})

	t.Run("a readable project is known", func(t *testing.T) {
		srv := server(http.StatusOK)
		defer srv.Close()

		result := &AnalysisResult{}
		data := collectGitLabTagProtection(l, conf(srv.URL), result)
		if data == nil || !data.Known || result.DataCollectionDegraded {
			t.Fatalf("want Known data and no degradation, got %+v, degraded=%v", data, result.DataCollectionDegraded)
		}
		if !result.CollectedLanes[laneGitLabTagProtection] {
			t.Error("the tag lane must be marked collected")
		}
		if _, ok := notEvaluable(data); ok {
			t.Error("known data must not be marked not evaluable")
		}
	})

	t.Run("a platform run fetches nothing", func(t *testing.T) {
		srv := server(http.StatusOK)
		defer srv.Close()
		hits.Store(0)

		c := conf(srv.URL)
		c.PlatformRun = &platform.RunContext{Context: &platform.ProjectContext{}}
		result := &AnalysisResult{}
		if data := collectGitLabTagProtection(l, c, result); data != nil {
			t.Fatalf("want no collection in platform mode, got %+v", data)
		}
		if hits.Load() != 0 {
			t.Errorf("platform mode made %d requests, want 0", hits.Load())
		}
		if !result.CollectedLanes[laneGitLabTagProtection] {
			t.Error("the lane is still marked: lane_not_served comes from controlsWithNoPlatformLane")
		}
	})

	t.Run("a disabled control fetches nothing", func(t *testing.T) {
		srv := server(http.StatusOK)
		defer srv.Close()
		hits.Store(0)

		c := conf(srv.URL)
		c.PlumberConfig = &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{}}
		result := &AnalysisResult{}
		if data := collectGitLabTagProtection(l, c, result); data != nil || hits.Load() != 0 || result.CollectedLanes[laneGitLabTagProtection] {
			t.Fatalf("want nothing collected, got data=%+v hits=%d lanes=%v", data, hits.Load(), result.CollectedLanes)
		}
	})
}

// tagFindingPatterns returns the tagPattern of every ISSUE-510 finding.
func tagFindingPatterns(findings []opaengine.Finding) []string {
	var out []string
	for _, f := range findings {
		if f.Code == "ISSUE-510" {
			p, _ := f.Data["tagPattern"].(string)
			out = append(out, p)
		}
	}
	return out
}

// The collected GitLab tags reach the policy through RunAnalysis: an
// unprotected v* tag is a finding, a protected one is not. Without the
// pipeline wiring in runRegoEngine the policy reads no tag data and both
// cases come out clean.
func TestRunAnalysis_TagProtectionReachesThePolicy(t *testing.T) {
	cases := []struct {
		name          string
		protectedTags string
		want          []string
	}{
		{name: "unprotected tag pattern", want: []string{"v*"}},
		{name: "protected tag pattern", protectedTags: `[{"name":"v*","create_access_levels":[{"access_level":40}]}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &gitlabRecorder{
				sha:           "0123456789abcdef0123456789abcdef01234567",
				tags:          `[{"name":"v1.0.0"}]`,
				protectedTags: tc.protectedTags,
			}
			srv := httptest.NewServer(rec)
			defer srv.Close()

			result, err := RunAnalysis(inventoryConf(t, srv.URL))
			if err != nil {
				t.Fatalf("analysis failed: %v", err)
			}
			if got := tagFindingPatterns(result.Findings); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("ISSUE-510 patterns = %v, want %v", got, tc.want)
			}
		})
	}
}

// swapTagFetch replaces the GitHub tag protection fetch so the remote
// analysis tests never need network or auth. Restores via t.Cleanup.
func swapTagFetch(t *testing.T, fn func(host, owner, repo string) (*ir.TagProtection, error)) {
	t.Helper()
	orig := fetchGitHubTagProtection
	fetchGitHubTagProtection = fn
	t.Cleanup(func() { fetchGitHubTagProtection = orig })
}

// On GitHub the tag enrichment fills the pipeline, and its outcome reaches
// the run: a failed fetch degrades it, an unreadable answer (no scope, a
// plan without rulesets) leaves tagMustBeProtected not evaluated only.
func TestRunGitHubAnalysisRemote_TagProtection(t *testing.T) {
	cases := []struct {
		name         string
		tp           *ir.TagProtection
		err          error
		wantKnown    bool
		wantDegraded bool
		wantGap      bool
	}{
		{
			name:      "readable repository",
			tp:        &ir.TagProtection{Known: true, Rules: []ir.TagProtectionRule{{ID: "1", Include: []string{"**"}, BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true}}, Tags: []string{"v1.0.0"}},
			wantKnown: true,
		},
		{
			name:         "fetch failure",
			tp:           &ir.TagProtection{Known: false},
			err:          errors.New("tag rulesets: HTTP 500"),
			wantDegraded: true,
			wantGap:      true,
		},
		{
			name:    "unreadable answer",
			tp:      &ir.TagProtection{Known: false},
			wantGap: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swapRemoteScan(t, remoteScanStub)
			swapDefaultBranchFetch(t, func(string, string, string) (string, error) { return "main", nil })
			var asked string
			swapTagFetch(t, func(host, owner, repo string) (*ir.TagProtection, error) {
				asked = owner + "/" + repo
				return tc.tp, tc.err
			})

			conf := &configuration.Configuration{PlumberConfig: tagControlOn(configuration.ProviderGitHub)}
			result, err := RunGitHubAnalysisRemote(conf, "owner", "repo", "main")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if asked != "owner/repo" {
				t.Fatalf("tag fetch asked for %q, want owner/repo", asked)
			}
			tp := result.GitHubPipeline.TagProtectionOrNil()
			if tp == nil || tp.Known != tc.wantKnown {
				t.Fatalf("pipeline tag protection = %+v, want Known=%v", tp, tc.wantKnown)
			}
			if got := result.DataCollectionDegraded && hasTagDegradedReason(result); got != tc.wantDegraded {
				t.Errorf("degraded with a tag reason = %v, want %v (reasons %v)", got, tc.wantDegraded, result.DegradedReasons)
			}
			reason, gap := result.NotEvaluable[controlTagMustBeProtected]
			if gap != tc.wantGap || (gap && reason != ReasonCollectionFailed) {
				t.Errorf("not evaluable = %v (%q), want %v (%s)", gap, reason, tc.wantGap, ReasonCollectionFailed)
			}
		})
	}
}

// The local GitHub path (RunGitHubAnalysis, a checkout on disk) runs its
// own copy of the tag enrichment, degrade and gap wiring: an unprotected
// tag is a finding, a failed fetch degrades the run, an unreadable answer
// only leaves tagMustBeProtected not evaluated.
func TestRunGitHubAnalysis_TagProtection(t *testing.T) {
	cases := []struct {
		name         string
		tp           *ir.TagProtection
		err          error
		wantPatterns []string
		wantDegraded bool
		wantGap      bool
	}{
		{
			name:         "unprotected tag pattern",
			tp:           &ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}},
			wantPatterns: []string{"v*"},
		},
		{
			name:         "fetch failure",
			tp:           &ir.TagProtection{Known: false},
			err:          errors.New("tag rulesets: HTTP 500"),
			wantDegraded: true,
			wantGap:      true,
		},
		{
			name:    "unreadable answer",
			tp:      &ir.TagProtection{Known: false},
			wantGap: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked string
			swapTagFetch(t, func(host, owner, repo string) (*ir.TagProtection, error) {
				asked = owner + "/" + repo
				return tc.tp, tc.err
			})

			conf := &configuration.Configuration{
				ProjectPath:   "owner/repo",
				Branch:        "main",
				GitRepoRoot:   writeMinimalGitHubWorkflowRow62(t),
				PlumberConfig: tagControlOn(configuration.ProviderGitHub),
			}
			result, err := RunGitHubAnalysis(conf)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if asked != "owner/repo" {
				t.Fatalf("tag fetch asked for %q, want owner/repo", asked)
			}
			if got := tagFindingPatterns(result.Findings); strings.Join(got, ",") != strings.Join(tc.wantPatterns, ",") {
				t.Errorf("ISSUE-510 patterns = %v, want %v", got, tc.wantPatterns)
			}
			if tp := result.GitHubPipeline.TagProtectionOrNil(); tp == nil || tp.Known != tc.tp.Known {
				t.Errorf("pipeline tag protection = %+v, want Known=%v", tp, tc.tp.Known)
			}
			if got := result.DataCollectionDegraded && hasTagDegradedReason(result); got != tc.wantDegraded {
				t.Errorf("degraded with a tag reason = %v, want %v (reasons %v)", got, tc.wantDegraded, result.DegradedReasons)
			}
			reason, gap := result.NotEvaluable[controlTagMustBeProtected]
			if gap != tc.wantGap || (gap && reason != ReasonCollectionFailed) {
				t.Errorf("not evaluable = %v (%q), want %v (%s)", gap, reason, tc.wantGap, ReasonCollectionFailed)
			}
		})
	}
}
