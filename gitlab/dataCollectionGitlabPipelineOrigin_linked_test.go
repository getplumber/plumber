package gitlab

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/platform"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

// captureLogrus installs a test hook on the process-global logger at Debug
// level and restores the original level and hook set afterwards. Both of the
// collector's loggers hang off logrus.StandardLogger(), so this is what lets
// a test assert on what a run PRINTED rather than only on what it returned.
func captureLogrus(t *testing.T) *logrustest.Hook {
	t.Helper()
	std := logrus.StandardLogger()
	savedLevel := std.GetLevel()
	savedHooks := std.Hooks
	std.SetLevel(logrus.DebugLevel)
	hook := logrustest.NewLocal(std)
	t.Cleanup(func() {
		std.ReplaceHooks(savedHooks)
		std.SetLevel(savedLevel)
	})
	return hook
}

// TestPipelineOrigin_LinkedRunWithAnUnobservedInclude is the whole run, end
// to end, for the case reported on a self-managed instance: a pipeline on a
// branch nobody had onboarded, holding no token of its own, evaluating a
// configuration the platform served with one include whose observations had
// not been collected yet.
//
// Three things are asserted together because each one alone would pass while
// the report stayed wrong. No request is made: the job has no credential to
// make it with, so every one of them answered 401. Nothing is logged above
// Debug: the errors that appeared named an API the operator never asked this
// job to reach, and there was no action behind any of them. And the include
// is RECORDED as unobserved, which is what turns the silence into a
// not_evaluable verdict instead of a clean pass over a control nobody could
// check.
func TestPipelineOrigin_LinkedRunWithAnUnobservedInclude(t *testing.T) {
	hook := captureLogrus(t)
	srv := refusingServer(t)

	const includeLocation = "gitlab.com/vendor/comp/build@1.0.0"

	served, err := json.Marshal(MergedCIConfResponseInclude{
		Location:       includeLocation,
		Type:           glOriginComponent,
		ContextProject: "my/project",
		// No jobs_known, no ref observation, no source catalogue: the
		// platform served the include and none of the facts about it.
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
	// The checkout's own CI file, so the root document needs no API call
	// either and the run's only remaining questions are about the include.
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

	if !containsString(data.ObservationsMissing, includeLocation) {
		t.Errorf("the unobserved include must be recorded, got %v", data.ObservationsMissing)
	}
	if containsString(data.IncludesFailed, includeLocation) {
		t.Error("nothing failed: the include was served, the facts about it were not, and the two must not read the same")
	}
	for _, entry := range hook.AllEntries() {
		if entry.Level <= logrus.WarnLevel {
			t.Errorf("a gap in what the platform served is not this job's fault to report: %s %q", entry.Level, entry.Message)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.TrimSpace(s) == needle {
			return true
		}
	}
	return false
}
