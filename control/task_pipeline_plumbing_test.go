package control

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
)

// TestRunAnalysis_ExposesPipelineForAuthorizedSourcesStats pins the
// result.Pipeline plumbing the authorized-sources stat blocks read
// (cmd/render_details.go, componentMustComeFromAuthorizedSources and
// functionMustComeFromAuthorizedSources). Both blocks guard on a nil
// Pipeline, so if RunAnalysis stopped setting it the terminal would
// silently print "Total 0" next to a nonzero "Unauthorized". This drives
// the real entry point against the recording fake GitLab
// (platform_call_inventory_test.go), whose project config includes one
// component, with the embedded default config.
func TestRunAnalysis_ExposesPipelineForAuthorizedSourcesStats(t *testing.T) {
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "embedded-default")
	if err != nil {
		t.Fatalf("loading the embedded default config: %v", err)
	}
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL = srv.URL
	conf.GitlabToken = "glpat-plumbing"
	conf.ProjectPath = testProjectPath
	conf.HTTPClientTimeout = 10 * time.Second
	conf.GitlabRetryMaxRetries = 0
	conf.PlumberConfig = pc

	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Pipeline == nil {
		t.Fatal("RunAnalysis left result.Pipeline nil: the authorized-sources stat blocks would print zero totals")
	}

	components := 0
	for _, inc := range result.Pipeline.Includes {
		if inc.Kind != "component" {
			continue
		}
		components++
		if inc.Source == "" {
			t.Errorf("component include carries an empty Source, which ISSUE-414 skips: %+v", inc)
		}
	}
	if components != 1 {
		t.Fatalf("result.Pipeline carries %d component includes, want the 1 the project config includes (includes=%+v)", components, result.Pipeline.Includes)
	}
}
