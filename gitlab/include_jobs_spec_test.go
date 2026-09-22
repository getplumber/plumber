package gitlab

import (
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/configuration"
)

// TestDeriveIncludeJobsSpecIncludeContributesNoJobs is the #471 regression
// guard. A file loaded through `spec:include` holds input definitions, not
// jobs, yet GitLab lists it in the merged response's include list as a plain
// local include. Re-merging it on its own reads its top-level `inputs:` key
// as a job named "inputs", which the origin loop then cannot find in the
// merged pipeline and logs as an error, after a config-merge call nobody
// needed. The file is a KNOWN empty contribution: zero jobs, no request.
func TestDeriveIncludeJobsSpecIncludeContributesNoJobs(t *testing.T) {
	// Refuses every request: a spec:include file must never be fetched.
	srv := refusingServer(t)
	conf := &configuration.Configuration{
		HTTPClientTimeout: 5 * time.Second,
		GitlabURL:         srv.URL,
	}

	// Parsed by the same decoder the collector uses, so Spec has the exact
	// shape production hands DeriveIncludeJobs (yaml.v2 generic maps).
	var raw GitlabCIConf
	if err := yaml.Unmarshal([]byte(`
spec:
  include:
    - local: .gitlab-ci/inputs/defaults.yml
    - local: /.gitlab-ci/inputs/extra.yml
    - .gitlab-ci/inputs/bare.yml
`), &raw); err != nil {
		t.Fatalf("parse raw config: %v", err)
	}

	got, err := DeriveIncludeJobs(IncludeJobsRequest{
		RawConfig: &raw,
		Includes: []MergedCIConfResponseInclude{
			{Location: ".gitlab-ci/inputs/defaults.yml", Type: glOriginLocal, ContextProject: "my/project"},
			{Location: ".gitlab-ci/inputs/extra.yml", Type: glOriginLocal, ContextProject: "my/project"},
			{Location: ".gitlab-ci/inputs/bare.yml", Type: glOriginLocal, ContextProject: "my/project"},
			{Location: "jobs.yml", Type: glOriginLocal, ContextProject: "my/project"},
		},
		ProjectPath: "my/project",
		Conf:        conf,
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want one record per include, got %d", len(got))
	}
	// The three spec:include shapes: a `local:` map, a `local:` map with the
	// optional leading "/", and a bare string entry.
	for i := 0; i < 3; i++ {
		if !got[i].Known {
			t.Errorf("include %d is a spec:include input file: a KNOWN empty contribution, got Known=false", i)
		}
		if len(got[i].Jobs) != 0 {
			t.Errorf("include %d is a spec:include input file and contributes no jobs, got %v", i, got[i].Jobs)
		}
		if got[i].Nested {
			t.Errorf("include %d is not nested, it is the project's own input file", i)
		}
	}
	// The ordinary local include still goes through the fetch and, against
	// the refusing server, ends unknown: the short-circuit is scoped to the
	// spec:include entries only.
	if got[3].Known {
		t.Error("an ordinary local include must still be resolved (and here refused), not short-circuited")
	}
}
