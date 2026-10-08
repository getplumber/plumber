// Package pipelines builds ir.NormalizedPipeline values from CI files for
// tests, so the controls' tests, the situation tests and the control
// package's corpus share one reading of the YAML instead of three copies.
//
// Two readings are offered. GitHubFromFiles and GitLabFromFiles go through
// the production collectors (github's workflow scan, gitlab's
// ToNormalizedPipeline over a merged configuration), offline: no action
// metadata, no project settings, nothing fetched. ParseGitHubWorkflow and
// ParseGitLabCI are the narrow test-time parsers the rule tests were
// written against, which read only the fields those tests need.
//
// Nothing outside tests imports this package.
package pipelines

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
)

// GitHubFromFiles copies the given workflow files into a scratch
// .github/workflows directory and scans it with the production collector,
// without action metadata enrichment (no network). Job names come out
// namespaced by workflow file base name ("release/publish"), as in a real
// run. A file the collector cannot read or parse fails the test.
func GitHubFromFiles(t testing.TB, files []string) *ir.NormalizedPipeline {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p, partial, err := github.ScanGitHubWorkflowsWithProgress("", "", root, "", false, false, nil)
	if err != nil {
		t.Fatalf("scan workflows: %v", err)
	}
	if len(partial) > 0 {
		t.Fatalf("scan workflows: %v", partial)
	}
	return p
}

// GitLabFromFiles reads one file as the project's merged CI configuration
// (what GitLab's lint endpoint returns as merged_yaml: includes inlined,
// extends resolved) and projects it through gitlab.ToNormalizedPipeline,
// the function a real run calls. Every top-level mapping that is not a
// reserved keyword becomes a job, as the collector's job map does, and
// every job counts as declared in the project's own file. Branch
// protection, settings variables and visibility are left for the caller
// to set from recorded facts.
func GitLabFromFiles(t testing.TB, files []string) *ir.NormalizedPipeline {
	t.Helper()
	if len(files) != 1 {
		t.Fatalf("GitLabFromFiles takes exactly one merged configuration, got %d files", len(files))
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var conf gitlab.GitlabCIConf
	if err := yaml.Unmarshal(raw, &conf); err != nil {
		t.Fatalf("parse %s: %v", files[0], err)
	}
	jobMap := map[string]*gitlab.GitlabPipelineJobData{}
	hardcoded := map[string]bool{}
	for name, v := range conf.GitlabJobs {
		if _, isMap := v.(map[any]any); !isMap {
			continue
		}
		jobMap[name] = &gitlab.GitlabPipelineJobData{Name: name, IsHardcoded: true}
		hardcoded[name] = true
	}
	origin := &gitlab.GitlabPipelineOriginData{
		Conf:            &conf,
		ConfString:      string(raw),
		MergedConf:      &conf,
		JobMap:          jobMap,
		JobHardcodedMap: hardcoded,
	}
	// Job images go through the collector's own resolution (the job's image,
	// else the default one, variables expanded from the file's own globals;
	// no project, group or instance values are recorded, so a placeholder
	// naming one of those stays unresolved, as when they are unreadable).
	defaultImage, err := gitlab.ParseDefaultImage(&conf)
	if err != nil {
		t.Fatalf("default image: %v", err)
	}
	globals, err := gitlab.ParseGlobalVariables(&conf)
	if err != nil {
		t.Fatalf("global variables: %v", err)
	}
	quiet := logrus.New()
	quiet.SetOutput(io.Discard)
	images, err := gitlab.JobImages(logrus.NewEntry(quiet), &conf, defaultImage, nil, nil, nil, globals)
	if err != nil {
		t.Fatalf("job images: %v", err)
	}
	return gitlab.ToNormalizedPipeline("", "", ".gitlab-ci.yml", origin, &gitlab.GitlabPipelineImageData{Images: images}, nil, nil, nil)
}
