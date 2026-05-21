package policies_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/collector"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// reservedTopLevelKeys are GitLab CI top-level keys that must not be
// interpreted as jobs by the mini-parser below.
var reservedTopLevelKeys = map[string]struct{}{
	"stages":        {},
	"variables":     {},
	"default":       {},
	"include":       {},
	"workflow":      {},
	"image":         {},
	"services":      {},
	"before_script": {},
	"after_script":  {},
	"cache":         {},
}

// parseGitLabCI is a deliberately narrow parser that extracts only what the
// currently ported rules need (jobs + jobs.*.image). It is the test-time
// substitute for the full collector, which depends on the GitLab API.
// Limitations: no include/extend resolution, no default image propagation,
// no variable expansion. Extend as new rules require it.
func parseGitLabCI(t *testing.T, data []byte) *ir.NormalizedPipeline {
	t.Helper()

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse yaml: %v", err)
	}

	var jobs []ir.Job
	for key, value := range raw {
		if _, reserved := reservedTopLevelKeys[key]; reserved {
			continue
		}
		section, ok := toStringMap(value)
		if !ok {
			continue
		}
		job := ir.Job{Name: key}
		if img, ok := parseImageField(section["image"]); ok {
			job.Image = &img
		}
		if svc := parseServicesField(section["services"]); len(svc) > 0 {
			job.Services = svc
		}
		if vars := parseVariablesField(section["variables"]); len(vars) > 0 {
			job.Variables = vars
			// Fixtures are user-authored .gitlab-ci.yml files: every
			// `variables:` block on a job is the project's own. Mirror
			// the production collector by exposing them as
			// LocalVariables too so policies that distinguish "user
			// wrote this" from merged-in upstream see them.
			job.LocalVariables = vars
		}
		if af, ok := section["allow_failure"].(bool); ok {
			job.AllowFailure = af
		}
		if w, ok := section["when"].(string); ok {
			job.When = w
		}
		if scripts := parseScriptsField(section["script"]); len(scripts) > 0 {
			job.Scripts = scripts
		}
		jobs = append(jobs, job)
	}

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Name < jobs[j].Name })
	return &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Jobs: jobs}
}

// parseServicesField accepts the GitLab services polymorphic form:
// list of strings or list of {name: …} maps.
func parseServicesField(v any) []ir.Image {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]ir.Image, 0, len(list))
	for _, item := range list {
		switch s := item.(type) {
		case string:
			out = append(out, splitNameTag(s))
		case map[any]any:
			m, _ := toStringMap(s)
			if name, ok := m["name"].(string); ok {
				out = append(out, splitNameTag(name))
			}
		}
	}
	return out
}

// parseScriptsField normalises the GitLab script: block into a list.
func parseScriptsField(v any) []string {
	switch s := v.(type) {
	case string:
		return []string{s}
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// parseVariablesField stringifies the variables map for policy consumption.
func parseVariablesField(v any) map[string]string {
	m, ok := toStringMap(v)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
			continue
		}
		out[k] = fmt.Sprintf("%v", val)
	}
	return out
}

// parseGitHubActions is the GitHub counterpart of parseGitLabCI. It walks
// workflow `jobs.<name>.container`, which may be either a string shortcut
// ("alpine:latest") or a map ({"image": "...", ...}), and maps each job to
// the shared IR so policies remain provider-agnostic.
// Limitations: `steps[].uses` and matrix strategies are not modeled yet.
func parseGitHubActions(t *testing.T, data []byte) *ir.NormalizedPipeline {
	t.Helper()

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse yaml: %v", err)
	}

	jobsMap, ok := toStringMap(raw["jobs"])
	if !ok {
		t.Fatalf("workflow is missing a top-level jobs: mapping")
	}

	var jobs []ir.Job
	for name, v := range jobsMap {
		section, ok := toStringMap(v)
		if !ok {
			continue
		}
		job := ir.Job{Name: name}
		if img, ok := parseGitHubContainer(section["container"]); ok {
			job.Image = &img
		}
		if uses := parseGitHubStepsUses(section["steps"]); len(uses) > 0 {
			job.Uses = uses
		}
		if jobUses, ok := section["uses"].(string); ok && jobUses != "" {
			job.ReusableWorkflowUses = jobUses
		}
		jobs = append(jobs, job)
	}

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Name < jobs[j].Name })
	return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: jobs}
}

// parseGitHubContainer accepts both `container: "name:tag"` and
// `container: { image: "name:tag" }`.
func parseGitHubContainer(v any) (ir.Image, bool) {
	switch c := v.(type) {
	case string:
		return splitNameTag(c), true
	case map[any]any:
		m, _ := toStringMap(c)
		if img, ok := m["image"].(string); ok {
			return splitNameTag(img), true
		}
	}
	return ir.Image{}, false
}

// toStringMap normalizes the yaml.v2 untyped map form to map[string]any.
func toStringMap(v any) (map[string]any, bool) {
	m, ok := v.(map[any]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(m))
	for k, vv := range m {
		ks, ok := k.(string)
		if !ok {
			continue
		}
		out[ks] = vv
	}
	return out, true
}

// parseImageField accepts both the `image: "name:tag"` shorthand and the
// `image: { name: "...", tag: "..." }` long form.
func parseImageField(v any) (ir.Image, bool) {
	switch img := v.(type) {
	case string:
		return splitNameTag(img), true
	case map[any]any:
		m, _ := toStringMap(img)
		name, _ := m["name"].(string)
		tag, _ := m["tag"].(string)
		if name == "" {
			return ir.Image{}, false
		}
		if tag == "" && strings.Contains(name, ":") {
			// Sometimes the whole reference lands in `name`.
			return splitNameTag(name), true
		}
		return ir.Image{Name: name, Tag: tag}, true
	default:
		return ir.Image{}, false
	}
}

func splitNameTag(ref string) ir.Image {
	// Digest form takes precedence: "alpine@sha256:..."
	if at := strings.Index(ref, "@"); at > 0 {
		return ir.Image{Name: ref[:at], Digest: ref[at+1:]}
	}
	if idx := strings.LastIndex(ref, ":"); idx > 0 {
		return ir.Image{Name: ref[:idx], Tag: ref[idx+1:]}
	}
	return ir.Image{Name: ref}
}

// TestIssue102_ImageMutableTag drives the embedded image_mutable_tag policy
// against real CI/CD fixtures for both GitLab and GitHub. The same Rego
// policy is used unchanged — only the test-time YAML → IR parser differs
// per provider, which is the whole point of the multi-provider refactor.
func TestIssue102_ImageMutableTag(t *testing.T) {
	type fixture struct {
		file            string
		expectedJobHits []string
	}
	type providerSuite struct {
		name     string
		dir      string
		parse    func(*testing.T, []byte) *ir.NormalizedPipeline
		fixtures []fixture
	}

	suites := []providerSuite{
		{
			name:  "gitlab",
			dir:   filepath.Join("testdata", "ISSUE-102", "gitlab"),
			parse: parseGitLabCI,
			fixtures: []fixture{
				{"violation_latest.gitlab-ci.yml", []string{"deploy"}},
				{"violation_wildcards.gitlab-ci.yml", []string{"ci"}},
				{"clean.gitlab-ci.yml", nil},
			},
		},
		{
			name:  "github",
			dir:   filepath.Join("testdata", "ISSUE-102", "github"),
			parse: parseGitHubActions,
			fixtures: []fixture{
				{"violation_latest.workflow.yml", []string{"deploy"}},
				{"violation_wildcards.workflow.yml", []string{"ci"}},
				{"clean.workflow.yml", nil},
			},
		},
	}

	forbiddenTags := []string{"latest", "dev", "*-alpha"}
	cfg := map[string]any{
		"imageMutableTag": map[string]any{"forbiddenTags": forbiddenTags},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	for _, suite := range suites {
		for _, fx := range suite.fixtures {
			t.Run(suite.name+"/"+fx.file, func(t *testing.T) {
				path := filepath.Join(suite.dir, fx.file)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				pipeline := suite.parse(t, data)

				findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
				if err != nil {
					t.Fatalf("evaluate: %v", err)
				}

				hits := make([]string, 0, len(findings))
				for _, f := range findings {
					if f.Code != "ISSUE-102" {
						continue
					}
					hits = append(hits, f.Job)
				}
				sort.Strings(hits)
				sort.Strings(fx.expectedJobHits)
				if !stringSlicesEqual(hits, fx.expectedJobHits) {
					t.Fatalf("%s/%s: expected hits on %v, got %v",
						suite.name, fx.file, fx.expectedJobHits, hits)
				}
			})
		}
	}
}

// TestIssue509_ExcessivePermissions drives the excessive_permissions
// policy against real GitHub workflow fixtures. It uses the real
// production collector (ScanGitHubWorkflows) rather than the test-time
// parser to exercise the permissions propagation end-to-end.
func TestIssue509_ExcessivePermissions(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{
			fixture:      "violation_workflow_write_all.yml",
			expectedHits: []string{"violation_workflow_write_all/publish"},
		},
		{
			fixture:      "violation_job_write_all.yml",
			expectedHits: []string{"violation_job_write_all/loose"},
		},
		{
			fixture:      "clean_minimal.yml",
			expectedHits: nil,
		},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			// Stage the fixture under a fake .github/workflows/ dir so
			// ScanGitHubWorkflows can discover it unmodified.
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-803", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}

			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			hits := make([]string, 0, len(findings))
			for _, f := range findings {
				if f.Code != "ISSUE-803" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue414_DangerousTriggers drives the dangerous_triggers policy
// against fixtures covering the two primary risky trigger types and
// the safe baseline. As for ISSUE-803 the test exercises the real
// production collector (ScanGitHubWorkflows) rather than the test-time
// parser.
func TestIssue414_DangerousTriggers(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{
			fixture:      "violation_pull_request_target.yml",
			expectedHits: []string{"violation_pull_request_target/preview"},
		},
		{
			fixture:      "violation_workflow_run.yml",
			expectedHits: []string{"violation_workflow_run/post"},
		},
		{
			fixture:      "clean_pull_request.yml",
			expectedHits: nil,
		},
		// Regression: the extended dangerous-events set must fire
		// once per (job, trigger) pair. The fixture has one job and
		// seven dangerous triggers (issue_comment + 2 PR review
		// variants + 2 discussion variants + gollum + fork), so
		// expect the same job name to appear seven times.
		{
			fixture: "violation_extended_triggers.yml",
			expectedHits: []string{
				"violation_extended_triggers/comment-handler",
				"violation_extended_triggers/comment-handler",
				"violation_extended_triggers/comment-handler",
				"violation_extended_triggers/comment-handler",
				"violation_extended_triggers/comment-handler",
				"violation_extended_triggers/comment-handler",
				"violation_extended_triggers/comment-handler",
			},
		},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-802", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}

			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			hits := make([]string, 0, len(findings))
			for _, f := range findings {
				if f.Code != "ISSUE-802" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue206_TemplateInjection drives the template_injection policy
// against fixtures covering the two most common unsafe patterns and
// the canonical safe env-variable workaround.
func TestIssue206_TemplateInjection(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{
			fixture:      "violation_pr_title.yml",
			expectedHits: []string{"violation_pr_title/bad"},
		},
		{
			fixture:      "violation_head_ref.yml",
			expectedHits: []string{"violation_head_ref/bad"},
		},
		{
			fixture:      "clean_env_var.yml",
			expectedHits: nil,
		},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-207", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}

			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			hits := make([]string, 0, len(findings))
			for _, f := range findings {
				if f.Code != "ISSUE-207" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue208_InsecureCommands drives the insecure_commands policy
// against a violation where `ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'`
// is set at the job level, and a baseline job with benign env vars.
func TestIssue208_InsecureCommands(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{
			fixture:      "violation_enabled.yml",
			expectedHits: []string{"violation_enabled/bad"},
		},
		{
			fixture:      "clean.yml",
			expectedHits: nil,
		},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-208", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}

			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			hits := make([]string, 0, len(findings))
			for _, f := range findings {
				if f.Code != "ISSUE-208" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue307_Artipacked drives the artipacked policy against a
// default actions/checkout (violation) and one explicitly passing
// `persist-credentials: false` (clean).
func TestIssue307_Artipacked(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{
			fixture:      "violation_default_checkout.yml",
			expectedHits: []string{"violation_default_checkout/clone"},
		},
		{
			fixture:      "clean_credentials_disabled.yml",
			expectedHits: nil,
		},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-307", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}

			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			hits := make([]string, 0, len(findings))
			for _, f := range findings {
				if f.Code != "ISSUE-307" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue103_ImagePinnedByDigest drives the image_pinned_by_digest
// policy against GitLab and GitHub fixtures, covering both the tagged
// violation and the digest-pinned clean baseline. The policy only
// fires when mustBePinnedByDigest is explicitly enforced in the
// input config.
func TestIssue103_ImagePinnedByDigest(t *testing.T) {
	type fixture struct {
		file            string
		expectedJobHits []string
	}
	type providerSuite struct {
		name     string
		dir      string
		parse    func(*testing.T, []byte) *ir.NormalizedPipeline
		fixtures []fixture
	}

	suites := []providerSuite{
		{
			name:  "gitlab",
			dir:   filepath.Join("testdata", "ISSUE-103", "gitlab"),
			parse: parseGitLabCI,
			fixtures: []fixture{
				{"violation_tagged.gitlab-ci.yml", []string{"build", "deploy"}},
				{"clean_pinned.gitlab-ci.yml", nil},
			},
		},
		{
			name:  "github",
			dir:   filepath.Join("testdata", "ISSUE-103", "github"),
			parse: parseGitHubActions,
			fixtures: []fixture{
				{"violation_tagged.workflow.yml", []string{"build"}},
				{"clean_pinned.workflow.yml", nil},
			},
		},
	}

	cfg := map[string]any{
		"containerImageMustNotUseForbiddenTags": map[string]any{
			"mustBePinnedByDigest": true,
		},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	for _, suite := range suites {
		for _, fx := range suite.fixtures {
			t.Run(suite.name+"/"+fx.file, func(t *testing.T) {
				path := filepath.Join(suite.dir, fx.file)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				pipeline := suite.parse(t, data)

				findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
				if err != nil {
					t.Fatalf("evaluate: %v", err)
				}

				hits := make([]string, 0, len(findings))
				for _, f := range findings {
					if f.Code != "ISSUE-103" {
						continue
					}
					hits = append(hits, f.Job)
				}
				sort.Strings(hits)
				expected := append([]string(nil), fx.expectedJobHits...)
				sort.Strings(expected)
				if !stringSlicesEqual(hits, expected) {
					t.Fatalf("%s/%s: expected %v, got %v",
						suite.name, fx.file, expected, hits)
				}
			})
		}
	}
}

// TestIssue412_DockerInDocker flags GitLab jobs attaching a DinD service.
func TestIssue412_DockerInDocker(t *testing.T) {
	runGitLabPolicyCases(t, "ISSUE-412", []policyCase{
		{"violation_dind.gitlab-ci.yml", []string{"docker-build"}},
		{"clean_kaniko.gitlab-ci.yml", nil},
	}, nil)
}

// TestIssue413_DockerInDockerInsecure flags DinD with TLS disabled.
func TestIssue413_DockerInDockerInsecure(t *testing.T) {
	runGitLabPolicyCases(t, "ISSUE-413", []policyCase{
		{"violation_tls_disabled.gitlab-ci.yml", []string{"docker-build"}},
		{"clean_tls_enabled.gitlab-ci.yml", nil},
	}, nil)
}

// TestIssue203_DebugTrace flags jobs enabling CI_DEBUG_TRACE.
// The legacy Go control disables itself when forbiddenVariables is
// empty, so the Rego policy mirrors that contract: cfg must declare
// the list explicitly — there is no built-in default.
func TestIssue203_DebugTrace(t *testing.T) {
	cfg := map[string]any{
		"debugTrace": map[string]any{
			"forbiddenVariables": []string{"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"},
		},
	}
	runGitLabPolicyCases(t, "ISSUE-203", []policyCase{
		{"violation_debug_enabled.gitlab-ci.yml", []string{"deploy"}},
		{"clean.gitlab-ci.yml", nil},
	}, cfg)
}

// TestIssue411_UnverifiedScripts flags pipe-to-shell patterns.
func TestIssue411_UnverifiedScripts(t *testing.T) {
	runGitLabPolicyCases(t, "ISSUE-411", []policyCase{
		{"violation_pipe_to_shell.gitlab-ci.yml", []string{"install"}},
		{"clean_checksum.gitlab-ci.yml", nil},
	}, nil)
}

// TestIssue403_IncludesOutdated flags includes whose ref differs from
// the resolved latest version.
func TestIssue403_IncludesOutdated(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "component", Source: "plumber/base", Ref: "1.0.0", Current: "1.2.3"},
			{Kind: "component", Source: "plumber/other", Ref: "2.0.0", Current: "2.0.0"},
			{Kind: "local", Source: "ci/lint.yml"},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := 0
	for _, f := range findings {
		if f.Code == "ISSUE-403" {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("expected 1 ISSUE-403 finding, got %d", hits)
	}
}

// TestIssue501_BranchUnprotected flags branches matching a required
// name pattern that the provider reports as unprotected.
func TestIssue501_BranchUnprotected(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"branchMustBeProtected": map[string]any{
			"namePatterns":           []string{"release-*"},
			"defaultMustBeProtected": true,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches: []ir.Branch{
			{Name: "main", Protected: false},
			{Name: "release-1.0", Protected: false},
			{Name: "feature/foo", Protected: false},
			{Name: "main-protected", Protected: true}, // just noise
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := 0
	for _, f := range findings {
		if f.Code == "ISSUE-501" {
			hits++
		}
	}
	if hits != 2 {
		t.Fatalf("expected 2 ISSUE-501 findings (main + release-1.0), got %d", hits)
	}
}

// TestIssue505_BranchNonCompliant flags protected branches whose
// settings fail to meet the declared minimum bar.
func TestIssue505_BranchNonCompliant(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"branchMustBeProtected": map[string]any{
			"namePatterns":              []string{"main", "low-push"},
			"allowForcePush":            false,
			"codeOwnerApprovalRequired": true,
			"minPushAccessLevel":        40,
			"minMergeAccessLevel":       40,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Branches: []ir.Branch{
			// main: force push + code owner failures only — push/merge match policy.
			{Name: "main", Protected: true, AllowForcePush: true, MinPushAccessLevel: 40, MinMergeAccessLevel: 40, ProtectionDetailsKnown: true},
			{Name: "compliant", Protected: true, CodeOwnerApprovalRequired: true, MinPushAccessLevel: 40, MinMergeAccessLevel: 40, ProtectionDetailsKnown: true},
			// low-push: push level 30 < 40 (more permissive than required).
			{Name: "low-push", Protected: true, CodeOwnerApprovalRequired: true, MinPushAccessLevel: 30, MinMergeAccessLevel: 40, ProtectionDetailsKnown: true},
			{Name: "unprotected", Protected: false},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := map[string]bool{}
	issue505ByJob := map[string]opaengine.Finding{}
	for _, f := range findings {
		if f.Code == "ISSUE-505" {
			if issue505ByJob[f.Job].Code != "" {
				t.Fatalf("expected at most one ISSUE-505 per branch, got duplicate for %q", f.Job)
			}
			issue505ByJob[f.Job] = f
			hits[f.Job] = true
		}
	}
	if !hits["main"] || !hits["low-push"] {
		t.Fatalf("expected main and low-push flagged, got %v", hits)
	}
	mainF := issue505ByJob["main"]
	if !strings.Contains(mainF.Message, "main") || !strings.Contains(mainF.Message, "non-compliant") {
		t.Fatalf("unexpected ISSUE-505 message for main: %q", mainF.Message)
	}
	raw, _ := mainF.Data["reasons"].([]interface{})
	if len(raw) != 2 {
		t.Fatalf("expected 2 sub-reasons for main, got %v (Data=%v)", raw, mainF.Data)
	}
	if hits["compliant"] || hits["unprotected"] {
		t.Fatalf("unexpected flag on compliant/unprotected: %v", hits)
	}
}

// TestIssue505_AccessLevelStrictestPolicy: GitLab access level 0 = "No one".
// When policy sets min*AccessLevel: 0, any non-zero branch level is too
// permissive and should fire (legacy parity).
func TestIssue505_AccessLevelStrictestPolicy(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"branchMustBeProtected": map[string]any{
			"namePatterns":        []string{"main"},
			"minPushAccessLevel":  0,
			"minMergeAccessLevel": 0,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Branches: []ir.Branch{
			{Name: "main", Protected: true, MinPushAccessLevel: 40, MinMergeAccessLevel: 40, ProtectionDetailsKnown: true},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	reasons := toStringSlice(findings[0].Data["reasons"])
	want := map[string]bool{
		"Merge access level is too low (40, minimum: 0)": false,
		"Push access level is too low (40, minimum: 0)":  false,
	}
	for _, r := range reasons {
		if _, ok := want[r]; ok {
			want[r] = true
		}
	}
	for k, hit := range want {
		if !hit {
			t.Fatalf("missing reason %q in %v", k, reasons)
		}
	}
}

// TestIssue505_AccessLevelSkipsWhenIRZero: legacy guard — when GitLab does
// not report a level (cur == 0), no access-level finding is emitted, even if
// policy requires a positive minimum.
func TestIssue505_AccessLevelSkipsWhenIRZero(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"branchMustBeProtected": map[string]any{
			"namePatterns":        []string{"main"},
			"minPushAccessLevel":  40,
			"minMergeAccessLevel": 40,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Branches: []ir.Branch{
			{Name: "main", Protected: true, ProtectionDetailsKnown: true},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for _, f := range findings {
		if f.Code != "ISSUE-505" {
			continue
		}
		for _, r := range toStringSlice(f.Data["reasons"]) {
			if strings.Contains(r, "access level") {
				t.Fatalf("did not expect access-level reason when IR is 0: %q", r)
			}
		}
	}
}

func toStringSlice(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// TestIssue505_DetailUnknownAbstainsButIssue501StillFires is the
// regression for the GitHub asymmetry: a branch listed as
// `protected: true` whose protection-detail fetch returned 403
// (token lacks Administration:read) MUST NOT trigger ISSUE-505.
// AllowForcePush / CodeOwnerApprovalRequired stay at the Go zero
// values which look identical to "force push allowed AND no
// code-owner approval required" — without the
// ProtectionDetailsKnown gate the rule would fire two false-
// positive reasons on every read-only-token branch. ISSUE-501
// (branch_unprotected) is unaffected because it only consults
// the authoritative `Protected` field from the listing.
func TestIssue505_DetailUnknownAbstainsButIssue501StillFires(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"branchMustBeProtected": map[string]any{
			"namePatterns":              []string{"main", "feature"},
			"defaultMustBeProtected":    true,
			"allowForcePush":            false,
			"codeOwnerApprovalRequired": true,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		DefaultBranch: "main",
		Branches: []ir.Branch{
			// main: protected, but no admin scope so detail is unknown.
			// MUST NOT fire ISSUE-505 (zero defaults are not authoritative).
			{Name: "main", Protected: true, ProtectionDetailsKnown: false},
			// feature: unprotected. MUST fire ISSUE-501 even though
			// detail is unknown for the protected siblings.
			{Name: "feature", Protected: false},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	saw501, saw505 := 0, 0
	for _, f := range findings {
		switch f.Code {
		case "ISSUE-501":
			if f.Job != "feature" {
				t.Fatalf("ISSUE-501 should target the unprotected branch, got %q", f.Job)
			}
			saw501++
		case "ISSUE-505":
			saw505++
		}
	}
	if saw501 != 1 {
		t.Errorf("expected 1 ISSUE-501 (feature), got %d", saw501)
	}
	if saw505 != 0 {
		t.Errorf("expected 0 ISSUE-505 when ProtectionDetailsKnown=false, got %d", saw505)
	}
}

// TestIssue505_NotInPolicyScope ensures ISSUE-501 scope matches ISSUE-505:
// a protected but misconfigured branch that does not match namePatterns and
// is not the default branch when defaultMustBeProtected is false produces no ISSUE-505.
func TestIssue505_NotInPolicyScope(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"branchMustBeProtected": map[string]any{
			"defaultMustBeProtected": false,
			"namePatterns":           []string{"master", "release/*"},
			"allowForcePush":         false,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches: []ir.Branch{
			{Name: "main", Protected: true, AllowForcePush: true, ProtectionDetailsKnown: true},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for _, f := range findings {
		if f.Code == "ISSUE-505" {
			t.Fatalf("expected no ISSUE-505 when main is out of policy scope, got %+v", f)
		}
	}
}

// TestIssue404_IncludesForbiddenVersion flags includes pinned to a
// forbidden version.
func TestIssue404_IncludesForbiddenVersion(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"includesForbiddenVersions": map[string]any{
			"forbiddenVersions":               []string{"dev"},
			"defaultBranchIsForbiddenVersion": true,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Includes: []ir.Include{
			{Kind: "component", Source: "plumber/a", Ref: "dev"},
			{Kind: "component", Source: "plumber/b", Ref: "main"},
			{Kind: "component", Source: "plumber/c", Ref: "1.0.0"},
			{Kind: "hardcoded", Source: "plumber/d", Ref: "main"}, // skipped
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := 0
	for _, f := range findings {
		if f.Code == "ISSUE-404" {
			hits++
		}
	}
	if hits != 2 {
		t.Fatalf("expected 2 ISSUE-404 findings, got %d", hits)
	}
}

// TestIssue204_UnsafeVariableExpansion flags scripts re-parsing
// user-controlled CI variables through a shell.
func TestIssue204_UnsafeVariableExpansion(t *testing.T) {
	cfg := map[string]any{
		"unsafeVariableExpansion": map[string]any{
			"dangerousVariables": []string{"CI_COMMIT_MESSAGE", "CI_COMMIT_BRANCH"},
			"allowedPatterns":    []string{},
		},
	}
	runGitLabPolicyCases(t, "ISSUE-204", []policyCase{
		{"violation_eval.gitlab-ci.yml", []string{"deploy"}},
		{"clean_echo.gitlab-ci.yml", nil},
	}, cfg)
}

// TestIssue401_HardcodedJobs flags jobs whose origin is "hardcoded".
// parseGitLabCI does not know about origins (that data comes from the
// full pipelineOriginData), so this test builds the IR directly.
func TestIssue401_HardcodedJobs(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "build", OriginKind: "hardcoded"},
			{Name: "lint", OriginKind: "component"},
			{Name: "deploy"}, // unknown origin — not flagged
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := []string{}
	for _, f := range findings {
		if f.Code == "ISSUE-401" {
			hits = append(hits, f.Job)
		}
	}
	if len(hits) != 1 || hits[0] != "build" {
		t.Fatalf("expected only [build], got %v", hits)
	}
}

// TestIssue101_ImageAuthorizedSources flags jobs using images from
// untrusted registries. Exercises the Docker-Hub-official-image
// fast-path and the trustedUrls glob matcher. Uses hand-built IRs
// because parseGitLabCI does not extract Image.Registry.
func TestIssue101_ImageAuthorizedSources(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"imageAuthorizedSources": map[string]any{
			"trustedUrls":            []string{"registry.company.com/*"},
			"trustDockerHubOfficial": true,
		},
	}

	cases := []struct {
		name     string
		image    ir.Image
		expected bool
	}{
		{"official_docker_hub", ir.Image{Name: "python", Tag: "3.12", Registry: "docker.io"}, false},
		{"company_registry", ir.Image{Name: "registry.company.com/app", Tag: "1.0"}, false},
		{"untrusted_registry", ir.Image{Name: "attacker/unknown", Tag: "1.0", Registry: "ghcr.io"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitLab,
				Jobs:     []ir.Job{{Name: "build", Image: &tc.image}},
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			found := false
			for _, f := range findings {
				if f.Code == "ISSUE-101" {
					found = true
				}
			}
			if found != tc.expected {
				t.Fatalf("%s: expected violation=%v, got %v (findings=%+v)", tc.name, tc.expected, found, findings)
			}
		})
	}
}

// TestIssue410_SecurityJobsWeakened flags SAST-like jobs with
// allow_failure: true or when: manual.
func TestIssue410_SecurityJobsWeakened(t *testing.T) {
	cfg := map[string]any{
		"securityJobsWeakened": map[string]any{
			"securityJobPatterns":     []string{"sast", "*-sast", "secret_detection"},
			"allowFailureMustBeFalse": true,
			"whenMustNotBeManual":     true,
		},
	}
	runGitLabPolicyCases(t, "ISSUE-410", []policyCase{
		{"violation_allow_failure.gitlab-ci.yml", []string{"sast"}},
		{"violation_manual.gitlab-ci.yml", []string{"sast"}},
		{"clean.gitlab-ci.yml", nil},
	}, cfg)
}

// TestIssue410_MultipleWeakeningsOnOneJob is the regression guard
// for the eval_conflict_error we hit on real-world GitLab pipelines:
// a single security job that is BOTH when:manual at job level AND
// rules-overrode by the project blew up the engine because
// _weakening_reason(job) was a function that demanded a single
// output per input. The fix split each weakening signal into its
// own deny rule. We construct the pipeline IR directly because the
// rules-block branch requires OriginKind = "hardcoded" / "local" /
// "project", which the YAML-only test parser does not populate.
func TestIssue410_MultipleWeakeningsOnOneJob(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"securityJobsWeakened": map[string]any{
			"securityJobPatterns":     []string{"sast"},
			"allowFailureMustBeFalse": true,
			"whenMustNotBeManual":     true,
			"rulesMustNotBeRedefined": true,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{
				Name:         "sast",
				OriginKind:   "hardcoded",
				When:         "manual",
				AllowFailure: true,
				Rules: []map[string]any{
					{"when": "manual"},
					{"when": "never"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v (was the function-conflict regression — pre-fix this errored with eval_conflict_error)", err)
	}
	hits := []string{}
	for _, f := range findings {
		if f.Code == "ISSUE-410" {
			detail, _ := f.Data["detail"].(string)
			hits = append(hits, detail)
		}
	}
	// Expect 4 findings on this one job:
	//   - allow_failure: true masks scan failures
	//   - when: manual prevents the scan from running automatically
	//   - rules overridden with 'when: manual', job will not run
	//   - rules overridden with 'when: never', job will not run
	if len(hits) != 4 {
		t.Fatalf("expected 4 distinct ISSUE-410 reasons on the multi-weakened job, got %d: %v", len(hits), hits)
	}
}

// TestIssue410_GitHubContinueOnError is the regression for the
// silent-on-GitHub bug: previously the GitLab-only `allow_failure`
// field was the sole input to security_jobs_weakened, and GitHub's
// `continue-on-error: true` never reached the rule. The fix has
// two parts and both must hold for the rule to fire: (a) the parser
// maps continue-on-error → AllowFailure, (b) the .plumber.yaml
// shipping defaults include GitHub-realistic security job names
// (codeql, trufflehog, …). This test exercises both ends through
// the production collector.
func TestIssue410_GitHubContinueOnError(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{
			fixture: "violation_continue_on_error.yml",
			// Only the codeql job: trufflehog has no weakening,
			// lint does have continue-on-error but doesn't match
			// any security pattern.
			expectedHits: []string{"violation_continue_on_error/codeql"},
		},
		{
			fixture:      "violation_when_manual_via_if.yml",
			expectedHits: nil,
		},
	}

	// GitHub job names are namespaced as `{workflow}/{job}`, so the
	// patterns must match through the prefix. `*codeql*` (also in
	// .plumber.yaml's GitHub defaults) covers `mywf/codeql`; bare
	// `codeql` would silently miss every namespaced match.
	cfg := map[string]any{
		"securityJobsWeakened": map[string]any{
			"securityJobPatterns":     []string{"*codeql*", "*trufflehog*", "*-sast"},
			"allowFailureMustBeFalse": true,
			"whenMustNotBeManual":     true,
		},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-410", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}

			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			hits := make([]string, 0, len(findings))
			for _, f := range findings {
				if f.Code != "ISSUE-410" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue205_JobVariableOverride flags pipeline jobs that set a
// variable protected by .plumber.yaml.
func TestIssue205_JobVariableOverride(t *testing.T) {
	cfg := map[string]any{
		"jobVariablesOverride": map[string]any{
			"protectedVariables": []string{"PROD_TOKEN"},
		},
	}
	runGitLabPolicyCases(t, "ISSUE-205", []policyCase{
		{"violation_override.gitlab-ci.yml", []string{"deploy"}},
		{"clean.gitlab-ci.yml", nil},
	}, cfg)
}

// TestIssue404_WildcardForbiddenVersion locks in legacy go-wildcard
// parity: a `v*` pattern in forbiddenVersions must match `v1.0.0`
// just like the legacy gitlab.CheckItemMatchToPatterns helper.
// Hardcoded includes are skipped regardless of ref.
func TestIssue404_WildcardForbiddenVersion(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"includesForbiddenVersions": map[string]any{
			"forbiddenVersions": []string{"v*"},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "component", Source: "plumber/a", Ref: "v1.0.0"},  // matches v*
			{Kind: "component", Source: "plumber/b", Ref: "1.0.0"},   // no match
			{Kind: "hardcoded", Source: "plumber/c", Ref: "v9.9.9"},  // skipped (kind)
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := []string{}
	for _, f := range findings {
		if f.Code == "ISSUE-404" {
			hits = append(hits, f.Job)
		}
	}
	if len(hits) != 1 || hits[0] != "plumber/a" {
		t.Fatalf("expected only [plumber/a] flagged via wildcard, got %v", hits)
	}
}

// TestIssue204_SourceAndDotSourcing covers the two patterns that were
// missing from the Rego port: `source script.sh` and `. script.sh`.
// Both re-parse the file as shell, so a tainted variable used in one
// is just as dangerous as `eval`.
func TestIssue204_SourceAndDotSourcing(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"unsafeVariableExpansion": map[string]any{
			"dangerousVariables": []string{"CI_COMMIT_MESSAGE"},
			"allowedPatterns":    []string{},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "src", Scripts: []string{`source ${CI_COMMIT_MESSAGE}`}},
			{Name: "dot", Scripts: []string{`. ${CI_COMMIT_MESSAGE}`}},
			{Name: "comment", Scripts: []string{`# eval $CI_COMMIT_MESSAGE`}}, // skipped
			{Name: "echo", Scripts: []string{`echo $CI_COMMIT_MESSAGE`}},     // safe
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := []string{}
	for _, f := range findings {
		if f.Code == "ISSUE-204" {
			hits = append(hits, f.Job)
		}
	}
	sort.Strings(hits)
	want := []string{"dot", "src"}
	if !stringSlicesEqual(hits, want) {
		t.Fatalf("expected %v, got %v", want, hits)
	}
}

// TestIssue204_VariableWordBoundary locks in the legacy regex
// `\$VAR(?:[^a-zA-Z0-9_]|$)` so `$CI_COMMIT_MESSAGE` is flagged but
// `$CI_COMMIT_MESSAGE_OTHER` is not. The naive `contains` form (the
// previous Rego implementation) over-matched.
func TestIssue204_VariableWordBoundary(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"unsafeVariableExpansion": map[string]any{
			"dangerousVariables": []string{"CI_COMMIT_BRANCH"},
			"allowedPatterns":    []string{},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "exact", Scripts: []string{`eval "$CI_COMMIT_BRANCH"`}},
			{Name: "prefix-only", Scripts: []string{`eval "$CI_COMMIT_BRANCH_OTHER"`}},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := []string{}
	for _, f := range findings {
		if f.Code == "ISSUE-204" {
			hits = append(hits, f.Job)
		}
	}
	if len(hits) != 1 || hits[0] != "exact" {
		t.Fatalf("expected only [exact] flagged, got %v", hits)
	}
}

// TestIssue412_DindLatestAndRegistryPrefix locks in two legacy
// behaviours of isDindImage: `docker:latest` is dind, and a
// registry-prefixed `<host>/docker:dind` is dind. A non-`docker`
// image with `dind` in the tag (e.g. `nginx:dind`) must NOT match.
func TestIssue412_DindLatestAndRegistryPrefix(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "latest", Services: []ir.Image{{Name: "docker", Tag: "latest"}}},
			{Name: "registry-dind", Services: []ir.Image{{Name: "registry.gitlab.com/group/docker", Tag: "dind"}}},
			{Name: "bare-docker", Services: []ir.Image{{Name: "docker"}}},        // no tag → not dind
			{Name: "nginx-dind", Services: []ir.Image{{Name: "nginx", Tag: "dind"}}}, // wrong name → not dind
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := []string{}
	for _, f := range findings {
		if f.Code == "ISSUE-412" {
			hits = append(hits, f.Job)
		}
	}
	sort.Strings(hits)
	want := []string{"latest", "registry-dind"}
	if !stringSlicesEqual(hits, want) {
		t.Fatalf("expected %v, got %v", want, hits)
	}
}

// TestIssue412_OneFindingPerJob mirrors the legacy `break` after the
// first matched dind service. Even with two dind services on the same
// job, the policy must emit a single finding.
func TestIssue412_OneFindingPerJob(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name: "build",
			Services: []ir.Image{
				{Name: "docker", Tag: "27-dind"},
				{Name: "docker", Tag: "dind"},
			},
		}},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	count := 0
	for _, f := range findings {
		if f.Code == "ISSUE-412" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 ISSUE-412 finding, got %d", count)
	}
}

// TestIssue203_TruthyAndCaseInsensitive locks in legacy parity:
//   - Variable name comparison is case-insensitive (`ci_debug_trace`
//     matches `CI_DEBUG_TRACE`).
//   - Truthy values are `true`, `1`, `yes` (case-insensitive,
//     trimmed).
//   - When forbiddenVariables is empty / cfg absent, no findings fire
//     (the legacy GetConf path skips the control).
func TestIssue203_TruthyAndCaseInsensitive(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"debugTrace": map[string]any{
			"forbiddenVariables": []string{"CI_DEBUG_TRACE"},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "lower", Variables: map[string]string{"ci_debug_trace": "true"}},
			{Name: "one", Variables: map[string]string{"CI_DEBUG_TRACE": "1"}},
			{Name: "yes-padded", Variables: map[string]string{"CI_DEBUG_TRACE": " YES "}},
			{Name: "off", Variables: map[string]string{"CI_DEBUG_TRACE": "false"}},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := []string{}
	for _, f := range findings {
		if f.Code == "ISSUE-203" {
			hits = append(hits, f.Job)
		}
	}
	sort.Strings(hits)
	want := []string{"lower", "one", "yes-padded"}
	if !stringSlicesEqual(hits, want) {
		t.Fatalf("expected %v, got %v", want, hits)
	}

	// No cfg → no findings (legacy parity: control is skipped when
	// forbiddenVariables is empty / unset).
	noCfg, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate (no cfg): %v", err)
	}
	for _, f := range noCfg {
		if f.Code == "ISSUE-203" {
			t.Fatalf("expected no ISSUE-203 findings without cfg, got %+v", f)
		}
	}
}

// TestIssue203_GitHubDebugVariables covers the GitHub side of the
// shared `pipelineMustNotEnableDebugTrace` rule. The GitHub collector
// folds workflow / job / step-level `env:` blocks into the per-job
// Variables map, so the same rule that catches `CI_DEBUG_TRACE` on
// GitLab catches `ACTIONS_STEP_DEBUG` / `ACTIONS_RUNNER_DEBUG` on
// GitHub. Verifies positive (truthy), negative (off), and disabled-
// when-no-cfg behaviour for the GitHub provider.
func TestIssue203_GitHubDebugVariables(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"debugTrace": map[string]any{
			"forbiddenVariables": []string{"ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG"},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "build/step-debug", Variables: map[string]string{"ACTIONS_STEP_DEBUG": "true"}},
			{Name: "build/runner-debug", Variables: map[string]string{"actions_runner_debug": "1"}},
			{Name: "build/off", Variables: map[string]string{"ACTIONS_STEP_DEBUG": "false"}},
			{Name: "build/expr", Variables: map[string]string{"ACTIONS_STEP_DEBUG": "${{ vars.enable_debug }}"}},
			{Name: "build/github-env", Scripts: []string{`echo "ACTIONS_RUNNER_DEBUG=true" >> $GITHUB_ENV`}},
			{Name: "build/no-vars"},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := map[string]int{}
	for _, f := range findings {
		if f.Code != "ISSUE-203" {
			continue
		}
		hits[f.Job]++
		if f.Severity != "critical" {
			t.Fatalf("ISSUE-203 must always emit critical (matches codes.go canonical severity), got %q on job %q", f.Severity, f.Job)
		}
	}
	wantJobs := []string{"build/expr", "build/github-env", "build/runner-debug", "build/step-debug"}
	for _, j := range wantJobs {
		if hits[j] == 0 {
			t.Fatalf("expected ISSUE-203 on job %q, got hits=%v", j, hits)
		}
	}
	if hits["build/off"] > 0 || hits["build/no-vars"] > 0 {
		t.Fatalf("unexpected ISSUE-203 on clean jobs, got hits=%v", hits)
	}

	// Without cfg the GitHub side stays silent too (same skip as GitLab).
	noCfg, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate (no cfg): %v", err)
	}
	for _, f := range noCfg {
		if f.Code == "ISSUE-203" {
			t.Fatalf("ISSUE-203 must abstain when cfg is missing; got %+v", f)
		}
	}
}

// TestIssue203_GitHubDebugTrace_CollectorIntegration exercises expression
// and $GITHUB_ENV bypass paths end-to-end through ScanGitHubWorkflows.
func TestIssue203_GitHubDebugTrace_CollectorIntegration(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: debug-hardening
on: push
jobs:
  expr:
    runs-on: ubuntu-latest
    env:
      ACTIONS_STEP_DEBUG: ${{ vars.enable_debug }}
    steps:
      - run: echo hi
  github-env:
    runs-on: ubuntu-latest
    steps:
      - run: echo "ACTIONS_RUNNER_DEBUG=true" >> $GITHUB_ENV
  clean:
    runs-on: ubuntu-latest
    steps:
      - run: echo "BUILD_MODE=release" >> $GITHUB_ENV
`
	if err := os.WriteFile(filepath.Join(wfDir, "debug.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	pipeline, partial, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: err=%v partial=%v", err, partial)
	}
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	cfg := map[string]any{
		"debugTrace": map[string]any{
			"forbiddenVariables": []string{"ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG"},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := map[string]int{}
	for _, f := range findings {
		if f.Code == "ISSUE-203" {
			hits[f.Job]++
		}
	}
	if hits["debug/expr"] == 0 || hits["debug/github-env"] == 0 {
		t.Fatalf("expected findings on debug/expr and debug/github-env, got %v", hits)
	}
	if hits["debug/clean"] > 0 {
		t.Fatalf("unexpected ISSUE-203 on clean job, got %v", hits)
	}
}

// TestIssue101_VarNotationAndUnknownRegistry locks in two legacy
// parity guarantees:
//   - `${VAR}` and `$VAR` notations normalize to the same form before
//     glob matching, so a pattern written either way matches a
//     reference written the other way.
//   - The "unknown" registry literal emitted by the GitLab image
//     collector is treated as no registry, so the trustedUrls glob
//     compares against just `name:tag`.
func TestIssue101_VarNotationAndUnknownRegistry(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	t.Run("var_notation_normalised", func(t *testing.T) {
		cfg := map[string]any{
			"imageAuthorizedSources": map[string]any{
				"trustedUrls": []string{"registry.company.com/${PROJECT}/*"},
			},
		}
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitLab,
			Jobs: []ir.Job{{
				Name: "build",
				// Reference written with $PROJECT (no braces) — must still match.
				Image: &ir.Image{Name: "$PROJECT/app", Tag: "1.0", Registry: "registry.company.com"},
			}},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-101" {
				t.Fatalf("expected match after var-notation normalisation, got finding %+v", f)
			}
		}
	})

	t.Run("unknown_registry_treated_as_no_registry", func(t *testing.T) {
		cfg := map[string]any{
			"imageAuthorizedSources": map[string]any{
				"trustedUrls": []string{"local-image:*"},
			},
		}
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitLab,
			Jobs: []ir.Job{{
				Name:  "build",
				Image: &ir.Image{Name: "local-image", Tag: "1.0", Registry: "unknown"},
			}},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-101" {
				t.Fatalf("expected unknown-registry image to match `local-image:*` glob, got %+v", f)
			}
		}
	})
}

type policyCase struct {
	file            string
	expectedJobHits []string
}

// runGitLabPolicyCases is a shared test harness for policies exercised
// via GitLab .gitlab-ci.yml fixtures under
// testdata/<code>/gitlab/. cfg (optional) is passed as input.config.
func runGitLabPolicyCases(t *testing.T, code string, cases []policyCase, cfg map[string]any) {
	t.Helper()
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	dir := filepath.Join("testdata", code, "gitlab")
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, c.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			pipeline := parseGitLabCI(t, data)
			findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != code {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), c.expectedJobHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s/%s: expected %v, got %v", code, c.file, expected, hits)
			}
		})
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestIssue408_ComponentMissing flags DNF groups whose required
// components are missing from the resolved include list. The Go
// control behaviour is to emit one finding per missing component per
// group — the Rego port does the same.
func TestIssue408_ComponentMissing(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"pipelineMustIncludeComponent": map[string]any{
			"requiredGroups": []any{
				[]any{"components/sast/sast", "components/secret-detection/secret-detection"},
				[]any{"your-org/full-security/full-security"},
			},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "component", Source: "gitlab.example.com/components/sast/sast@1.0.0", Path: "components/sast/sast"},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := map[string]bool{}
	for _, f := range findings {
		if f.Code == "ISSUE-408" {
			hits[f.Job] = true
		}
	}
	if !hits["components/secret-detection/secret-detection"] {
		t.Fatalf("expected secret-detection flagged, got %v", hits)
	}
	if !hits["your-org/full-security/full-security"] {
		t.Fatalf("expected full-security flagged, got %v", hits)
	}
	if hits["components/sast/sast"] {
		t.Fatalf("unexpected flag on present component: %v", hits)
	}
}

// TestIssue409_ComponentOverridden flags required components whose
// jobs were overridden with forbidden CI/CD keys.
func TestIssue409_ComponentOverridden(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"pipelineMustIncludeComponent": map[string]any{
			"requiredGroups": []any{
				[]any{"components/sast/sast"},
			},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{
				Kind:   "component",
				Source: "gitlab.example.com/components/sast/sast@1.0.0",
				Path:   "components/sast/sast",
				OverriddenJobs: []ir.OverriddenJob{
					{Name: "sast", Keys: []string{"script", "rules"}},
				},
			},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := 0
	for _, f := range findings {
		if f.Code == "ISSUE-409" {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("expected 1 ISSUE-409 finding, got %d", hits)
	}
}

// TestIssue405_TemplateMissing flags DNF groups whose required
// templates are missing. Template includes (project/remote/local/
// template) are considered; components and hardcoded origins are
// ignored.
func TestIssue405_TemplateMissing(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"pipelineMustIncludeTemplate": map[string]any{
			"requiredGroups": []any{
				[]any{"templates/go/go", "templates/trivy/trivy"},
			},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "project", Source: "group/templates/templates/go/go.yml", Path: "group/templates/templates/go/go.yml", AltPath: "templates/go/go"},
			// a component should NOT satisfy a template requirement
			{Kind: "component", Source: "gitlab.example.com/components/trivy/trivy@1.0.0", Path: "components/trivy/trivy"},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := map[string]bool{}
	for _, f := range findings {
		if f.Code == "ISSUE-405" {
			hits[f.Job] = true
		}
	}
	if !hits["templates/trivy/trivy"] {
		t.Fatalf("expected trivy template flagged, got %v", hits)
	}
	if hits["templates/go/go"] {
		t.Fatalf("unexpected flag on present template: %v", hits)
	}
}

// TestIssue406_TemplateOverridden flags required templates whose
// jobs were overridden locally.
func TestIssue406_TemplateOverridden(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"pipelineMustIncludeTemplate": map[string]any{
			"requiredGroups": []any{
				[]any{"templates/go/go"},
			},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{
				Kind:    "project",
				Source:  "group/templates/templates/go/go.yml",
				Path:    "group/templates/templates/go/go.yml",
				AltPath: "templates/go/go",
				OverriddenJobs: []ir.OverriddenJob{
					{Name: "build", Keys: []string{"script"}},
				},
			},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := 0
	for _, f := range findings {
		if f.Code == "ISSUE-406" {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("expected 1 ISSUE-406 finding, got %d", hits)
	}
}

// parseGitHubStepsUses extracts `steps[].uses` entries from a workflow
// job. Only `uses` is needed for the currently ported policies; the
// accompanying `with:` block is left empty since no rule reads it yet.
func parseGitHubStepsUses(v any) []ir.Action {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]ir.Action, 0, len(list))
	for _, item := range list {
		step, ok := toStringMap(item)
		if !ok {
			continue
		}
		uses, ok := step["uses"].(string)
		if !ok || uses == "" {
			continue
		}
		out = append(out, ir.Action{Uses: uses})
	}
	return out
}

// TestIssue302_SecretsInherit flags reusable-workflow calls that
// forward every caller secret via `secrets: inherit`. Explicit
// per-secret mappings and regular (non-reusable) jobs stay silent.
func TestIssue302_SecretsInherit(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_inherit.yml", []string{"violation_inherit/call"}},
		{"clean_named.yml", nil},
		{"clean_regular_job.yml", nil},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-302", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != "ISSUE-302" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue301_OverprovisionedSecrets flags jobs that serialise the
// entire `secrets` context via toJson/toJSON and pass it into a
// step's script, env binding, or action `with:` input. The scoped
// pattern `${{ secrets.NAME }}` stays silent.
func TestIssue301_OverprovisionedSecrets(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_env.yml", []string{"violation_env/call"}},
		{"violation_run_script.yml", []string{"violation_run_script/dump"}},
		{"violation_with.yml", []string{"violation_with/deploy"}},
		{"clean_scoped.yml", nil},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-301", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != "ISSUE-301" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue209_GitHubEnvInjection flags `run:` steps that write a
// user-controlled GitHub template expression into $GITHUB_ENV or
// $GITHUB_PATH. The env-binding pattern (bind through env: then
// dereference the shell variable on the redirect line) must stay
// silent — it is the canonical remediation.
func TestIssue209_GitHubEnvInjection(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_event_to_env.yml", []string{"violation_event_to_env/build"}},
		{"violation_head_ref_to_path.yml", []string{"violation_head_ref_to_path/deploy"}},
		{"clean_env_binding.yml", nil},
		{"clean_literal.yml", nil},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-209", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != "ISSUE-209" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue105_ContainerHardcodedCredentials flags
// jobs.<name>.container.credentials.password literals. Template
// expressions (${{ secrets.X }}) pass through; missing credentials
// block is a no-op. Exercises the production ScanGitHubWorkflows
// collector so the test covers the full extraction path.
func TestIssue105_ContainerHardcodedCredentials(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_literal.yml", []string{"violation_literal/build"}},
		{"clean_secret_ref.yml", nil},
		{"clean_no_credentials.yml", nil},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-704", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != "ISSUE-704" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue104_ActionUnpinned flags third-party GitHub Actions
// references that use mutable refs (tags, branches) instead of
// commit SHAs. Exercises the opt-in config, trusted-owners
// exemption, and SHA/local exemptions.
func TestIssue104_ActionUnpinned(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	dir := filepath.Join("testdata", "ISSUE-701", "github")
	cases := []struct {
		fixture   string
		cfg       map[string]any
		wantCount int
	}{
		{"violation_tag_ref.yml", map[string]any{"actionsMustBePinnedByCommitSha": map[string]any{}}, 3},
		{"clean_sha_pinned.yml", map[string]any{"actionsMustBePinnedByCommitSha": map[string]any{}}, 0},
		{"trusted_owner_tag.yml", map[string]any{"actionsMustBePinnedByCommitSha": map[string]any{"trustedOwners": []any{"actions", "github"}}}, 1},
		{"violation_tag_ref.yml", nil, 0},
		// Regression: reusable workflows called via job-level `uses:`
		// were ignored before. The fixture has three jobs; only the
		// third-party @main job should fire, trusted-owner @main and
		// SHA-pinned must stay silent.
		{"violation_reusable_workflow_mutable.yml", map[string]any{"actionsMustBePinnedByCommitSha": map[string]any{"trustedOwners": []any{"actions", "github"}}}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, tc.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			pipeline := parseGitHubActions(t, data)
			findings, err := engine.Evaluate(context.Background(), pipeline, tc.cfg)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := 0
			for _, f := range findings {
				if f.Code == "ISSUE-701" {
					hits++
				}
			}
			if hits != tc.wantCount {
				t.Fatalf("%s cfg=%v: expected %d ISSUE-701, got %d", tc.fixture, tc.cfg, tc.wantCount, hits)
			}
		})
	}
}

// TestIssue210_BotConditions flags workflows that gate behaviour on
// spoofable identity fields (github.actor, sender.login, etc.).
// Branch/ref conditions stay silent.
func TestIssue210_BotConditions(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_actor_dependabot.yml", []string{"violation_actor_dependabot/merge"}},
		{"violation_sender_login.yml", []string{"violation_sender_login/label"}},
		{"clean_branch_condition.yml", nil},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-210", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != "ISSUE-210" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue303_UnredactedSecrets flags workflows that deserialise a
// secret via fromJSON and project one of its fields — the fresh
// string bypasses GitHub's log redaction.
func TestIssue303_UnredactedSecrets(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_env.yml", []string{"violation_env/deploy"}},
		{"violation_run.yml", []string{"violation_run/notify"}},
		{"clean_scoped.yml", nil},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-303", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != "ISSUE-303" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue106_CachePoisoning flags release/publish workflows that
// restore a build cache without a release-ref-scoped key. A plain CI
// workflow or a release workflow with the ref woven into the cache
// key stays silent.
func TestIssue106_CachePoisoning(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_release_unkeyed.yml", []string{"violation_release_unkeyed/publish"}},
		{"violation_publish_action.yml", []string{"violation_publish_action/build"}},
		{"clean_release_scoped_key.yml", nil},
		{"clean_ci_no_publish.yml", nil},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-705", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != "ISSUE-705" {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue601_AnonymousDefinition flags workflow files without a
// top-level `name:`. One finding per file (not per job).
func TestIssue601_AnonymousDefinition(t *testing.T) {
	cases := []struct {
		fixture   string
		wantCount int
	}{
		{"violation_unnamed.yml", 1},
		{"clean_named.yml", 0},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-601", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := 0
			for _, f := range findings {
				if f.Code == "ISSUE-601" {
					hits++
				}
			}
			if hits != tc.wantCount {
				t.Fatalf("%s: expected %d, got %d", tc.fixture, tc.wantCount, hits)
			}
		})
	}
}

// TestIssue602_MissingConcurrency flags workflow files with no
// concurrency block at either workflow or job level.
func TestIssue602_MissingConcurrency(t *testing.T) {
	cases := []struct {
		fixture   string
		wantCount int
	}{
		{"violation_no_concurrency.yml", 1},
		{"clean_workflow_concurrency.yml", 0},
		{"clean_job_concurrency.yml", 0},
	}

	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-418", "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := 0
			for _, f := range findings {
				if f.Code == "ISSUE-418" {
					hits++
				}
			}
			if hits != tc.wantCount {
				t.Fatalf("%s: expected %d, got %d", tc.fixture, tc.wantCount, hits)
			}
		})
	}
}

// TestIssue211_UnsoundCondition flags tautology / contradiction
// patterns inside `if:` expressions.
func TestIssue211_UnsoundCondition(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_tautology.yml", []string{"violation_tautology/deploy"}},
		{"violation_contradiction.yml", []string{"violation_contradiction/build"}},
		{"clean_normal_check.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-211", cases)
}

// TestIssue212_UnsoundContains flags inverted contains() calls.
func TestIssue212_UnsoundContains(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_inverted.yml", []string{"violation_inverted/deploy"}},
		{"clean_correct_order.yml", nil},
		{"clean_fromJSON_set.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-212", cases)
}

// runGitHubFixtureCases drives a list of (fixture, expected jobs)
// cases through ScanGitHubWorkflows + the embedded policies, then
// asserts the set of job names hit by the given issue code matches.
func runGitHubFixtureCases(t *testing.T, code string, cases []struct {
	fixture      string
	expectedHits []string
},
) {
	t.Helper()
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", code, "github", tc.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := make([]string, 0)
			for _, f := range findings {
				if f.Code != code {
					continue
				}
				hits = append(hits, f.Job)
			}
			sort.Strings(hits)
			expected := append([]string(nil), tc.expectedHits...)
			sort.Strings(expected)
			if !stringSlicesEqual(hits, expected) {
				t.Fatalf("%s: expected %v, got %v", tc.fixture, expected, hits)
			}
		})
	}
}

// TestIssue603_WorkflowMisfeature flags upload-artifact of the
// whole checkout directory (leaks .git/).
func TestIssue603_WorkflowMisfeature(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_dot.yml", []string{"violation_dot/build"}},
		{"violation_workspace.yml", []string{"violation_workspace/build"}},
		{"clean_scoped_path.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-419", cases)
}

// TestIssue604_WorkflowObfuscation flags zero-width / bidi Unicode
// inside scripts, env, or action with: inputs.
func TestIssue604_WorkflowObfuscation(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_zero_width.yml", []string{"violation_zero_width/deploy"}},
		{"clean.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-420", cases)
}

// TestIssue605_UseTrustedPublishing flags publish steps that carry a
// static token rather than OIDC.
func TestIssue605_UseTrustedPublishing(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_pypi_static.yml", []string{"violation_pypi_static/publish"}},
		{"clean_oidc.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-421", cases)
}

// TestIssue606_DependabotInsecureExec flags a dependabot.yml that
// re-enables insecure-external-code-execution on an ecosystem.
func TestIssue606_DependabotInsecureExec(t *testing.T) {
	type tc struct {
		fixture   string
		wantCount int
	}
	cases := []tc{
		{"violation_allow.yml", 1},
		{"clean.yml", 0},
	}
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			ghDir := filepath.Join(tmp, ".github")
			if err := os.MkdirAll(filepath.Join(tmp, ".github", "workflows"), 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-901", "github", c.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(ghDir, "dependabot.yml"), data, 0o644); err != nil {
				t.Fatal(err)
			}
			// Minimal workflow to give the scanner something to look at.
			minimal := []byte("name: x\non: [push]\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo x\n")
			if err := os.WriteFile(filepath.Join(tmp, ".github", "workflows", "w.yml"), minimal, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := 0
			for _, f := range findings {
				if f.Code == "ISSUE-901" {
					hits++
				}
			}
			if hits != c.wantCount {
				t.Fatalf("%s: expected %d, got %d", c.fixture, c.wantCount, hits)
			}
		})
	}
}

// TestIssue304_UndocumentedPermissions flags jobs that run with no
// explicit permissions: block at either level.
func TestIssue304_UndocumentedPermissions(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_no_perms.yml", []string{"violation_no_perms/build"}},
		{"clean_workflow_perms.yml", nil},
		{"clean_job_perms.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-801", cases)
}

// TestIssue305_SecretsOutsideEnv flags deploy/publish jobs that use
// secrets without an environment: gate. Plain CI jobs reading a
// secret stay silent.
func TestIssue305_SecretsOutsideEnv(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_release.yml", []string{"violation_release/publish"}},
		{"clean_with_env.yml", nil},
		{"clean_ci_with_secret.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-305", cases)
}

// TestIssue607_DependabotMissingCooldown flags dependabot ecosystems
// with no cooldown window.
func TestIssue607_DependabotMissingCooldown(t *testing.T) {
	type tc struct {
		fixture   string
		wantCount int
	}
	cases := []tc{
		{"violation_no_cooldown.yml", 2},
		{"clean_with_cooldown.yml", 0},
	}
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			if err := os.MkdirAll(filepath.Join(tmp, ".github", "workflows"), 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-902", "github", c.fixture)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(tmp, ".github", "dependabot.yml"), data, 0o644); err != nil {
				t.Fatal(err)
			}
			minimal := []byte("name: x\non: [push]\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo x\n")
			if err := os.WriteFile(filepath.Join(tmp, ".github", "workflows", "w.yml"), minimal, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := collector.ScanGitHubWorkflows("owner/repo", "main", tmp, "", false)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := engine.Evaluate(context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := 0
			for _, f := range findings {
				if f.Code == "ISSUE-902" {
					hits++
				}
			}
			if hits != c.wantCount {
				t.Fatalf("%s: expected %d, got %d", c.fixture, c.wantCount, hits)
			}
		})
	}
}

// TestIssue306_GitHubAppSkipRevoke flags app-token minting with
// skip-token-revoke: true.
func TestIssue306_GitHubAppSkipRevoke(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_skip_revoke.yml", []string{"violation_skip_revoke/release"}},
		{"clean_default.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-306", cases)
}

// TestIssue415_PullRequestTargetWithHeadCheckout flags the tj-actions
// pattern: pull_request_target + checkout of the PR head SHA/ref.
func TestIssue415_PullRequestTargetWithHeadCheckout(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_head_sha.yml", []string{"violation_head_sha/preview"}},
		{"clean_no_ref.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-804", cases)
}

// TestIssue215_TemplateInjectionVars flags scripts that expand
// `vars.*` or `inputs.*` directly into a shell command; env-binding
// pattern stays silent.
func TestIssue215_TemplateInjectionVars(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_vars_docker_login.yml", []string{"violation_vars_docker_login/login"}},
		{"violation_inputs_reusable.yml", []string{"violation_inputs_reusable/run"}},
		{"clean_env_binding.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-215", cases)
}

// TestIssue308_SecretsDynamicIndex flags secrets[expr] with a
// non-literal index; literal quoted forms (secrets.NAME,
// secrets['NAME']) stay silent.
func TestIssue308_SecretsDynamicIndex(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_secrets_env_index.yml", []string{"violation_secrets_env_index/e2e"}},
		{"clean_literal_quoted.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-308", cases)
}

// TestIssue113_RefConfusion drives a hand-built IR because the
// API metadata feeding ref-confusion is not exercised by the unit-
// test harness (PLUMBER_DISABLE_GITHUB_API is set in TestMain).
// The test checks that the policy fires exactly when RefIsAmbiguous
// is true on an Action.
func TestIssue113_RefConfusion(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{
				Name: "build",
				Uses: []ir.Action{
					{Uses: "owner/repo@v1", Metadata: &ir.ActionMetadata{RefKind: "tag", RefExists: true, RefIsAmbiguous: true}},
					{Uses: "actions/checkout@v4", Metadata: &ir.ActionMetadata{RefKind: "tag", RefExists: true}},
				},
			},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := 0
	for _, f := range findings {
		if f.Code == "ISSUE-710" {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("expected 1 ISSUE-710 finding, got %d", hits)
	}
}

// TestIssue114_KnownVulnerableAction stubs the Advisories slice
// directly on the IR so the test does not require GitHub API access.
// Covers the single-advisory positive, the no-advisory negative, the
// multi-advisory case (URL for each ID), and the missing-metadata
// negative (silent abstain, no false positive).
func TestIssue114_KnownVulnerableAction(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	t.Run("single advisory fires once with clickable URL", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name: "build",
				Uses: []ir.Action{
					{Uses: "tj-actions/changed-files@v45", Metadata: &ir.ActionMetadata{RefKind: "tag", RefExists: true, Advisories: []string{"GHSA-mrrh-fwg8-r2c3"}}},
					{Uses: "actions/checkout@v4", Metadata: &ir.ActionMetadata{RefKind: "tag", RefExists: true}},
				},
			}},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, nil)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		hits := 0
		for _, f := range findings {
			if f.Code != "ISSUE-703" {
				continue
			}
			hits++
			wantLink := "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3"
			if !strings.Contains(f.Message, wantLink) {
				t.Fatalf("ISSUE-703 message missing advisory URL\n  got: %s\n  want substring: %s", f.Message, wantLink)
			}
		}
		if hits != 1 {
			t.Fatalf("expected 1 ISSUE-703 finding, got %d", hits)
		}
	})

	t.Run("multi-advisory lists every GHSA URL", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name: "build",
				Uses: []ir.Action{
					{Uses: "vendor/action@v1", Metadata: &ir.ActionMetadata{Advisories: []string{"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"}}},
				},
			}},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, nil)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		hits := 0
		for _, f := range findings {
			if f.Code != "ISSUE-703" {
				continue
			}
			hits++
			for _, want := range []string{
				"https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
				"https://github.com/advisories/GHSA-dddd-eeee-ffff",
			} {
				if !strings.Contains(f.Message, want) {
					t.Errorf("ISSUE-703 message missing %q\n  got: %s", want, f.Message)
				}
			}
		}
		if hits != 1 {
			t.Fatalf("expected 1 ISSUE-703 finding (one per affected action), got %d", hits)
		}
	})

	t.Run("missing metadata stays silent", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name: "build",
				Uses: []ir.Action{
					{Uses: "vendor/action@v1"}, // no Metadata at all
				},
			}},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, nil)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-703" {
				t.Fatalf("ISSUE-703 must abstain when metadata is missing; got %+v", f)
			}
		}
	})
}

// TestIssue108_ActionArchivedRepo locks in the three branches of the
// archived-repo rule: archived=true positive, archived=false negative,
// and missing-metadata silent abstain (no false positive when the
// GitHub API enrichment did not run).
func TestIssue108_ActionArchivedRepo(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	t.Run("archived=true fires with uses field on the finding", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name: "release",
				Uses: []ir.Action{
					{Uses: "archived-org/release-action@v1", Metadata: &ir.ActionMetadata{RepoArchived: true}},
				},
			}},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, nil)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		hits := 0
		for _, f := range findings {
			if f.Code != "ISSUE-702" {
				continue
			}
			hits++
			if uses, ok := f.Data["uses"].(string); !ok || uses != "archived-org/release-action@v1" {
				t.Errorf("ISSUE-702 finding missing/wrong uses field: %v", f.Data["uses"])
			}
		}
		if hits != 1 {
			t.Fatalf("expected 1 ISSUE-702 finding, got %d", hits)
		}
	})

	t.Run("archived=false stays silent", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name: "release",
				Uses: []ir.Action{
					{Uses: "actions/checkout@v4", Metadata: &ir.ActionMetadata{RepoArchived: false}},
				},
			}},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, nil)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-702" {
				t.Fatalf("ISSUE-702 must not fire when archived=false; got %+v", f)
			}
		}
	})

	t.Run("missing metadata stays silent", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name: "release",
				Uses: []ir.Action{
					{Uses: "actions/checkout@v4"}, // no Metadata
				},
			}},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, nil)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-702" {
				t.Fatalf("ISSUE-702 must abstain when metadata is missing; got %+v", f)
			}
		}
	})
}

// TestIssue115_SuperfluousAction flags peter-evans/create-pull-request
// and similar third-party wrappers.
func TestIssue115_SuperfluousAction(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_peter_evans_pr.yml", []string{"violation_peter_evans_pr/open-pr"}},
		{"clean.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-711", cases)
}

// TestIssue213_UnsafeGitHubContextDump flags jobs that serialise
// the entire `github` context via toJson(github).
func TestIssue213_UnsafeGitHubContextDump(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_tojson_github_event.yml", []string{"violation_tojson_github_event/report"}},
		{"clean.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-213", cases)
}

// TestIssue214_UnpinnedPackageInstall flags `pip install pkg` /
// `npm install pkg` without a pinned version or lockfile.
func TestIssue214_UnpinnedPackageInstall(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_pip_unpinned.yml", []string{"violation_pip_unpinned/test"}},
		{"clean.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-214", cases)
}

// TestIssue112_ReleaseWorkflowUnsigned flags release jobs that
// publish artefacts without any signing step.
func TestIssue112_ReleaseWorkflowUnsigned(t *testing.T) {
	cases := []struct {
		fixture      string
		expectedHits []string
	}{
		{"violation_release_unsigned.yml", []string{"violation_release_unsigned/publish"}},
		{"clean_cosign.yml", nil},
	}
	runGitHubFixtureCases(t, "ISSUE-712", cases)
}

// TestIssue609_SASTWorkflowMissing flags repos with workflows but
// no SAST action invocation.
func TestIssue609_SASTWorkflowMissing(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	t.Run("no-sast", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name:       "build",
				OriginFile: "/tmp/.github/workflows/build.yml",
				Uses:       []ir.Action{{Uses: "actions/checkout@v4"}},
			}},
		}
		findings, _ := engine.Evaluate(context.Background(), pipeline, nil)
		hits := 0
		for _, f := range findings {
			if f.Code == "ISSUE-904" {
				hits++
			}
		}
		if hits != 1 {
			t.Fatalf("expected 1 ISSUE-904, got %d", hits)
		}
	})
	t.Run("has-sast", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name:       "analyze",
				OriginFile: "/tmp/.github/workflows/codeql.yml",
				Uses:       []ir.Action{{Uses: "github/codeql-action/analyze@v3"}},
			}},
		}
		findings, _ := engine.Evaluate(context.Background(), pipeline, nil)
		for _, f := range findings {
			if f.Code == "ISSUE-904" {
				t.Fatalf("unexpected ISSUE-904 on SAST-equipped repo: %+v", f)
			}
		}
	})
}

// TestIssue608_DependencyUpdateToolMissing flags repos with
// workflows but neither dependabot nor renovate config.
func TestIssue608_DependencyUpdateToolMissing(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	baseJobs := []ir.Job{{Name: "build", OriginFile: "/tmp/.github/workflows/build.yml"}}
	t.Run("no-tool", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: baseJobs}
		findings, _ := engine.Evaluate(context.Background(), pipeline, nil)
		hits := 0
		for _, f := range findings {
			if f.Code == "ISSUE-903" {
				hits++
			}
		}
		if hits != 1 {
			t.Fatalf("expected 1 ISSUE-903, got %d", hits)
		}
	})
	t.Run("has-dependabot", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider:   ir.ProviderGitHub,
			Jobs:       baseJobs,
			Dependabot: &ir.DependabotConfig{Path: "/tmp/.github/dependabot.yml"},
		}
		findings, _ := engine.Evaluate(context.Background(), pipeline, nil)
		for _, f := range findings {
			if f.Code == "ISSUE-903" {
				t.Fatalf("unexpected ISSUE-903 on dependabot-equipped repo: %+v", f)
			}
		}
	})
	t.Run("has-renovate", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider:           ir.ProviderGitHub,
			Jobs:               baseJobs,
			RenovateConfigPath: "/tmp/renovate.json",
		}
		findings, _ := engine.Evaluate(context.Background(), pipeline, nil)
		for _, f := range findings {
			if f.Code == "ISSUE-903" {
				t.Fatalf("unexpected ISSUE-903 on renovate-equipped repo: %+v", f)
			}
		}
	})
}

// TestIssue610_SecurityPolicyMissing flags repos with workflows
// but no SECURITY.md.
func TestIssue610_SecurityPolicyMissing(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	baseJobs := []ir.Job{{Name: "build", OriginFile: "/tmp/.github/workflows/build.yml"}}
	t.Run("missing", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: baseJobs}
		findings, _ := engine.Evaluate(context.Background(), pipeline, nil)
		hits := 0
		for _, f := range findings {
			if f.Code == "ISSUE-905" {
				hits++
			}
		}
		if hits != 1 {
			t.Fatalf("expected 1 ISSUE-905, got %d", hits)
		}
	})
	t.Run("present", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider:           ir.ProviderGitHub,
			Jobs:               baseJobs,
			SecurityPolicyPath: "/tmp/SECURITY.md",
		}
		findings, _ := engine.Evaluate(context.Background(), pipeline, nil)
		for _, f := range findings {
			if f.Code == "ISSUE-905" {
				t.Fatalf("unexpected ISSUE-905: %+v", f)
			}
		}
	})
}

// TestIssue107_DockerfileUnpinnedBase flags FROM directives
// without a @sha256 digest.
func TestIssue107_DockerfileUnpinnedBase(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Dockerfiles: []ir.Dockerfile{
			{
				Path: "/tmp/Dockerfile",
				Bases: []ir.DockerfileBase{
					{Image: "alpine:3.20", Line: 1, PinnedByDigest: false},
					{Image: "node:20@sha256:abc123", Line: 7, PinnedByDigest: true},
					{Image: "scratch", Line: 12, PinnedByDigest: false},
					{Image: "builder", Line: 15, PinnedByDigest: false},
				},
			},
		},
	}
	findings, _ := engine.Evaluate(context.Background(), pipeline, nil)
	hits := 0
	for _, f := range findings {
		if f.Code == "ISSUE-706" {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("expected 1 ISSUE-706 (alpine:3.20 unpinned), got %d", hits)
	}
}

// TestIssue416_RequiredActionMissing covers the GitHub counterpart
// of ISSUE-408: one finding per missing required action / reusable
// workflow per DNF group. Verifies (a) step-level uses, (b) job-
// level reusable workflow uses, (c) ref-agnostic match,
// (d) slash-guard against accidental prefix collisions, and
// (e) the outer-OR satisfaction short-circuit.
func TestIssue416_RequiredActionMissing(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}

	cfg := map[string]any{
		"workflowMustIncludeRequiredActions": map[string]any{
			"requiredGroups": []any{
				[]any{"myorg/sast-scan", "myorg/policy/.github/workflows/policy.yml"},
				[]any{"myorg/full-security"},
			},
		},
	}

	t.Run("missing entries from every group surface as findings", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{
				{
					Name: "ci/lint",
					Uses: []ir.Action{{Uses: "actions/checkout@v4"}},
				},
			},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		hits := map[string]bool{}
		for _, f := range findings {
			if f.Code == "ISSUE-417" {
				hits[f.Job] = true
			}
		}
		for _, want := range []string{"myorg/sast-scan", "myorg/policy/.github/workflows/policy.yml", "myorg/full-security"} {
			if !hits[want] {
				t.Errorf("expected ISSUE-417 finding for %q; got hits=%v", want, hits)
			}
		}
	})

	t.Run("step-level uses with pinned SHA satisfies ref-agnostic match", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{
				{
					Name: "ci/security",
					Uses: []ir.Action{
						{Uses: "myorg/sast-scan@abc1234567890abc1234567890abc1234567890a"},
					},
				},
				{
					Name:                 "ci/policy-call",
					ReusableWorkflowUses: "myorg/policy/.github/workflows/policy.yml@v1",
				},
			},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-417" {
				t.Errorf("unexpected ISSUE-417 finding when first group fully satisfied: %+v", f)
			}
		}
	})

	t.Run("sub-action under required owner/repo counts as present", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{
				{
					Name: "ci/scan",
					Uses: []ir.Action{
						{Uses: "myorg/sast-scan/composite@v2"},
					},
				},
				{
					Name:                 "ci/policy-call",
					ReusableWorkflowUses: "myorg/policy/.github/workflows/policy.yml@v1",
				},
			},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-417" {
				t.Errorf("sub-action should satisfy the required owner/repo prefix, got finding %+v", f)
			}
		}
	})

	t.Run("slash-guard rejects accidental prefix collisions", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{
				{
					Name: "ci/lookalike",
					Uses: []ir.Action{
						{Uses: "myorg/sast-scan-fork@v1"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		matched := false
		for _, f := range findings {
			if f.Code == "ISSUE-417" && f.Job == "myorg/sast-scan" {
				matched = true
			}
		}
		if !matched {
			t.Errorf("expected myorg/sast-scan to be flagged missing despite a lookalike fork ref, got findings %+v", findings)
		}
	})

	t.Run("any satisfied group short-circuits the whole policy", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{
				{
					Name: "ci/full",
					Uses: []ir.Action{
						{Uses: "myorg/full-security@v3"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-417" {
				t.Errorf("second group satisfied; first-group misses should not fire: %+v", f)
			}
		}
	})

	t.Run("empty config keeps the policy silent", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{
				{Name: "ci/lint", Uses: []ir.Action{{Uses: "actions/checkout@v4"}}},
			},
		}
		findings, err := engine.Evaluate(context.Background(), pipeline, map[string]any{})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-417" {
				t.Errorf("policy must abstain when no requiredGroups is configured, got %+v", f)
			}
		}
	})
}
