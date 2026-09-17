package gitlab

import (
	"bytes"
	"io"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// componentJobRules returns the `if:` expression of every rule on the component's `plumber` job,
// in order, from the second YAML document of templates/plumber.yml (the first document is the
// component `spec`).
func componentJobRules(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../templates/plumber.yml")
	if err != nil {
		t.Fatalf("read the component template: %v", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var spec map[string]any
	if err := dec.Decode(&spec); err != nil {
		t.Fatalf("decode the spec document: %v", err)
	}
	if _, ok := spec["spec"]; !ok {
		t.Fatalf("the first document must be the component spec, got keys %v", keysOf(spec))
	}
	var config map[string]any
	if err := dec.Decode(&config); err != nil {
		t.Fatalf("decode the job document: %v", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("the template must hold exactly two documents, third decode err = %v", err)
	}
	job, ok := config["plumber"].(map[string]any)
	if !ok {
		t.Fatalf("the job document must define the `plumber` job, got keys %v", keysOf(config))
	}
	rules, ok := job["rules"].([]any)
	if !ok {
		t.Fatalf("the plumber job must carry a rules list, got %T", job["rules"])
	}
	var ifs []string
	for i, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("rule %d is not a map: %T", i, r)
		}
		expr, ok := m["if"].(string)
		if !ok {
			t.Fatalf("rule %d has no `if` string: %v", i, m)
		}
		if len(m) != 1 {
			t.Fatalf("rule %d must be a bare `if` (no when/allow_failure override), got %v", i, m)
		}
		ifs = append(ifs, expr)
	}
	return ifs
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Issue #476: the component job used to run only on MR pipelines, the default branch and tags,
// so a project adopting Plumber through an onboarding MR (branch `plumber/onboard-<id>`) never saw
// the job run on that branch's pipeline. The job now also runs on a branch pipeline whose commit
// has an open merge request, and on any `plumber/` branch. Order and exact expressions are pinned:
// the release pipeline never rewrites this block, so a drift here is a human edit.
func TestComponentTemplate_PlumberJobRules_Issue476(t *testing.T) {
	want := []string{
		`$CI_PIPELINE_SOURCE == "merge_request_event"`,
		`$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`,
		`$CI_COMMIT_TAG`,
		`$CI_OPEN_MERGE_REQUESTS`,
		`$CI_COMMIT_BRANCH =~ /^plumber\//`,
	}
	got := componentJobRules(t)
	if len(got) != len(want) {
		t.Fatalf("want %d rules, got %d: %q", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d: want %q, got %q", i, want[i], got[i])
		}
	}
}
