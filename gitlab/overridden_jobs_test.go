package gitlab

import (
	"reflect"
	"sort"
	"testing"
)

// fullWithJobs builds a GitlabPipelineOriginDataFull carrying the given
// jobs in its embedded project-specific section.
func fullWithJobs(jobs ...GitlabPipelineJobData) *GitlabPipelineOriginDataFull {
	return &GitlabPipelineOriginDataFull{
		GitlabPipelineOriginDataProjectSpecific: GitlabPipelineOriginDataProjectSpecific{
			Jobs: jobs,
		},
	}
}

func TestCollectOverriddenJobs_NilGuards(t *testing.T) {
	data := &GitlabPipelineOriginData{}
	if got := CollectOverriddenJobs(nil, data); got != nil {
		t.Errorf("nil origin: got %+v, want nil", got)
	}
	if got := CollectOverriddenJobs(fullWithJobs(), nil); got != nil {
		t.Errorf("nil data: got %+v, want nil", got)
	}
}

func TestCollectOverriddenJobs_SkipsNonOverridden(t *testing.T) {
	o := fullWithJobs(GitlabPipelineJobData{Name: "build", IsOverridden: false})
	data := &GitlabPipelineOriginData{
		JobHardcodedContent: map[string]interface{}{
			// Even though forbidden keys exist, the job is not overridden.
			"build": map[interface{}]interface{}{"script": "make"},
		},
	}
	if got := CollectOverriddenJobs(o, data); got != nil {
		t.Errorf("non-overridden job: got %+v, want nil", got)
	}
}

func TestCollectOverriddenJobs_OverriddenWithForbiddenKeys(t *testing.T) {
	o := fullWithJobs(GitlabPipelineJobData{Name: "deploy", IsOverridden: true})
	data := &GitlabPipelineOriginData{
		JobHardcodedContent: map[string]interface{}{
			"deploy": map[interface{}]interface{}{
				"script":    "deploy.sh",
				"image":     "alpine:3",
				"unrelated": "value", // not a forbidden key
			},
		},
	}
	got := CollectOverriddenJobs(o, data)
	if len(got) != 1 || got[0].Name != "deploy" {
		t.Fatalf("got %+v, want one entry named deploy", got)
	}
	keys := append([]string(nil), got[0].Keys...)
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"image", "script"}) {
		t.Errorf("keys = %v, want [image script]", keys)
	}
}

func TestCollectOverriddenJobs_OverriddenButNoForbiddenKey(t *testing.T) {
	o := fullWithJobs(GitlabPipelineJobData{Name: "lint", IsOverridden: true})
	data := &GitlabPipelineOriginData{
		JobHardcodedContent: map[string]interface{}{
			"lint": map[interface{}]interface{}{"variables": "X"},
		},
	}
	// "variables" is not in the forbidden-override list, and no content
	// would also yield nothing -> the job is dropped.
	if got := CollectOverriddenJobs(o, data); got != nil {
		t.Errorf("no forbidden key: got %+v, want nil", got)
	}
}

func TestCollectOverriddenJobs_MissingHardcodedContent(t *testing.T) {
	o := fullWithJobs(GitlabPipelineJobData{Name: "ghost", IsOverridden: true})
	data := &GitlabPipelineOriginData{JobHardcodedContent: nil}
	if got := CollectOverriddenJobs(o, data); got != nil {
		t.Errorf("missing content: got %+v, want nil", got)
	}
}

func TestCollectOverriddenJobs_DedupsByJobName(t *testing.T) {
	// The same overridden job appears twice (e.g. surfaced by two
	// origins); it must be emitted only once.
	o := fullWithJobs(
		GitlabPipelineJobData{Name: "test", IsOverridden: true},
		GitlabPipelineJobData{Name: "test", IsOverridden: true},
	)
	data := &GitlabPipelineOriginData{
		JobHardcodedContent: map[string]interface{}{
			"test": map[interface{}]interface{}{"script": "go test"},
		},
	}
	got := CollectOverriddenJobs(o, data)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (deduped): %+v", len(got), got)
	}
}

func TestForbiddenOverrides_DedupsRepeatedKey(t *testing.T) {
	// A forbidden key appearing in nested structures must be reported once.
	job := map[interface{}]interface{}{
		"script": []interface{}{"a", "b"},
		"rules": []interface{}{
			map[interface{}]interface{}{"when": "manual"},
			map[interface{}]interface{}{"when": "always"},
		},
	}
	keys, block := forbiddenOverrides(job)
	sort.Strings(keys)
	want := []string{"rules", "script", "when"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
	// The block comes back whole and JSON-ready: the nested "when" values
	// travel inside "rules", where the fingerprint picks them up.
	wantBlock := map[string]any{
		"script": []interface{}{"a", "b"},
		"rules": []interface{}{
			map[string]interface{}{"when": "manual"},
			map[string]interface{}{"when": "always"},
		},
	}
	if !reflect.DeepEqual(block, wantBlock) {
		t.Errorf("block = %#v, want the whole local job map %#v", block, wantBlock)
	}
}

// Row 85 (platform QUESTIONS, 2026-09-16): a forbidden keyword that only ever
// appears NESTED under a key the regex does not match still gets the whole local
// block carried, so the include's fingerprint moves when its value changes.
func TestForbiddenOverrides_NestedOnlyKeyword_Row85(t *testing.T) {
	job := map[interface{}]interface{}{
		"variables": map[interface{}]interface{}{"image": "alpine:3"},
	}
	keys, block := forbiddenOverrides(job)
	if !reflect.DeepEqual(keys, []string{"image"}) {
		t.Errorf("keys = %v, want [image]", keys)
	}
	wantBlock := map[string]any{"variables": map[string]interface{}{"image": "alpine:3"}}
	if !reflect.DeepEqual(block, wantBlock) {
		t.Fatalf("block = %#v, want the whole local job map %#v", block, wantBlock)
	}
}

func TestForbiddenOverrides_NilJob(t *testing.T) {
	keys, values := forbiddenOverrides(nil)
	if keys != nil {
		t.Errorf("nil job: keys = %+v, want nil", keys)
	}
	if values != nil {
		t.Errorf("nil job: values = %+v, want nil", values)
	}
}

// Row 85 (platform QUESTIONS, 2026-09-16): the collector carries the overridden
// keys' values, and the include's fingerprint names that content, so a dismissal
// keyed on it lapses as soon as the overriding job changes.
func TestBuildIncludes_OverrideFingerprint_Row85(t *testing.T) {
	originData := func(script string) *GitlabPipelineOriginData {
		full := fullWithJobs(GitlabPipelineJobData{Name: "deploy", IsOverridden: true})
		full.OriginType = "component"
		full.GitlabIncludeOrigin.Location = "templates/deploy.yml"
		return &GitlabPipelineOriginData{
			Origins: []GitlabPipelineOriginDataFull{*full},
			JobHardcodedContent: map[string]interface{}{
				"deploy": map[interface{}]interface{}{
					"script": []interface{}{script},
					"image":  "alpine:3",
				},
			},
		}
	}

	includes := buildIncludes(originData("deploy.sh"), ".gitlab-ci.yml")
	if len(includes) != 1 {
		t.Fatalf("got %d includes, want 1: %+v", len(includes), includes)
	}
	jobs := includes[0].OverriddenJobs
	if len(jobs) != 1 || jobs[0].Name != "deploy" {
		t.Fatalf("got %+v, want one overridden job named deploy", jobs)
	}
	if !reflect.DeepEqual(jobs[0].Values["script"], []interface{}{"deploy.sh"}) {
		t.Errorf("Values[script] = %#v, want [deploy.sh]", jobs[0].Values["script"])
	}
	if jobs[0].Values["image"] != "alpine:3" {
		t.Errorf("Values[image] = %#v, want alpine:3", jobs[0].Values["image"])
	}
	if includes[0].OverrideFingerprint == "" {
		t.Fatal("an overridden job must give the include a fingerprint")
	}

	changed := buildIncludes(originData("deploy.sh --prod"), ".gitlab-ci.yml")
	if len(changed) != 1 {
		t.Fatalf("got %d includes, want 1: %+v", len(changed), changed)
	}
	if changed[0].OverrideFingerprint == includes[0].OverrideFingerprint {
		t.Error("a changed script must move the include's override fingerprint")
	}
}

// Row 85 (platform QUESTIONS, 2026-09-16): the include's fingerprint follows the
// whole overriding block, so it moves on a value the override regex never matches
// at the job's top level (here "image", nested under "variables").
func TestBuildIncludes_OverrideFingerprint_NestedOnly_Row85(t *testing.T) {
	originData := func(image string) *GitlabPipelineOriginData {
		full := fullWithJobs(GitlabPipelineJobData{Name: "build", IsOverridden: true})
		full.OriginType = "component"
		full.GitlabIncludeOrigin.Location = "templates/build.yml"
		return &GitlabPipelineOriginData{
			Origins: []GitlabPipelineOriginDataFull{*full},
			JobHardcodedContent: map[string]interface{}{
				"build": map[interface{}]interface{}{
					"variables": map[interface{}]interface{}{"image": image},
				},
			},
		}
	}

	three := buildIncludes(originData("alpine:3"), ".gitlab-ci.yml")
	four := buildIncludes(originData("alpine:4"), ".gitlab-ci.yml")
	if len(three) != 1 || len(four) != 1 {
		t.Fatalf("got %d and %d includes, want 1 each", len(three), len(four))
	}
	if three[0].OverrideFingerprint == "" {
		t.Fatal("a nested-only overridden keyword must still give the include a fingerprint")
	}
	if three[0].OverrideFingerprint == four[0].OverrideFingerprint {
		t.Error("a change to a nested-only value must move the include's override fingerprint")
	}
}
