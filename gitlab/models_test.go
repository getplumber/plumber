package gitlab

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"
)

// specSeparatedCI is a multi-document YAML that mirrors what users get when
// they copy the Plumber CI component template into their .gitlab-ci.yml.
// The `spec:` block is in the first document; the actual job is in the second.
const specSeparatedCI = `
spec:
  inputs:
    gitlab_token:
      default: $GITLAB_TOKEN

---

plumber:
  stage: .pre
  script:
    - /plumber analyze
`

func TestIncludeList_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// want is the expected decoded Include. nil means the field must stay nil
		// (absent or explicit null). An empty slice means an explicit empty list.
		want []interface{}
	}{
		{
			name:  "scalar string (GitLab merged config normalization)",
			input: `include: "https://example.com/template.yml"`,
			want:  []interface{}{"https://example.com/template.yml"},
		},
		{
			name:  "scalar local template path",
			input: `include: "/templates/build.yml"`,
			want:  []interface{}{"/templates/build.yml"},
		},
		{
			name: "array with string items",
			input: `include:
  - "https://example.com/a.yml"
  - "https://example.com/b.yml"`,
			want: []interface{}{
				"https://example.com/a.yml",
				"https://example.com/b.yml",
			},
		},
		{
			name: "array with remote: object",
			input: `include:
  - remote: "https://example.com/template.yml"`,
			want: []interface{}{
				map[interface{}]interface{}{"remote": "https://example.com/template.yml"},
			},
		},
		{
			name: "array with local: object",
			input: `include:
  - local: "/templates/build.yml"`,
			want: []interface{}{
				map[interface{}]interface{}{"local": "/templates/build.yml"},
			},
		},
		{
			name: "array with template: object",
			input: `include:
  - template: "Jobs/SAST.gitlab-ci.yml"`,
			want: []interface{}{
				map[interface{}]interface{}{"template": "Jobs/SAST.gitlab-ci.yml"},
			},
		},
		{
			name: "array with project/file object",
			input: `include:
  - project: "dev/templates"
    ref: master
    file: "/receipts/.php-api.yml"`,
			want: []interface{}{
				map[interface{}]interface{}{
					"project": "dev/templates",
					"ref":     "master",
					"file":    "/receipts/.php-api.yml",
				},
			},
		},
		{
			name: "array with project/file where file is a list",
			input: `include:
  - project: "dev/templates"
    file:
      - "/a.yml"
      - "/b.yml"`,
			want: []interface{}{
				map[interface{}]interface{}{
					"project": "dev/templates",
					"file":    []interface{}{"/a.yml", "/b.yml"},
				},
			},
		},
		{
			name: "mixed array (strings + objects)",
			input: `include:
  - "https://example.com/a.yml"
  - remote: "https://example.com/b.yml"
  - template: "Jobs/SAST.gitlab-ci.yml"`,
			want: []interface{}{
				"https://example.com/a.yml",
				map[interface{}]interface{}{"remote": "https://example.com/b.yml"},
				map[interface{}]interface{}{"template": "Jobs/SAST.gitlab-ci.yml"},
			},
		},
		{
			name:  "explicit empty array",
			input: `include: []`,
			want:  []interface{}{},
		},
		{
			name:  "absent include",
			input: `stages: [build]`,
			want:  nil,
		},
		{
			name:  "explicit null include",
			input: `include: null`,
			want:  nil,
		},
		{
			name:  "include key with no value",
			input: `include:`,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var conf GitlabCIConf
			if err := yaml.Unmarshal([]byte(tt.input), &conf); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}

			got := []interface{}(conf.Include)
			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil Include, got %#v", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Include mismatch\n  got:  %#v\n  want: %#v", got, tt.want)
			}
		})
	}
}

// TestIncludeList_UnmarshalYAML_MappingAtTopLevel pins the current lenient
// behavior: a mapping at the include position (not valid per the GitLab spec,
// which requires a scalar or sequence) is accepted by the scalar fallback and
// wrapped as a single-element list. The fallback uses `var single interface{}`
// which can hold any YAML value, so this branch never returns an error in
// practice. If stricter validation is ever added, update this test.
func TestIncludeList_UnmarshalYAML_MappingAtTopLevel(t *testing.T) {
	input := `include:
  remote: "https://example.com/template.yml"
  ref: main`

	var conf GitlabCIConf
	if err := yaml.Unmarshal([]byte(input), &conf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := IncludeList{
		map[interface{}]interface{}{
			"remote": "https://example.com/template.yml",
			"ref":    "main",
		},
	}
	if !reflect.DeepEqual(conf.Include, want) {
		t.Errorf("mapping-at-include mismatch\n  got:  %#v\n  want: %#v", conf.Include, want)
	}
}

// TestIncludeList_DirectUnmarshal asserts the custom type works on its own,
// not only as a field of GitlabCIConf — guards against a future refactor
// that drops the inline tag or renames the field.
func TestIncludeList_DirectUnmarshal(t *testing.T) {
	var il IncludeList
	if err := yaml.Unmarshal([]byte(`"https://example.com/t.yml"`), &il); err != nil {
		t.Fatalf("scalar direct unmarshal failed: %v", err)
	}
	want := IncludeList{"https://example.com/t.yml"}
	if !reflect.DeepEqual(il, want) {
		t.Errorf("direct scalar unmarshal mismatch\n  got:  %#v\n  want: %#v", il, want)
	}
}

// TestUnmarshalMultiDocGitlabCI_SpecSeparated is a regression test for the bug
// where a CI file starting with a `spec:` document followed by `---` and job
// definitions caused hardcoded jobs to be invisible: yaml.Unmarshal only read
// the first document, so GitlabJobs was always empty for such files.
func TestUnmarshalMultiDocGitlabCI_SpecSeparated(t *testing.T) {
	conf, err := unmarshalMultiDocGitlabCI([]byte(specSeparatedCI))
	if err != nil {
		t.Fatalf("unmarshalMultiDocGitlabCI: %v", err)
	}

	// The `spec:` block must be captured.
	if conf.Spec == nil {
		t.Error("expected Spec to be populated from the first document, got nil")
	}

	// The `plumber` job from the second document must be present.
	if conf.GitlabJobs == nil {
		t.Fatal("expected GitlabJobs to be non-nil")
	}
	if _, ok := conf.GitlabJobs["plumber"]; !ok {
		t.Errorf("expected 'plumber' job in GitlabJobs, got keys: %v", jobKeys(conf.GitlabJobs))
	}

	// Verify plain yaml.Unmarshal (single-doc) would miss the job — confirms
	// the regression scenario that this test guards against.
	var singleDoc GitlabCIConf
	_ = yaml.Unmarshal([]byte(specSeparatedCI), &singleDoc)
	if _, ok := singleDoc.GitlabJobs["plumber"]; ok {
		t.Log("note: yaml.Unmarshal now reads multi-doc; this test may need revisiting")
	}
}

func jobKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
