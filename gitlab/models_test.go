package gitlab

import (
	"testing"

	"gopkg.in/yaml.v2"
)

func TestIncludeList_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantNil  bool
	}{
		{
			name:    "scalar string (GitLab merged config normalization)",
			input:   `include: "https://example.com/template.yml"`,
			wantLen: 1,
		},
		{
			name: "array with string items",
			input: `include:
  - "https://example.com/a.yml"
  - "https://example.com/b.yml"`,
			wantLen: 2,
		},
		{
			name: "array with remote: object",
			input: `include:
  - remote: "https://example.com/template.yml"`,
			wantLen: 1,
		},
		{
			name: "array with project/file object",
			input: `include:
  - project: "dev/templates"
    ref: master
    file: "/receipts/.php-api.yml"`,
			wantLen: 1,
		},
		{
			name:   "absent include",
			input:  `stages: [build]`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var conf GitlabCIConf
			if err := yaml.Unmarshal([]byte(tt.input), &conf); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}
			if tt.wantNil {
				if conf.Include != nil {
					t.Errorf("expected nil Include, got %v", conf.Include)
				}
				return
			}
			if len(conf.Include) != tt.wantLen {
				t.Errorf("expected %d include entries, got %d", tt.wantLen, len(conf.Include))
			}
		})
	}
}
