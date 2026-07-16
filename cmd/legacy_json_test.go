package cmd

import (
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// The machine-readable key for "which job is this finding in" is `job`
// — the same key every Rego rule emits and the engine parses
// (Finding.Job). The v0.2.x `jobName` alias is gone: blocks that
// historically exposed it emit the canonical key instead, so JSON
// consumers read a single key across every *Result block. Blocks that
// pass "" (branch/include findings that deliberately drop the field)
// or "file" (gitleaks hits, where Finding.Job carries a file path)
// have no job semantics and must NOT grow a `job` key.
func TestProjectFindingJobKey(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-701", Job: "ci/build"}

	cases := []struct {
		name       string
		jobKey     string
		wantKeys   map[string]any
		absentKeys []string
	}{
		{
			name:       "job blocks emit the canonical key, never the retired alias",
			jobKey:     "job",
			wantKeys:   map[string]any{"job": "ci/build"},
			absentKeys: []string{"jobName"},
		},
		{
			name:       "empty-key blocks keep dropping the job field",
			jobKey:     "",
			absentKeys: []string{"job", "jobName"},
		},
		{
			name:       "file blocks carry a file path, not a job",
			jobKey:     "file",
			wantKeys:   map[string]any{"file": "ci/build"},
			absentKeys: []string{"job", "jobName"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := projectFinding(f, tc.jobKey)
			for k, want := range tc.wantKeys {
				if got := out[k]; got != want {
					t.Errorf("out[%q] = %v, want %v", k, got, want)
				}
			}
			for _, k := range tc.absentKeys {
				if v, ok := out[k]; ok {
					t.Errorf("out[%q] = %v, want absent", k, v)
				}
			}
		})
	}
}
