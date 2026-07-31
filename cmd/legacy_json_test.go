package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
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

// controlName lives once on the parent *Result block, not on every
// individual issue -- every issue in a block is guaranteed to share
// that block's controlName (FindingsByControl buckets strictly by it),
// so per-issue controlName would be pure redundancy. See
// TestWithControlMeta for the block-level stamping.
func TestProjectFindingOmitsControlName(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-701"}
	out := projectFinding(f, "job")
	if got, ok := out["controlName"]; ok {
		t.Errorf("controlName = %v, want absent from individual issues", got)
	}
}

func TestWithControlMeta(t *testing.T) {
	entry := control.ControlEntry{ControlName: "actionsMustBePinnedByCommitSha"}
	healthy := &control.AnalysisResult{CiValid: true}

	t.Run("stamps controlName and status onto a map[string]any block", func(t *testing.T) {
		block := any(map[string]any{"issues": []any{}, "skipped": false})
		got := _withControlMeta(block, entry, healthy, 0)
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("result is not a map[string]any: %T", got)
		}
		if m["controlName"] != "actionsMustBePinnedByCommitSha" {
			t.Errorf("controlName = %v, want actionsMustBePinnedByCommitSha", m["controlName"])
		}
		if m["status"] != control.StatusPassed {
			t.Errorf("status = %v, want %q", m["status"], control.StatusPassed)
		}
		// The rest of the block is untouched.
		if _, ok := m["skipped"]; !ok {
			t.Errorf("existing block keys were lost")
		}
	})

	t.Run("findings flip status to failed", func(t *testing.T) {
		block := any(map[string]any{})
		m := _withControlMeta(block, entry, healthy, 2).(map[string]any)
		if m["status"] != control.StatusFailed {
			t.Errorf("status = %v, want %q", m["status"], control.StatusFailed)
		}
	})

	t.Run("skipped entry yields status skipped", func(t *testing.T) {
		block := any(map[string]any{})
		skipped := control.ControlEntry{ControlName: "x", Skipped: true}
		m := _withControlMeta(block, skipped, healthy, 0).(map[string]any)
		if m["status"] != control.StatusSkipped {
			t.Errorf("status = %v, want %q", m["status"], control.StatusSkipped)
		}
	})

	t.Run("missing CI config yields status error, not a silent pass", func(t *testing.T) {
		block := any(map[string]any{})
		m := _withControlMeta(block, entry, &control.AnalysisResult{CiMissing: true}, 0).(map[string]any)
		if m["status"] != control.StatusError {
			t.Errorf("status = %v, want %q", m["status"], control.StatusError)
		}
	})

	t.Run("non-map block is returned unchanged, not panicked on", func(t *testing.T) {
		block := any("not a map")
		got := _withControlMeta(block, entry, healthy, 0)
		if got != block {
			t.Errorf("got %v, want the original value unchanged", got)
		}
	})
}
