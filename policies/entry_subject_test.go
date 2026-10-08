package policies_test

import (
	"context"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestEntryRulesNameTheirSubject pins the subject each entry rule whose
// other fields do not name one emits: the attack-path assembly reads it as
// the path's entry, and the engine keeps it out of every output.
func TestEntryRulesNameTheirSubject(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	github := func(job ir.Job) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{job}}
	}
	cases := []struct {
		name, code, want string
		pipeline         *ir.NormalizedPipeline
		config           map[string]any
	}{
		{"template injection", "ISSUE-207", "github.event.pull_request.title",
			github(ir.Job{Name: "ci/build", Scripts: []string{`echo "${{ github.event.pull_request.title }}"`}}), nil},
		{"template injection, two lines, one finding", "ISSUE-207", "github.event.pull_request.body",
			github(ir.Job{Name: "ci/build", Scripts: []string{"echo \"${{ github.event.pull_request.title }}\"\necho \"${{ github.event.pull_request.body }}\""}}), nil},
		{"env injection, direct", "ISSUE-209", "github.event.issue.title",
			github(ir.Job{Name: "ci/build", Scripts: []string{`echo "T=${{ github.event.issue.title }}" >> $GITHUB_ENV`}}), nil},
		{"env injection, bound", "ISSUE-209", "github.event.issue.body",
			github(ir.Job{Name: "ci/build", Variables: map[string]string{"BODY": "${{ github.event.issue.body }}"}, Scripts: []string{`echo "B=$BODY" >> $GITHUB_ENV`}}), nil},
		{"context dump", "ISSUE-213", "toJson(github)",
			github(ir.Job{Name: "ci/build", Scripts: []string{`echo '${{ toJson(github) }}'`}}), nil},
		{"dangerous trigger", "ISSUE-802", "github.event.workflow_run.head_sha",
			github(ir.Job{Name: "ci/build", Triggers: []string{"workflow_run"},
				Uses: []ir.Action{{Uses: "actions/checkout@v4", With: map[string]any{"ref": "${{ github.event.workflow_run.head_sha }}"}}}}), nil},
		{"forbidden include version", "ISSUE-404", "group/ci@main",
			&ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Includes: []ir.Include{{Kind: "project", Source: "group/ci", Ref: "main"}}},
			map[string]any{"includesForbiddenVersions": map[string]any{"forbiddenVersions": []string{"main"}}}},
		{"cache key nobody saves", "ISSUE-705", "125-cargo-home-linux-x86_64-bench-",
			github(ir.Job{Name: "ci/bench", Triggers: []string{"push"}, Scripts: []string{"cargo publish"},
				Uses: []ir.Action{{Uses: "actions/cache/restore@v4", With: map[string]any{"key": "never_saved", "restore-keys": "125-cargo-home-linux-x86_64-bench-"}}}}),
			cachePoisoningConfig},
		{"cache key another job saves", "ISSUE-705", "deps-linux",
			&ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
				{Name: "ci/bench", Triggers: []string{"push"}, Scripts: []string{"cargo publish"},
					Uses: []ir.Action{{Uses: "actions/cache/restore@v4", With: map[string]any{"key": "deps-linux", "restore-keys": "deps-"}}}},
				{Name: "ci/warm", Triggers: []string{"push"}, Uses: []ir.Action{{Uses: "actions/cache/save@v4", With: map[string]any{"key": "deps-linux"}}}},
			}},
			cachePoisoningConfig},
		// A key scoped to the release ref names no cache a run that is not
		// trusted can write, nor does a restore-keys prefix scoped the same
		// way: the subject is the first prefix that is not.
		{"release-scoped key, unscoped restore-keys prefix", "ISSUE-705", "deps-",
			github(ir.Job{Name: "ci/bench", Triggers: []string{"push"}, Scripts: []string{"cargo publish"},
				Uses: []ir.Action{{Uses: "actions/cache@v4", With: map[string]any{
					"key":          "release-${{ github.ref_name }}-${{ hashFiles('Cargo.lock') }}",
					"restore-keys": "release-${{ github.ref_name }}-\ndeps-",
				}}}}),
			cachePoisoningConfig},
		{"ambiguous include ref", "ISSUE-402", "group/ci@v1",
			&ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Includes: []ir.Include{{Kind: "project", Source: "group/ci", Ref: "v1", RefIsAmbiguous: true}}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := evaluateStrict(engine, context.Background(), tc.pipeline, tc.config)
			if err != nil {
				t.Fatal(err)
			}
			var got []opaengine.Finding
			for _, f := range findings {
				if f.Code == tc.code {
					got = append(got, f)
				}
			}
			if len(got) != 1 {
				t.Fatalf("want one %s finding, got %d: %+v", tc.code, len(got), got)
			}
			if got[0].Subject != tc.want {
				t.Errorf("Subject = %q, want %q", got[0].Subject, tc.want)
			}
			if _, ok := got[0].Data["subject"]; ok {
				t.Errorf("subject left in Data: %+v", got[0].Data)
			}
		})
	}
}

// cachePoisoningConfig is the slice of the shipped cache poisoning
// configuration the ISSUE-705 cases read: the restoring actions and a
// publish command.
var cachePoisoningConfig = map[string]any{"cachePoisoning": map[string]any{
	"cacheActions": []any{
		map[string]any{"action": "actions/cache", "mode": "always"},
		map[string]any{"action": "actions/cache/restore", "mode": "always"},
	},
	"publishScriptPatterns": []any{`(?i)cargo\s+publish`},
}}
