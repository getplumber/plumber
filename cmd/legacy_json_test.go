package cmd

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/finding/identity"
	"github.com/getplumber/plumber/gitlab"
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

// The job key disappears from an issue entry on its own once the rule stops
// emitting one, because projectFinding guards on a non-empty Job. That makes
// the output contract depend on rule payload rather than on the builder's
// argument, so it is pinned here.
func TestProjectFindingOmitsJobForANonJobFinding(t *testing.T) {
	f := opaengine.Finding{
		Code: "ISSUE-408", Fingerprint: "deadbeefcafef00d",
		Data: map[string]any{"componentPath": "components/sast/sast"},
	}

	got := projectFinding(f, "job")

	if _, has := got["job"]; has {
		t.Errorf("job = %v, want the key absent for a finding that is not about a job", got["job"])
	}
	if got["componentPath"] != "components/sast/sast" {
		t.Errorf("componentPath = %v, want the component path", got["componentPath"])
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

// The fingerprint is the per-finding identifier a consumer keys on to follow one
// specific finding across runs, and the JSON report is the format most
// integrations read. It reaches the output through projectFinding, so a
// refactor there could silently drop it while every other format kept working.
func TestProjectFindingEmitsFingerprint(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-701", Job: "ci/build", Fingerprint: "deadbeefcafef00d"}

	got := projectFinding(f, "job")

	if got["fingerprint"] != "deadbeefcafef00d" {
		t.Errorf("fingerprint = %v, want deadbeefcafef00d", got["fingerprint"])
	}
}

// A finding with no fingerprint (a codeless finding is never stamped) must not
// grow an empty key: consumers distinguish "absent" from "empty string".
func TestProjectFindingOmitsEmptyFingerprint(t *testing.T) {
	got := projectFinding(opaengine.Finding{Code: "ISSUE-701", Job: "ci/build"}, "job")

	if _, has := got["fingerprint"]; has {
		t.Errorf("unstamped finding emitted fingerprint = %v, want the key absent", got["fingerprint"])
	}
}

// The fingerprint is a hash, so a consumer that groups findings into long-lived
// issues cannot see WHICH fields it was built from. projectFinding strips
// message, file and line from the issue entry, so those inputs are not
// recoverable from the report either. The identity block carries the selected
// field set itself, which is what makes the grouping derivable downstream.
func TestProjectFindingEmitsIdentityFieldSet(t *testing.T) {
	f := opaengine.Finding{
		Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "build",
		Message: "prose", Line: 12, Fingerprint: "deadbeefcafef00d",
		Data: map[string]any{"uses": "owner/act@v1", "step": "Check out"},
	}

	got := projectFinding(f, "job")

	block, ok := got["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity = %v, want a block carrying the selected fields", got["identity"])
	}
	if block["version"] != identity.RecipeVersion {
		t.Errorf("identity.version = %v, want %d", block["version"], identity.RecipeVersion)
	}
	want := []identity.Field{
		{Key: "code", Value: "ISSUE-701"},
		{Key: "file", Value: ".github/workflows/ci.yml"},
		{Key: "job", Value: "build"},
		{Key: "uses", Value: "owner/act@v1"},
		{Key: "step", Value: "Check out"},
	}
	if fields, ok := block["fields"].([]identity.Field); !ok || !slices.Equal(fields, want) {
		t.Errorf("identity.fields = %v, want %v", block["fields"], want)
	}
}

// The identity block exists to be read out of Plumber's serialized output by a
// consumer in another module, and docs/FINGERPRINT.md publishes its wire shape
// as a contract. Every other assertion in this file inspects Go values, which
// cannot see the encoding: dropping the json tags on identity.Field would turn
// `key`/`value` into `Key`/`Value`, every consumer reading fields[].key would
// get nothing, and the suite would stay green. So this one goes through JSON.
func TestProjectFindingIdentityMarshalsToTheDocumentedShape(t *testing.T) {
	f := opaengine.Finding{
		Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "build",
		Message: "prose", Fingerprint: "deadbeefcafef00d",
		Data: map[string]any{"uses": "owner/act@v1", "step": "Check out"},
	}

	raw, err := json.Marshal(projectFinding(f, "job"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	block, ok := got["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity = %v, want an object; raw: %s", got["identity"], raw)
	}
	// Numbers come back as float64 through a JSON round trip, which is what a
	// consumer parsing the report actually sees.
	if block["version"] != float64(identity.RecipeVersion) {
		t.Errorf("identity.version = %v, want %d", block["version"], identity.RecipeVersion)
	}
	if block["subjectFromMessage"] != false {
		t.Errorf("identity.subjectFromMessage = %v, want false", block["subjectFromMessage"])
	}
	want := []any{
		map[string]any{"key": "code", "value": "ISSUE-701"},
		map[string]any{"key": "file", "value": ".github/workflows/ci.yml"},
		map[string]any{"key": "job", "value": "build"},
		map[string]any{"key": "uses", "value": "owner/act@v1"},
		map[string]any{"key": "step", "value": "Check out"},
	}
	if !reflect.DeepEqual(block["fields"], want) {
		t.Errorf("identity.fields = %#v,\nwant %#v", block["fields"], want)
	}
}

// The message fallback still has to survive the encoding on the one path that
// can still reach it: an undeclared code, the defensive backstop. Its
// subjectFromMessage flag is what tells a consumer the finding is re-keyed by a
// copy-edit. No registered code takes this path now (every one declares a
// structured or canonical identity); it is exercised here so the serialization
// cannot silently break.
func TestProjectFindingIdentityMarshalsTheBackstopMessageFallback(t *testing.T) {
	f := opaengine.Finding{
		Code: "ISSUE-UNDECLARED", Job: "build", Message: "job \"build\" hit an undeclared code",
		Fingerprint: "deadbeefcafef00d",
	}

	raw, err := json.Marshal(projectFinding(f, "job"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	block := got["identity"].(map[string]any)
	if block["subjectFromMessage"] != true {
		t.Errorf("identity.subjectFromMessage = %v, want true", block["subjectFromMessage"])
	}
	fields, ok := block["fields"].([]any)
	if !ok {
		t.Fatalf("identity.fields = %v, want an array", block["fields"])
	}
	last := fields[len(fields)-1]
	if !reflect.DeepEqual(last, map[string]any{"key": "message", "value": f.Message}) {
		t.Errorf("subject pair = %#v, want the message fallback", last)
	}
}

// The file is stripped from the issue entry itself but is part of the identity,
// so a consumer must not have to recover it from the url. This is the field
// whose absence made the report unusable for grouping.
func TestProjectFindingIdentityCarriesTheStrippedFile(t *testing.T) {
	f := opaengine.Finding{
		Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "build",
		Fingerprint: "deadbeefcafef00d", Data: map[string]any{"uses": "owner/act@v1"},
	}

	got := projectFinding(f, "job")

	if _, has := got["file"]; has {
		t.Fatalf("the legacy issue shape grew a file key: %v", got["file"])
	}
	block := got["identity"].(map[string]any)
	for _, p := range block["fields"].([]identity.Field) {
		if p.Key == "file" && p.Value == ".github/workflows/ci.yml" {
			return
		}
	}
	t.Errorf("identity.fields does not carry the file: %v", block["fields"])
}

// A former message-keyed control now reports a structured identity: ISSUE-803
// identifies on {file, job}, so subjectFromMessage is false and the prose is no
// longer part of the identity block. Regression guard for the
// message-elimination pass.
func TestProjectFindingIdentityReportsStructuredSubjectForFormerMessageCode(t *testing.T) {
	f := opaengine.Finding{
		Code: "ISSUE-803", File: ".github/workflows/ci.yml", Job: "build",
		Message:     "job \"build\" runs with overly broad permissions",
		Fingerprint: "deadbeefcafef00d",
	}

	got := projectFinding(f, "job")

	block := got["identity"].(map[string]any)
	if block["subjectFromMessage"] == true {
		t.Errorf("subjectFromMessage = true, want false for a now-structured code")
	}
	for _, p := range block["fields"].([]identity.Field) {
		if p.Key == "message" {
			t.Errorf("message entered the identity of a now-structured code: %+v", block["fields"])
		}
	}
}

// A codeless finding has no identity, so the key must be absent rather than an
// empty block: consumers distinguish "absent" from "empty".
func TestProjectFindingOmitsIdentityForCodelessFinding(t *testing.T) {
	got := projectFinding(opaengine.Finding{Job: "build", Message: "x"}, "job")

	if _, has := got["identity"]; has {
		t.Errorf("codeless finding emitted identity = %v, want the key absent", got["identity"])
	}
}

// Data must not be able to overwrite the derived block: a rule payload carrying
// an "identity" key would otherwise forge the grouping key.
func TestProjectFindingDataCannotOverrideIdentity(t *testing.T) {
	f := opaengine.Finding{
		Code: "ISSUE-701", Job: "build", Fingerprint: "realfingerprint0",
		Data: map[string]any{"identity": "forged", "uses": "owner/act@v1"},
	}

	got := projectFinding(f, "job")

	if _, ok := got["identity"].(map[string]any); !ok {
		t.Errorf("identity = %v, want the derived block to win over Data", got["identity"])
	}
}

// Data must not be able to overwrite the stamped value: a rule payload that
// happened to carry a "fingerprint" key would otherwise forge the identifier.
func TestProjectFindingDataCannotOverrideFingerprint(t *testing.T) {
	f := opaengine.Finding{
		Code: "ISSUE-701", Job: "ci/build", Fingerprint: "realfingerprint0",
		Data: map[string]any{"fingerprint": "forged"},
	}

	got := projectFinding(f, "job")

	if got["fingerprint"] != "realfingerprint0" {
		t.Errorf("fingerprint = %v, want the stamped value to win over Data", got["fingerprint"])
	}
}

// The v0.2.x branch block exposes the full protection settings only on branches
// that fired a non-compliance finding, and it finds them by matching the
// finding to the branch. That match must read branchName from the payload: the
// job field is empty for a branch finding, because a branch is not a job.
func TestBranchProtectionBlockMatchesNonCompliantBranchByPayload(t *testing.T) {
	f := opaengine.Finding{
		Code: string(control.CodeBranchNonCompliant),
		Data: map[string]any{"branchName": "main", "allowForcePush": true},
	}

	got := nonCompliantBranchNames([]opaengine.Finding{f})

	if !got["main"] {
		t.Errorf("nonCompliantBranchNames = %v, want main flagged", got)
	}
}

// A finding without a branchName cannot name a branch, so it must not produce a
// phantom "" entry that would match no branch and hide the real ones.
func TestNonCompliantBranchNamesIgnoresAPayloadWithoutABranch(t *testing.T) {
	f := opaengine.Finding{Code: string(control.CodeBranchNonCompliant)}

	if got := nonCompliantBranchNames([]opaengine.Finding{f}); len(got) != 0 {
		t.Errorf("nonCompliantBranchNames = %v, want empty", got)
	}
}

// ISSUE-404 no longer emits a job field: an include is not a job, and
// includePath is what the identity recipe now selects for this rule
// (finding/identity). The enrichment step must follow that move and read
// the include source from includePath, not from the retired job field, or
// it silently drops every origin-derived key (version, latestVersion,
// gitlabIncludeLocation, gitlabIncludeType, gitlabIncludeProject, nested,
// originHash, componentName, plumberOriginPath, plumberTemplateName) from
// the JSON report.
func TestEnrichForbiddenVersion404IssueMaps_ReadsIncludePath(t *testing.T) {
	t.Parallel()
	result := &control.AnalysisResult{
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			Origins: []gitlab.GitlabPipelineOriginDataFull{
				{
					GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
						OriginType: "project",
						GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
							Location: "templates/deploy.yml@group/project",
							Type:     "file",
							Project:  "group/project",
						},
						OriginHash: 42,
					},
					GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
						Version: "main",
						Nested:  false,
					},
				},
			},
		},
	}
	// Post-change shape: the rule emits includePath and no job key at all.
	issues := []map[string]any{{
		"code":        string(control.CodeIncludeForbiddenVersion),
		"docUrl":      "x",
		"includePath": "templates/deploy.yml@group/project",
	}}

	enrichForbiddenVersion404IssueMaps(issues, result)

	iss := issues[0]
	if iss["version"] != "main" {
		t.Errorf("version: got %v, want %q", iss["version"], "main")
	}
	if iss["gitlabIncludeLocation"] != "templates/deploy.yml@group/project" {
		t.Errorf("gitlabIncludeLocation: got %v", iss["gitlabIncludeLocation"])
	}
	if iss["gitlabIncludeType"] != "file" {
		t.Errorf("gitlabIncludeType: got %v", iss["gitlabIncludeType"])
	}
	if iss["gitlabIncludeProject"] != "group/project" {
		t.Errorf("gitlabIncludeProject: got %v", iss["gitlabIncludeProject"])
	}
	if iss["originHash"] != uint64(42) {
		t.Errorf("originHash: got %v, want 42", iss["originHash"])
	}
}
