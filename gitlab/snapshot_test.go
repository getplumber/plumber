package gitlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/platform"
	glab "gitlab.com/gitlab-org/api/client-go"
)

// engagedRun builds a RunContext that has genuinely fetched a context, with
// the given snapshot data. A RunContext whose Context is nil is a platform
// that never answered, and the lane split does not apply to it.
func engagedRun(data *platform.SnapshotData) *platform.RunContext {
	return &platform.RunContext{
		Endpoint:    "https://platform.test",
		ProjectPath: "group/project",
		Context: &platform.ProjectContext{
			Snapshot: platform.Snapshot{Data: data},
		},
	}
}

func TestProtectionFromSnapshotStandaloneDoesNotServe(t *testing.T) {
	// nil is standalone mode: the caller must collect from GitLab exactly
	// as it always has.
	if _, served := ProtectionFromSnapshot(nil); served {
		t.Error("standalone mode must not be served from a snapshot")
	}
	if _, served := VariablesFromSnapshot(nil); served {
		t.Error("standalone mode must not be served from a snapshot")
	}

	// --platform was asked for but the platform never answered. There is no
	// agreed lane split without an answer, so the run collects locally.
	notFetched := &platform.RunContext{Endpoint: "https://platform.test"}
	if _, served := ProtectionFromSnapshot(notFetched); served {
		t.Error("a context that was never fetched must not be treated as a served lane")
	}
	if _, served := VariablesFromSnapshot(notFetched); served {
		t.Error("a context that was never fetched must not be treated as a served lane")
	}
}

func TestProtectionFromSnapshotDecodesTheLanes(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{
		SchemaVersion: platform.SnapshotSchemaV2,
		BranchProtection: json.RawMessage(`{
			"branches": ["main", "feature/x"],
			"protections": [{
				"protectionPattern": "main",
				"allowForcePush": true,
				"codeOwnerApprovalRequired": true,
				"pushAccessLevels": [{"accessLevel": 40, "accessLevelDescription": "Maintainers"}],
				"mergeAccessLevels": [{"accessLevel": 30, "accessLevelDescription": "Developers"}]
			}]
		}`),
		MrApprovals: json.RawMessage(`{
			"rules": [{"id": 7, "name": "two eyes", "approvals_required": 2, "applies_to_all_protected_branches": true}],
			"settings": {"reset_approvals_on_push": true, "merge_requests_author_approval": false}
		}`),
	})

	data, served := ProtectionFromSnapshot(run)
	if !served {
		t.Fatal("an engaged run must be served from the snapshot")
	}

	if got := data.Branches; len(got) != 2 || got[0] != "main" {
		t.Errorf("branches = %v, want [main feature/x]", got)
	}
	if len(data.BranchProtections) != 1 {
		t.Fatalf("protections = %d, want 1", len(data.BranchProtections))
	}
	p := data.BranchProtections[0]
	if p.ProtectionPattern != "main" || !p.AllowForcePush || !p.CodeOwnerApprovalRequired {
		t.Errorf("protection decoded wrong: %+v", p)
	}
	// The access-level ARRAYS are what buildBranches reduces to the
	// effective bar; a decoder that dropped them would silently report
	// "nobody may push" (level 0) on every protected branch.
	if len(p.PushAccessLevels) != 1 || p.PushAccessLevels[0].AccessLevel != 40 {
		t.Errorf("push access levels = %+v, want one entry at 40", p.PushAccessLevels)
	}
	if len(p.MergeAccessLevels) != 1 || p.MergeAccessLevels[0].AccessLevel != 30 {
		t.Errorf("merge access levels = %+v, want one entry at 30", p.MergeAccessLevels)
	}

	if !data.MRApprovalRulesKnown {
		t.Error("a healthy mr_approvals lane must be authoritative")
	}
	if len(data.MRApprovalRules) != 1 || data.MRApprovalRules[0].ApprovalsRequired != 2 {
		t.Errorf("approval rules decoded wrong: %+v", data.MRApprovalRules)
	}
	if data.MRApprovalSettings == nil || !data.MRApprovalSettings.ResetApprovalsOnPush {
		t.Errorf("approval settings decoded wrong: %+v", data.MRApprovalSettings)
	}

	// The project payload's merge settings have no snapshot lane, so the
	// only honest value is nil. A zero-valued glab.Project here would make
	// ISSUE-506 compare a real expectation against fabricated defaults.
	if data.MRSettings != nil {
		t.Error("MRSettings has no snapshot lane and must stay nil")
	}
}

// TestProtectionFromSnapshotEmptyLanesAreRealFindings pins the distinction
// the whole design turns on. A project with NO protected branches is
// exactly what branchMustBeProtected exists to catch, so an empty
// protections list must reach the control as data, not as an abstention.
func TestProtectionFromSnapshotEmptyLanesAreRealFindings(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{
		SchemaVersion:    platform.SnapshotSchemaV2,
		BranchProtection: json.RawMessage(`{"branches": ["main"], "protections": []}`),
		MrApprovals:      json.RawMessage(`{"rules": []}`),
	})

	data, served := ProtectionFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	if len(data.Branches) != 1 {
		t.Errorf("branches = %v, want [main]", data.Branches)
	}
	if len(data.BranchProtections) != 0 {
		t.Errorf("protections = %v, want none", data.BranchProtections)
	}
	if !data.MRApprovalRulesKnown {
		t.Error("an empty rules list from a HEALTHY collection is authoritative: the control must fail on it, not abstain")
	}
}

// TestProtectionFromSnapshotDegradedLaneIsNotEmpty is the other half: a
// lane the platform reports as a FAILED collection must not be scored. The
// payload looks identical to the empty case above, and degraded_fields is
// the only thing that tells them apart.
func TestProtectionFromSnapshotDegradedLaneIsNotEmpty(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{
		SchemaVersion:  platform.SnapshotSchemaV2,
		DegradedFields: []string{platform.DegradedFieldMrApprovals},
	})

	data, served := ProtectionFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	if data.MRApprovalRulesKnown {
		t.Error("a degraded mr_approvals lane must leave the listing non-authoritative")
	}
}

// TestProtectionFromSnapshotPreV2CannotVouchForALane guards the version
// gate from this side. Below schema 2 the platform recorded no degradation
// bookkeeping, so an absent lane proves nothing — and IsDegraded answers
// false, which callers must not read as "this lane is fine".
func TestProtectionFromSnapshotPreV2CannotVouchForALane(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{SchemaVersion: "1"})
	data, served := ProtectionFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	// LaneDegraded is false on a pre-v2 snapshot because the snapshot
	// cannot tell us, not because the lane succeeded. This test records
	// that the CLI currently treats that as authoritative-empty; if that
	// ever changes, this is the assertion to revisit.
	if !data.MRApprovalRulesKnown {
		t.Error("pre-v2 behaviour changed; confirm it is deliberate")
	}
}

func TestProtectionFromSnapshotUndecodableLaneIsUnavailable(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{
		SchemaVersion:    platform.SnapshotSchemaV2,
		BranchProtection: json.RawMessage(`{"protections": "not-a-list"}`),
	})

	data, served := ProtectionFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	// A lane the CLI cannot read is not a project with no protected
	// branches. Leaving the collection empty is what lets control/lanes.go
	// report not_evaluable instead of inventing a violation.
	if len(data.Branches) != 0 || len(data.BranchProtections) != 0 {
		t.Errorf("an undecodable lane must decode to nothing, got %+v", data)
	}
}

func TestProtectionFromSnapshotNoSnapshotAtAll(t *testing.T) {
	data, served := ProtectionFromSnapshot(engagedRun(nil))
	if !served {
		t.Fatal("an engaged run with no cached snapshot is still platform mode")
	}
	if data == nil {
		t.Fatal("expected an empty collection, not nil")
	}
	if data.MRApprovalRulesKnown {
		t.Error("no snapshot means no authoritative approval-rules listing")
	}
}

// TestVariablesFromSnapshotKeepsOnlyProjectScope is the one that would go
// wrong silently. The platform collects group-inherited and instance-level
// variables into the same list; cicdVariablesMustBe* are about the
// project's OWN settings, and reporting a group variable under the
// project's verdict would flag something the project cannot fix.
func TestVariablesFromSnapshotKeepsOnlyProjectScope(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{
		SchemaVersion: platform.SnapshotSchemaV2,
		Variables: json.RawMessage(`{"items": [
			{"name": "PROJECT_SECRET", "type": "env_var", "scope": "project", "masked": true, "protected": true},
			{"name": "PROJECT_PLAIN", "type": "env_var", "scope": "project"},
			{"name": "GROUP_TOKEN", "type": "env_var", "scope": "group"},
			{"name": "INSTANCE_TOKEN", "type": "env_var", "scope": "instance"}
		]}`),
	})

	data, served := VariablesFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	if !data.Known {
		t.Error("a healthy variables lane must be authoritative")
	}
	if len(data.Variables) != 2 {
		t.Fatalf("kept %d variables, want the 2 project-scoped ones: %+v", len(data.Variables), data.Variables)
	}
	if data.Variables[0].Name != "PROJECT_SECRET" || !data.Variables[0].Masked || !data.Variables[0].Protected {
		t.Errorf("first variable decoded wrong: %+v", data.Variables[0])
	}
	// The platform omits FALSE booleans, so an unprotected, unmasked
	// variable arrives with those keys absent. Absent must decode to false,
	// which is the finding, not to some other default.
	if data.Variables[1].Masked || data.Variables[1].Protected {
		t.Errorf("absent booleans must decode as false, got %+v", data.Variables[1])
	}
	for _, v := range data.Variables {
		if v.Value != "" {
			t.Errorf("a variable value reached the collection: %q", v.Name)
		}
	}
}

func TestVariablesFromSnapshotEmptyIsAPass(t *testing.T) {
	// The platform omits the whole variables section when it collected
	// none. A project with no CI/CD variables genuinely passes both
	// controls, so this must be authoritative rather than an abstention.
	run := engagedRun(&platform.SnapshotData{SchemaVersion: platform.SnapshotSchemaV2})
	data, served := VariablesFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	if !data.Known {
		t.Error("an absent-but-healthy variables lane is an authoritative empty listing")
	}
	if len(data.Variables) != 0 {
		t.Errorf("expected no variables, got %+v", data.Variables)
	}
}

func TestVariablesFromSnapshotDegradedIsNotKnown(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{
		SchemaVersion:  platform.SnapshotSchemaV2,
		DegradedFields: []string{platform.DegradedFieldVariables},
	})
	data, served := VariablesFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	if data.Known {
		t.Error("a degraded variables lane must not certify an unprotected variable as fine")
	}
}

func TestVariablesFromSnapshotUndecodableIsNotKnown(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{
		SchemaVersion: platform.SnapshotSchemaV2,
		Variables:     json.RawMessage(`{"items": {"not": "a list"}}`),
	})
	data, served := VariablesFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	if data.Known {
		t.Error("an undecodable variables lane must not be authoritative")
	}
}

// TestSnapshotLanesRoundTripTheProviderTypes pins the contract from this
// side. The platform builds these payloads by MARSHALLING this package's
// own types (ADR-0021: it imports the CLI rather than reimplementing the
// collector), so anything that survives a marshal here must survive the
// decoders. A field renamed in BranchProtection or a tag changed on
// glab.ProjectApprovalRule breaks the wire silently; this catches it.
func TestSnapshotLanesRoundTripTheProviderTypes(t *testing.T) {
	original := []BranchProtection{{
		ProtectionPattern:         "release/*",
		AllowForcePush:            false,
		CodeOwnerApprovalRequired: true,
		PushAccessLevels:          []BranchProtectionAccessLevel{{AccessLevel: 40, AccessLevelDescription: "Maintainers"}},
		MergeAccessLevels:         []BranchProtectionAccessLevel{{AccessLevel: 30, AccessLevelDescription: "Developers"}},
	}}
	protections, err := json.Marshal(map[string]any{"branches": []string{"main"}, "protections": original})
	if err != nil {
		t.Fatalf("marshaling the platform's own shape: %v", err)
	}

	rules := []*glab.ProjectApprovalRule{{ID: 12, Name: "security", ApprovalsRequired: 3}}
	approvals, err := json.Marshal(map[string]any{"rules": rules})
	if err != nil {
		t.Fatalf("marshaling the platform's own shape: %v", err)
	}

	data, served := ProtectionFromSnapshot(engagedRun(&platform.SnapshotData{
		SchemaVersion:    platform.SnapshotSchemaV2,
		BranchProtection: protections,
		MrApprovals:      approvals,
	}))
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}

	if len(data.BranchProtections) != 1 || !sameProtection(data.BranchProtections[0], original[0]) {
		t.Errorf("branch protection did not round-trip:\n got %+v\nwant %+v", data.BranchProtections, original)
	}
	if len(data.MRApprovalRules) != 1 || data.MRApprovalRules[0].ID != 12 || data.MRApprovalRules[0].ApprovalsRequired != 3 {
		t.Errorf("approval rules did not round-trip: %+v", data.MRApprovalRules)
	}
}

// sameProtection compares two protections by their MARSHALED form.
// BranchProtection holds slices, so == does not apply, and comparing the
// wire encoding is what this test is actually about: the payload the
// platform writes and the payload the CLI reads must be the same bytes.
func sameProtection(a, b BranchProtection) bool {
	left, errA := json.Marshal(a)
	right, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(left) == string(right)
}

// TestSnapshotDecodersAgainstACapturedContextPayload runs the decoders over
// a payload CAPTURED from a running platform rather than one written to
// match the decoders.
//
// Every other test in this file states what the CLI expects. This one
// states what the platform actually sent, on 2026-08-26, for a real GitLab
// project (identifiers replaced, shapes untouched). It is the check that
// catches the class of drift a hand-written fixture cannot: a key the
// platform spells differently, a boolean it omits, a section it leaves out
// entirely. Refresh it from `scripts/platform-e2e/context.sh --raw` when the
// contract moves, and read the diff rather than the new file.
//
// Three properties of the captured payload are worth naming, because each
// one is a decision the decoders had to make:
//
//   - mr_approvals carries `settings` and NO `rules` key. On GitLab Free the
//     approval-rules endpoint answers 200 with an empty list, so the
//     platform's collector - which only stores a non-empty list - omits it.
//     That is an authoritative "no rules", not a failed read, and
//     degraded_fields is absent to confirm it.
//   - variables.items mixes scopes. The group-scoped entry is a token
//     inherited from the parent group; judging it under the project's
//     verdict would report a violation the project cannot fix.
//   - The booleans are omitted when false. `protected` is present only on
//     the two protected variables and absent on the rest.
func TestSnapshotDecodersAgainstACapturedContextPayload(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "platform_snapshot_v2.json"))
	if err != nil {
		t.Fatalf("reading the captured payload: %v", err)
	}
	var data platform.SnapshotData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("the captured payload no longer decodes into SnapshotData: %v", err)
	}
	run := engagedRun(&data)

	protection, served := ProtectionFromSnapshot(run)
	if !served {
		t.Fatal("expected the snapshot lane to be served")
	}
	if len(protection.Branches) != 3 {
		t.Errorf("branches = %v, want the three in the payload", protection.Branches)
	}
	if len(protection.BranchProtections) != 1 {
		t.Fatalf("protections = %d, want 1", len(protection.BranchProtections))
	}
	p := protection.BranchProtections[0]
	if p.ProtectionPattern != "main" || !p.AllowForcePush {
		t.Errorf("protection decoded wrong: %+v", p)
	}
	// The scalar minima serialize as 0 because no API path populates them;
	// buildBranches derives the real bar from the arrays, so those are what
	// must survive.
	if len(p.MergeAccessLevels) != 1 || p.MergeAccessLevels[0].AccessLevel != 40 {
		t.Errorf("merge access levels = %+v, want one entry at 40", p.MergeAccessLevels)
	}

	if !protection.MRApprovalRulesKnown {
		t.Error("no rules key and nothing degraded is an authoritative empty listing")
	}
	if len(protection.MRApprovalRules) != 0 {
		t.Errorf("rules = %+v, want none", protection.MRApprovalRules)
	}
	if protection.MRApprovalSettings == nil {
		t.Fatal("the settings the payload carries must decode")
	}
	if protection.MRApprovalSettings.MergeRequestsAuthorApproval {
		t.Error("merge_requests_author_approval decoded wrong")
	}

	variables, served := VariablesFromSnapshot(run)
	if !served {
		t.Fatal("expected the variables lane to be served")
	}
	if !variables.Known {
		t.Error("nothing is degraded in the captured payload")
	}
	for _, v := range variables.Variables {
		if strings.HasPrefix(v.Name, "GROUP_") || strings.HasPrefix(v.Name, "INSTANCE_") {
			t.Errorf("a variable from another scope reached the project's verdict: %q", v.Name)
		}
		if v.Value != "" {
			t.Errorf("a variable value reached the collection: %q", v.Name)
		}
	}
	if len(variables.Variables) != 5 {
		t.Fatalf("kept %d variables, want the 5 project-scoped ones", len(variables.Variables))
	}
	protectedCount := 0
	for _, v := range variables.Variables {
		if v.Protected {
			protectedCount++
		}
	}
	if protectedCount != 2 {
		t.Errorf("protected variables = %d, want 2; an omitted false must decode as false", protectedCount)
	}
}

// TestDeclaredVariableNamesExcludesWhatTheJobCannotStandInFor pins the
// filter that decides which placeholders may be expanded from the analysing
// job's environment.
//
// The values come from THIS job. The references being expanded belong to
// every job in the pipeline. So a variable only qualifies when its value is
// the same for all of them and is not a secret - and when it does not, the
// right outcome is an unexpanded placeholder and an abstention, never a
// plausible substitute.
func TestDeclaredVariableNamesExcludesWhatTheJobCannotStandInFor(t *testing.T) {
	run := engagedRun(&platform.SnapshotData{
		SchemaVersion: platform.SnapshotSchemaV2,
		Variables: json.RawMessage(`{"items": [
			{"name": "REGISTRY", "type": "ENV_VAR", "scope": "project", "environment": "*"},
			{"name": "TAG", "type": "ENV_VAR", "scope": "group"},
			{"name": "PROD_REGISTRY", "type": "ENV_VAR", "scope": "project", "environment": "production"},
			{"name": "DEPLOY_KEY", "type": "ENV_VAR", "scope": "project", "environment": "*", "masked": true},
			{"name": "SECRET_HOST", "type": "ENV_VAR", "scope": "project", "environment": "*", "hidden": true},
			{"name": "KUBE_CONFIG", "type": "FILE", "scope": "project", "environment": "*"}
		]}`),
	})

	// An unprotected ref: GitLab withholds a protected variable there, so
	// anything found under that name in this process came from elsewhere.
	t.Setenv("CI_COMMIT_REF_PROTECTED", "false")

	got := DeclaredVariableNames(run)
	want := map[string]bool{"REGISTRY": true, "TAG": true}
	if len(got) != len(want) {
		t.Fatalf("expandable names = %v, want exactly %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("%q must not be expanded from this job's environment", name)
		}
	}
}

// TestJobEnvironmentVariablesReadsOnlyWhatItMay covers the other half: the
// environment holds far more than CI/CD variables, and an image reference
// containing `$HOME` is not one GitLab would have expanded.
func TestJobEnvironmentVariablesReadsOnlyWhatItMay(t *testing.T) {
	t.Setenv("CI_REGISTRY_IMAGE", "registry.example.com/group/project")
	t.Setenv("GITLAB_USER_LOGIN", "someone")
	t.Setenv("REGISTRY", "registry.example.com")
	t.Setenv("HOME", "/root")
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("EMPTY_ONE", "")

	got := JobEnvironmentVariables([]string{"REGISTRY", "EMPTY_ONE"})

	// Declared by the platform, or under a GitLab-reserved prefix.
	for _, name := range []string{"CI_REGISTRY_IMAGE", "GITLAB_USER_LOGIN", "REGISTRY"} {
		if got[name] == "" {
			t.Errorf("%q should be available for expansion", name)
		}
	}
	// Process environment that is not a CI/CD variable. GitLab would not
	// substitute these into an image reference, so neither may we.
	for _, name := range []string{"HOME", "PATH"} {
		if _, present := got[name]; present {
			t.Errorf("%q is not a CI/CD variable and must not be substituted", name)
		}
	}
	// A defined-but-empty variable is skipped: substituting "" turns
	// `$REGISTRY/app` into `/app`, a reference that looks resolved, carries
	// no `$` for anything to notice, and is not the one the job uses.
	if _, present := got["EMPTY_ONE"]; present {
		t.Error("an empty value must not be substituted")
	}
}

// TestDeclaredVariableNamesHonoursRefProtection covers the entitlement rule
// the whole env-expansion approach rests on.
//
// A protected variable reaches a job only on a protected ref. On any other
// ref GitLab withholds it, so a value found under that name in this process
// came from somewhere else - an ENV line in Plumber's own container image is
// the likely source, where names like VERSION or LANG are ordinary.
// Substituting it would judge a job against a value it is specifically not
// allowed to see.
func TestDeclaredVariableNamesHonoursRefProtection(t *testing.T) {
	data := &platform.SnapshotData{
		SchemaVersion: platform.SnapshotSchemaV2,
		Variables: json.RawMessage(`{"items": [
			{"name": "RELEASE_REGISTRY", "type": "ENV_VAR", "scope": "project", "environment": "*", "protected": true},
			{"name": "PUBLIC_REGISTRY", "type": "ENV_VAR", "scope": "project", "environment": "*"}
		]}`),
	}

	t.Run("unprotected ref withholds the protected variable", func(t *testing.T) {
		t.Setenv("CI_COMMIT_REF_PROTECTED", "false")
		got := DeclaredVariableNames(engagedRun(data))
		if len(got) != 1 || got[0] != "PUBLIC_REGISTRY" {
			t.Errorf("expandable = %v, want only PUBLIC_REGISTRY", got)
		}
	})

	t.Run("protected ref makes it available", func(t *testing.T) {
		t.Setenv("CI_COMMIT_REF_PROTECTED", "true")
		got := map[string]bool{}
		for _, n := range DeclaredVariableNames(engagedRun(data)) {
			got[n] = true
		}
		if !got["RELEASE_REGISTRY"] || !got["PUBLIC_REGISTRY"] {
			t.Errorf("expandable = %v, want both on a protected ref", got)
		}
	})
}

// TestJobEnvironmentVariablesSkipsJobScopedPredefined covers the one class
// the reserved-prefix allowlist gets wrong.
//
// `CI_`-prefixed names are a sound allowlist for pipeline-wide facts:
// $CI_REGISTRY_IMAGE is the same for every job. The job-scoped ones are not.
// Plumber reads them from ITS OWN job, so substituting them into another
// job's image reference produces a resolved-looking value that is
// confidently wrong - worse than the placeholder it replaced.
func TestJobEnvironmentVariablesSkipsJobScopedPredefined(t *testing.T) {
	t.Setenv("CI_REGISTRY_IMAGE", "registry.example.com/group/project")
	t.Setenv("CI_JOB_NAME", "plumber")
	t.Setenv("CI_JOB_IMAGE", "getplumber/plumber:1.2.3")
	t.Setenv("CI_ENVIRONMENT_NAME", "production")
	t.Setenv("CI_NODE_INDEX", "1")

	got := JobEnvironmentVariables(nil)

	if got["CI_REGISTRY_IMAGE"] == "" {
		t.Error("a pipeline-wide predefined variable must still be expandable")
	}
	for _, name := range []string{"CI_JOB_NAME", "CI_JOB_IMAGE", "CI_ENVIRONMENT_NAME", "CI_NODE_INDEX"} {
		if _, present := got[name]; present {
			t.Errorf("%q describes Plumber's own job and must not be substituted into another job's reference", name)
		}
	}
}

// TestProtectionFromSnapshotMarksTheListingKnown pins the flag the branch
// controls read to decide whether they may report a verdict at all.
//
// An empty protection list and an unreadable one are the same bytes. The
// difference is this flag, and getting it wrong in the permissive direction
// certifies a project whose protections nobody could read.
func TestProtectionFromSnapshotMarksTheListingKnown(t *testing.T) {
	served := json.RawMessage(`{"branches":["main"],"protections":[]}`)

	t.Run("a healthy lane is authoritative", func(t *testing.T) {
		data, _ := ProtectionFromSnapshot(engagedRun(&platform.SnapshotData{
			SchemaVersion: platform.SnapshotSchemaV2, BranchProtection: served,
		}))
		if !data.BranchProtectionsKnown {
			t.Error("a decoded, undegraded lane is a real listing; the controls must judge it")
		}
	})

	t.Run("a degraded lane is not", func(t *testing.T) {
		data, _ := ProtectionFromSnapshot(engagedRun(&platform.SnapshotData{
			SchemaVersion:    platform.SnapshotSchemaV2,
			BranchProtection: served,
			DegradedFields:   []string{platform.DegradedFieldBranchProtection},
		}))
		if data.BranchProtectionsKnown {
			t.Error("the platform said this collection failed; its emptiness proves nothing")
		}
	})

	t.Run("an absent lane is not", func(t *testing.T) {
		data, _ := ProtectionFromSnapshot(engagedRun(&platform.SnapshotData{
			SchemaVersion: platform.SnapshotSchemaV2,
		}))
		if data.BranchProtectionsKnown {
			t.Error("no lane at all cannot be authoritative")
		}
	})
}
