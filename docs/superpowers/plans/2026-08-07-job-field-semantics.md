# `Finding.Job` Means A Job: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `Finding.Job` hold a CI job name and nothing else, moving the ten
finding blocks that put a branch, an include source or a required path there
onto structured subject keys instead.

**Architecture:** Rego rules stop emitting `"job"` where the value is not a job,
and each such rule emits a key naming what its finding is about. The identity
recipe in `finding/identity` selects that key as the subject, so identity keeps
its discrimination without leaning on a mislabelled field. Output formats need
no changes: `projectFinding` and the OCSF writer already omit the key when
`Job` is empty.

**Tech Stack:** Go 1.25 / 1.26, Open Policy Agent (Rego v1), `make test`,
`make lint`, `make deadcode`.

## Global Constraints

- Design spec: `docs/superpowers/specs/2026-08-07-job-field-semantics-design.md`.
- `identity.RecipeVersion` stays **2**. Do not bump it: this work ships in the
  same release as the re-key already in PR #404, so the affected set moves once.
- The selection algorithm in `finding/identity` does not change. Only the
  priority list and the rule payloads change.
- No rule may emit `"job": ""`. Omit the key entirely.
- ISSUE-401 `hardcoded_jobs` keeps `"job": job.name`. It is not part of this
  change.
- No em dashes in comments, commit messages or docs.
- Every commit must leave `make test`, `make lint` and `make deadcode` green.

---

### Task 1: Reorder the subject-key priority list

**Files:**
- Modify: `finding/identity/identity.go` (the `subjectKeys` var)
- Test: `finding/identity/identity_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: the key names later tasks emit from Rego: `includePath`,
  `templatePath`, `componentPath`, `requiredAction`. `identity.SubjectKeys()`
  returns them in priority order.

- [ ] **Step 1: Write the failing tests**

In `finding/identity/identity_test.go`, replace the body of
`TestSubjectKeys_CoverTheStructuredControls` with the new list and add one new
test below it:

```go
// Every control that names what it is about must have its key in the list, or
// its findings ride on reformulable prose.
func TestSubjectKeys_CoverTheStructuredControls(t *testing.T) {
	keys := identity.SubjectKeys()
	for _, want := range []string{
		"uses", "branchName", "includePath", "templatePath", "componentPath",
		"requiredAction", "hardcodedJob",
	} {
		if !slices.Contains(keys, want) {
			t.Errorf("subject key %q missing from the recipe: %v", want, keys)
		}
	}
}

// componentName is payload, not identity. ISSUE-402 and ISSUE-403 emit it as an
// empty string for any include that is not a component, and it holds a bare
// name where includePath holds the full source. Two components named "deploy"
// in different groups would collide on the bare name.
func TestSubjectKeys_ExcludesComponentName(t *testing.T) {
	if slices.Contains(identity.SubjectKeys(), "componentName") {
		t.Errorf("componentName is payload, not a subject key: %v", identity.SubjectKeys())
	}
}

// A finding carrying both keys must identify on the full source.
func TestOf_IncludePathOutranksComponentName(t *testing.T) {
	f := identity.Finding{
		Code: "ISSUE-403", File: ".gitlab-ci.yml",
		Data: map[string]any{
			"componentName": "deploy",
			"includePath":   "gitlab.example.com/components/deploy/deploy",
		},
	}

	got, _ := identity.Of(f)

	if got.Subject.Key != "includePath" {
		t.Errorf("subject = %+v, want the includePath key", got.Subject)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./finding/... -run 'TestSubjectKeys|TestOf_IncludePathOutranks' -v`

Expected: `TestSubjectKeys_CoverTheStructuredControls` fails on the missing
`componentPath` and `requiredAction`, `TestSubjectKeys_ExcludesComponentName`
fails because `componentName` is still in the list, and
`TestOf_IncludePathOutranksComponentName` fails with
`subject = {Key:componentName Value:deploy}`.

- [ ] **Step 3: Update the priority list**

In `finding/identity/identity.go`:

```go
var subjectKeys = []string{
	"uses", "branchName", "includePath", "templatePath", "componentPath",
	"requiredAction", "image", "serviceImage", "link", "tag", "variableName",
	"hardcodedJob", "scriptLine", "detail",
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./finding/... -v`
Expected: PASS. The golden fingerprint tests must still pass: they use `uses`
and the message fallback, neither of which moved.

- [ ] **Step 5: Commit**

```bash
git add finding/identity/identity.go finding/identity/identity_test.go
git commit -m "refactor(identity): order the subject keys by specificity

includePath outranks componentName because a full include source beats a
bare component name, and componentName leaves the list entirely: it is
payload, empty for any include that is not a component, and no control
depends on it for identity.

Refs #403"
```

---

### Task 2: Component family (ISSUE-408, ISSUE-409)

**Files:**
- Modify: `policies/component_missing.rego`
- Modify: `policies/component_overridden.rego`
- Test: `policies/rules_test.go` (`assertSubjectKey`, `assertNoJob`,
  `TestIssue408_ComponentMissing`, `TestIssue409_ComponentOverridden`)

**Interfaces:**
- Consumes: `identity.SubjectKeys()` containing `componentPath` (Task 1).
- Produces: `assertNoJob(t *testing.T, findings []opaengine.Finding, code string)`,
  used by Tasks 3 to 6.

- [ ] **Step 1: Write the failing tests**

In `policies/rules_test.go`, add this helper directly below `assertSubjectKey`:

```go
// assertNoJob pins that a control leaves Finding.Job empty. The field is a CI
// job name and a hashed identity input; a control that puts a branch, an
// include source or a required path there both mislabels its output and makes
// identity depend on the mislabelling.
func assertNoJob(t *testing.T, findings []opaengine.Finding, code string) {
	t.Helper()
	for _, f := range findings {
		if f.Code == code && f.Job != "" {
			t.Errorf("%s: job = %q, want empty: this finding is not about a job", code, f.Job)
		}
	}
}
```

In `TestIssue408_ComponentMissing`, replace the `hits` collection (which keys on
`f.Job`) and the trailing `assertSubjectKey` call with:

```go
	hits := map[string]bool{}
	for _, f := range findings {
		if f.Code == "ISSUE-408" {
			name, _ := f.Data["componentPath"].(string)
			hits[name] = true
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
	assertSubjectKey(t, findings, "ISSUE-408", "componentPath",
		[]string{"components/secret-detection/secret-detection", "your-org/full-security/full-security"})
	assertNoJob(t, findings, "ISSUE-408")
```

In `TestIssue409_ComponentOverridden`, replace the trailing `assertSubjectKey`
call with:

```go
	assertSubjectKey(t, findings, "ISSUE-409", "componentPath", []string{"components/sast/sast"})
	assertNoJob(t, findings, "ISSUE-409")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./policies/ -run 'TestIssue408_ComponentMissing|TestIssue409_ComponentOverridden' -v`

Expected: both fail. `componentPath` is not emitted yet, so `hits` is keyed on
the empty string and `assertNoJob` reports
`job = "components/sast/sast", want empty`.

- [ ] **Step 3: Update the rules**

In `policies/component_missing.rego`, replace the finding object with:

```rego
	finding := {
		"code":     "ISSUE-408",
		"severity": "high",
		"message":  sprintf("required component %q is missing from the pipeline (group %d)", [required, i]),
		# No "job": a missing component is not a job. componentPath names what
		# this finding is about and is what the identity recipe selects
		# (finding/identity). The group index stays out: it moves whenever the
		# user reorders requiredGroups, which is not a new finding.
		"componentPath": required,
	}
```

In `policies/component_overridden.rego`:

```rego
	finding := {
		"code":     "ISSUE-409",
		"severity": "high",
		"message":  sprintf("required component %q is imported but %d of its job(s) are overridden locally", [required, count(inc.overriddenJobs)]),
		# No "job": an overridden component is not a job. componentPath names
		# what this finding is about, so its identity does not depend on the
		# message above, whose override count moves as jobs are added.
		"componentPath": required,
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./policies/ -run 'TestIssue40[89]' -v`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `make test`
Expected: PASS. If `cmd` fails, a JSON fixture is asserting `job` on one of
these blocks; update the fixture to drop the key.

- [ ] **Step 6: Commit**

```bash
git add policies/component_missing.rego policies/component_overridden.rego policies/rules_test.go
git commit -m "fix(policies): stop putting a component path in the job field

ISSUE-408 and ISSUE-409 are about a required component, not a job. They
now emit componentPath and leave job empty, so identity names what it
identifies instead of leaning on a mislabelled field. componentPath also
disambiguates from componentName, which holds a bare name elsewhere.

Refs #403"
```

---

### Task 3: Template family (ISSUE-405, ISSUE-406)

**Files:**
- Modify: `policies/template_missing.rego`
- Modify: `policies/template_overridden.rego`
- Test: `policies/rules_test.go` (`TestIssue405_TemplateMissing`,
  `TestIssue406_TemplateOverridden`)

**Interfaces:**
- Consumes: `assertNoJob` (Task 2), `templatePath` already in the priority list
  (Task 1).
- Produces: nothing new.

- [ ] **Step 1: Write the failing tests**

In `TestIssue405_TemplateMissing`, replace the `hits` collection and the
trailing `assertSubjectKey` call with:

```go
	hits := map[string]bool{}
	for _, f := range findings {
		if f.Code == "ISSUE-405" {
			path, _ := f.Data["templatePath"].(string)
			hits[path] = true
		}
	}
	if !hits["templates/trivy/trivy"] {
		t.Fatalf("expected trivy template flagged, got %v", hits)
	}
	if hits["templates/go/go"] {
		t.Fatalf("unexpected flag on present template: %v", hits)
	}
	assertSubjectKey(t, findings, "ISSUE-405", "templatePath", []string{"templates/trivy/trivy"})
	assertNoJob(t, findings, "ISSUE-405")
```

In `TestIssue406_TemplateOverridden`, append after the existing
`assertSubjectKey` call:

```go
	assertNoJob(t, findings, "ISSUE-406")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./policies/ -run 'TestIssue40[56]' -v`
Expected: both fail with `job = "templates/trivy/trivy", want empty` and
`job = "templates/go/go", want empty`.

- [ ] **Step 3: Update the rules**

In `policies/template_missing.rego`, replace the finding object with:

```rego
	finding := {
		"code":     "ISSUE-405",
		"severity": "high",
		"message":  sprintf("required template %q is missing from the pipeline (group %d)", [required, i]),
		# No "job": a missing template is not a job. templatePath names what
		# this finding is about and is what the identity recipe selects
		# (finding/identity). The group index stays out: it moves whenever the
		# user reorders requiredGroups, which is not a new finding.
		"templatePath": required,
	}
```

In `policies/template_overridden.rego`:

```rego
	finding := {
		"code":     "ISSUE-406",
		"severity": "high",
		"message":  sprintf("required template %q is imported but %d of its job(s) are overridden locally", [required, count(inc.overriddenJobs)]),
		# No "job": an overridden template is not a job. templatePath names what
		# this finding is about, so its identity does not depend on the message
		# above, whose override count moves as jobs are added.
		"templatePath": required,
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./policies/ -run 'TestIssue40[56]' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add policies/template_missing.rego policies/template_overridden.rego policies/rules_test.go
git commit -m "fix(policies): stop putting a template path in the job field

ISSUE-405 and ISSUE-406 are about a required template, not a job.

Refs #403"
```

---

### Task 4: Include family (ISSUE-402 GitLab block, ISSUE-403, ISSUE-404)

**Files:**
- Modify: `policies/ref_confusion.rego` (the GitLab include block only, the one
  matching `input.pipeline.includes`)
- Modify: `policies/includes_outdated.rego`
- Modify: `policies/includes_forbidden_version.rego`
- Test: `policies/rules_test.go`
  (`TestIssue404_IncludesForbiddenVersion`, plus two new tests)

**Interfaces:**
- Consumes: `assertNoJob` (Task 2), `includePath` in the priority list (Task 1).
- Produces: nothing new.

Note: `ref_confusion.rego` has two finding blocks. Only the second one, which
iterates `input.pipeline.includes`, is changed. The first iterates
`input.pipeline.jobs` and its `"job": job.name` is correct.

- [ ] **Step 1: Write the failing tests**

In `TestIssue404_IncludesForbiddenVersion`, append after the existing
`assertSubjectKey` call:

```go
	assertNoJob(t, findings, "ISSUE-404")
```

Add two new tests at the end of `policies/rules_test.go`:

```go
// ISSUE-403 is about an include, not a job. Its identity used to be the include
// source smuggled through the job field, with componentName (a bare name, empty
// for non-component includes) as the only structured key.
func TestIssue403_OutdatedIncludeIdentifiesOnTheIncludePath(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "component", Source: "gitlab.example.com/components/sast/sast", Ref: "1.0.0", Current: "1.1.0"},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertSubjectKey(t, findings, "ISSUE-403", "includePath",
		[]string{"gitlab.example.com/components/sast/sast"})
	assertNoJob(t, findings, "ISSUE-403")
}

// ISSUE-402's GitLab block is about an include. Its GitHub block, which flags an
// ambiguous action ref inside a job, keeps its job name and its uses subject.
func TestIssue402_AmbiguousIncludeIdentifiesOnTheIncludePath(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "component", Source: "gitlab.example.com/components/sast/sast", Ref: "v1", RefIsAmbiguous: true},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertSubjectKey(t, findings, "ISSUE-402", "includePath",
		[]string{"gitlab.example.com/components/sast/sast"})
	assertNoJob(t, findings, "ISSUE-402")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./policies/ -run 'TestIssue40[234]' -v`

Expected: all three fail. ISSUE-403 and ISSUE-402 report
`identity subject is "componentName"=...` or the message fallback, and
`assertNoJob` reports the include source in `job`.

- [ ] **Step 3: Update the rules**

In `policies/includes_forbidden_version.rego`, remove the `"job"` line so the
finding object reads:

```rego
	finding := {
		"code":     "ISSUE-404",
		"severity": "medium",
		"message":  sprintf("%s uses forbidden version '%s'", [inc.source, inc.ref]),
		# No "job": an include is not a job. includePath names what this finding
		# is about and is what the identity recipe selects (finding/identity).
		# The ref stays out: the same include drifting from one forbidden
		# version to another is the same unresolved problem.
		"includePath": inc.source,
	}
```

In `policies/includes_outdated.rego`, remove the `"job"` line and add
`"includePath"`:

```rego
	finding := {
		"code":     "ISSUE-403",
		"severity": "medium",
		"message":  sprintf("%s uses version '%s' (latest: %s)", [inc.source, inc.ref, inc.current]),
		# No "job": an include is not a job. includePath names what this finding
		# is about (finding/identity). componentName stays as payload: it is a
		# bare name, empty for any include that is not a component.
		"includePath":           inc.source,
		"file":                  object.get(inc, "originFile", ""),
		"line":                  object.get(inc, "originLine", 0),
		"version":               inc.ref,
		"latestVersion":         inc.current,
		"gitlabIncludeLocation": inc.source,
		"gitlabIncludeType":     inc.kind,
		"nested":                object.get(inc, "nested", false),
		"componentName":         object.get(inc, "componentName", ""),
		"originHash":            object.get(inc, "originHash", 0),
	}
```

In `policies/ref_confusion.rego`, in the **second** finding block only (the one
under `inc := input.pipeline.includes[i]`), remove the `"job"` line and add
`"includePath"`:

```rego
	finding := {
		"code":                  "ISSUE-402",
		"severity":              "medium",
		"message":               sprintf("%s pins ref '%s' — it resolves as both a tag AND a branch in the source project, so which revision runs is ambiguous; pin to a commit SHA to disambiguate", [inc.source, inc.ref]),
		# No "job": an include is not a job. includePath names what this finding
		# is about (finding/identity). componentName stays as payload.
		"includePath":           inc.source,
		"file":                  object.get(inc, "originFile", ""),
		"line":                  object.get(inc, "originLine", 0),
		"version":               inc.ref,
		"gitlabIncludeLocation": inc.source,
		"gitlabIncludeType":     inc.kind,
		"nested":                object.get(inc, "nested", false),
		"componentName":         object.get(inc, "componentName", ""),
		"originHash":            object.get(inc, "originHash", 0),
	}
```

Leave the message text exactly as it is, including its em dash: it is existing
user-facing copy and rewording it would re-key nothing here (identity no longer
reads the message) but would churn the report for no reason.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./policies/ -run 'TestIssue40[234]' -v`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add policies/ref_confusion.rego policies/includes_outdated.rego policies/includes_forbidden_version.rego policies/rules_test.go
git commit -m "fix(policies): identify include findings by the include path

ISSUE-402's GitLab block, ISSUE-403 and ISSUE-404 are about an include,
not a job. They now emit includePath and leave job empty. ISSUE-402 and
ISSUE-403 had no working structured key at all: componentName is empty
for any include that is not a component, so their identity rode on the
prose message.

Refs #403"
```

---

### Task 5: Required actions (ISSUE-417)

**Files:**
- Modify: `policies/required_actions.rego`
- Test: `policies/rules_test.go`, `TestIssue416_RequiredActionMissing` (starts at
  line 4789; the name says 416 but the code it asserts is ISSUE-417). Every
  ISSUE-417 assertion lives in this one table-driven test, at lines 4820, 4852,
  4879, 4903, 4929 and 4947. Only two of them read `f.Job`.

**Interfaces:**
- Consumes: `assertNoJob` (Task 2), `requiredAction` in the priority list
  (Task 1).
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

In `TestIssue416_RequiredActionMissing`, the first subtest collects hits by job
(line 4821). Replace that collection so it reads the structured key:

```go
				requiredAction, _ := f.Data["requiredAction"].(string)
				hits[requiredAction] = true
```

The `want` list on line 4832 already holds the three expected values and does
not change: `"myorg/sast-scan"`, `"myorg/policy/.github/workflows/policy.yml"`,
`"myorg/full-security"`.

At line 4903, replace the job comparison:

```go
			if f.Code == "ISSUE-417" && f.Data["requiredAction"] == "myorg/sast-scan" {
```

Then add to the end of the first subtest:

```go
		assertSubjectKey(t, findings, "ISSUE-417", "requiredAction", []string{
			"myorg/sast-scan",
			"myorg/policy/.github/workflows/policy.yml",
			"myorg/full-security",
		})
		assertNoJob(t, findings, "ISSUE-417")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./policies/ -run TestIssue417 -v`
Expected: FAIL with `identity subject is "message"=...` and
`job = "org/sast-scan", want empty`.

- [ ] **Step 3: Update the rule**

In `policies/required_actions.rego`, replace the finding object with:

```rego
	finding := {
		"code":     "ISSUE-417",
		"severity": "high",
		"message":  sprintf("required action or reusable workflow %q is not referenced by any workflow (group %d)", [required, i]),
		# No "job": a missing required action is not a job. requiredAction names
		# what this finding is about and is what the identity recipe selects
		# (finding/identity). groupIndex stays as payload: it moves whenever the
		# user reorders requiredGroups, which is not a new finding.
		"requiredAction": required,
		"required":       required,
		"groupIndex":     i,
	}
```

`required` is kept as payload for consumers already reading it; only
`requiredAction` participates in identity.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./policies/ -run TestIssue417 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add policies/required_actions.rego policies/rules_test.go
git commit -m "fix(policies): identify required-action findings by the action

ISSUE-417 is about a required action or reusable workflow, not a job. It
emitted a required key that was never in the subject-key list, so its
identity rode on the prose message including the group index.

Refs #403"
```

---

### Task 6: Branch family (ISSUE-501, ISSUE-505) and the branch aggregation

**Files:**
- Modify: `policies/branch_unprotected.rego`
- Modify: `policies/branch_non_compliant.rego`
- Modify: `cmd/legacy_json.go` (the `nonCompliantBranches` loop, around line 539)
- Test: `policies/rules_test.go` (the ISSUE-501 and ISSUE-505 assertions that key
  on `f.Job`), `cmd/legacy_json_test.go`

**Interfaces:**
- Consumes: `assertNoJob` (Task 2), `branchName` already first-class in the
  priority list.
- Produces: nothing new.

This is the one task with a load-bearing consumer. `cmd/legacy_json.go` builds
`nonCompliantBranches` by keying on `f.Job`; with `job` empty every branch would
key on `""` and no branch would receive the full protection-settings shape.

- [ ] **Step 1: Write the failing test for the aggregation**

In `cmd/legacy_json_test.go`, add:

```go
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
```

Note: `cmd` has no test that builds the branch block itself, so this helper is
the automated guard for the aggregation. The block-level shape is verified in
Task 7 against the real GitLab project, which produces ISSUE-505 findings.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/ -run TestBranchProtectionBlockMatchesNonCompliantBranchByPayload -v`
Expected: FAIL to compile, `undefined: nonCompliantBranchNames`.

- [ ] **Step 3: Extract and fix the aggregation**

In `cmd/legacy_json.go`, replace the inline loop:

```go
		nonCompliantBranches := map[string]bool{}
		for _, f := range findings {
			if f.Code == string(control.CodeBranchNonCompliant) {
				nonCompliantBranches[f.Job] = true
			}
		}
```

with a call to a named helper, and add the helper next to
`buildBranchProtectionBlock`:

```go
		nonCompliantBranches := nonCompliantBranchNames(findings)
```

```go
// nonCompliantBranchNames collects the branches that fired ISSUE-505, read from
// the finding's branchName payload. Not from Finding.Job: that field is a CI job
// name, and a branch is not a job, so branch rules leave it empty.
func nonCompliantBranchNames(findings []opaengine.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if f.Code != string(control.CodeBranchNonCompliant) {
			continue
		}
		if name, ok := f.Data["branchName"].(string); ok && name != "" {
			out[name] = true
		}
	}
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./cmd/ -run TestBranchProtectionBlockMatchesNonCompliantBranchByPayload -v`
Expected: PASS.

- [ ] **Step 5: Write the failing rule tests**

In `policies/rules_test.go`, in the ISSUE-505 test, replace the three lines that
key on `f.Job` (`issue505ByJob[f.Job]`, the duplicate check, and
`hits[f.Job] = true`) with a payload read:

```go
			branch, _ := f.Data["branchName"].(string)
			if issue505ByJob[branch].Code != "" {
				t.Fatalf("expected at most one ISSUE-505 per branch, got duplicate for %q", branch)
			}
			issue505ByJob[branch] = f
			hits[branch] = true
```

In the ISSUE-501 test, replace the `f.Job != "feature"` assertion with:

```go
			if name, _ := f.Data["branchName"].(string); name != "feature" {
				t.Fatalf("ISSUE-501 should target the unprotected branch, got %q", name)
			}
```

Then append `assertNoJob` to both tests:

```go
	assertNoJob(t, findings, "ISSUE-501")
```

```go
	assertNoJob(t, findings, "ISSUE-505")
```

- [ ] **Step 6: Run the tests to verify they fail**

Run: `go test ./policies/ -run 'TestIssue50[15]' -v`
Expected: FAIL with `job = "feature", want empty` and `job = "main", want empty`.

- [ ] **Step 7: Update the rules**

In `policies/branch_unprotected.rego`, remove the `"job"` line:

```rego
	finding := {
		"code":     "ISSUE-501",
		"severity": "critical",
		"message":  sprintf("branch %q must be protected", [branch.name]),
		# No "job": a branch is not a job. branchName names what this finding is
		# about and is what the identity recipe selects (finding/identity).
		"type":       "unprotected",
		"branchName": branch.name,
	}
```

In `policies/branch_non_compliant.rego`, remove the `"job"` line and leave every
other key untouched:

```rego
	finding := {
		"code":     "ISSUE-505",
		"severity": "high",
		"message":  sprintf("Branch '%s' has non-compliant protection settings", [branch.name]),
		# No "job": a branch is not a job. branchName names what this finding is
		# about and is what the identity recipe selects (finding/identity).
		"type":                          "non_compliant",
		"branchName":                    branch.name,
		"reasons":                       reasons,
		"allowForcePush":                object.get(branch, "allowForcePush", false),
		"allowForcePushDisplay":         object.get(branch, "allowForcePush", false),
		"minMergeAccessLevel":           object.get(branch, "minMergeAccessLevel", 0),
		"authorizedMinMergeAccessLevel": object.get(input.config.branchMustBeProtected, "minMergeAccessLevel", 0),
		"minPushAccessLevel":            object.get(branch, "minPushAccessLevel", 0),
		"authorizedMinPushAccessLevel":  object.get(input.config.branchMustBeProtected, "minPushAccessLevel", 0),
	}
```

- [ ] **Step 8: Run the whole suite**

Run: `make test`
Expected: PASS. `cmd` covers the branch block; if a JSON fixture there asserts
the old shape, the aggregation fix is what keeps it correct, so a failure here
means the helper is not wired in.

- [ ] **Step 9: Commit**

```bash
git add policies/branch_unprotected.rego policies/branch_non_compliant.rego policies/rules_test.go cmd/legacy_json.go cmd/legacy_json_test.go
git commit -m "fix(policies): stop putting a branch name in the job field

ISSUE-501 and ISSUE-505 are about a branch, not a job; branchName already
carries their identity. The JSON branch block matched non-compliant
branches through Finding.Job, so it now reads branchName from the payload
instead, behind a named helper with its own test.

Refs #403"
```

---

### Task 7: Documentation, the JSON contract test, and end-to-end verification

**Files:**
- Modify: `docs/FINGERPRINT.md`
- Modify: `cmd/csv.go` (the `context` column comment, around line 41)
- Test: `cmd/legacy_json_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1 to 6.
- Produces: nothing.

- [ ] **Step 1: Write the failing JSON contract test**

In `cmd/legacy_json_test.go`, add:

```go
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
```

- [ ] **Step 2: Run the test**

Run: `go test ./cmd/ -run TestProjectFindingOmitsJobForANonJobFinding -v`
Expected: PASS immediately, because `projectFinding` already guards on
`f.Job != ""`. This test is a contract pin, not a driver. Confirm it can fail by
temporarily changing the guard to `if jobKey != ""`, re-running (expect FAIL),
then restoring it.

- [ ] **Step 3: Update the CSV column comment**

In `cmd/csv.go`, replace the paragraph describing the `context` column:

```go
// The "context" column is Finding.Job: the CI job a finding sits in, or empty
// when the finding is not about a job (a branch, an include, a required
// template or component). Those findings carry what they are about in their
// structured payload and in the identity block of the JSON report.
```

- [ ] **Step 4: Update docs/FINGERPRINT.md**

Replace the subject-key priority table with the new order and drop the
`componentName` row:

| Priority | Key | Example value |
| --- | --- | --- |
| 1 | `uses` | `grafana/shared-workflows/actions/get-vault-secrets@main` |
| 2 | `branchName` | `main` |
| 3 | `includePath` | `gitlab.example.com/components/sast/sast` |
| 4 | `templatePath` | `templates/go/go` |
| 5 | `componentPath` | `components/sast/sast` |
| 6 | `requiredAction` | `org/sast-scan` |
| 7 | `image` | `golang:1.25` (a Dockerfile `FROM` base) |
| 8 | `serviceImage` | `docker:27-dind` |
| 9 | `link` | `registry.gitlab.com/security-products/secrets:7` |
| 10 | `tag` | `latest` |
| 11 | `variableName` | `CI_DEBUG_TRACE` |
| 12 | `hardcodedJob` | `deploy-prod` |
| 13 | `scriptLine` | `curl -sSL https://example.com/i.sh \| bash` |
| 14 | `detail` | `allow_failure: true masks scan failures` |

Update the same list inside the ASCII path diagram in the "The paths" section.

Extend the RecipeVersion 2 history row so it names the whole set:

```markdown
| 2 | Ten finding blocks that had no structured key, or that smuggled their subject through the `job` field, now name what they are about: ISSUE-401 (`hardcodedJob`), ISSUE-402 GitLab / ISSUE-403 / ISSUE-404 (`includePath`), ISSUE-405 / ISSUE-406 (`templatePath`), ISSUE-408 / ISSUE-409 (`componentPath`), ISSUE-417 (`requiredAction`), and ISSUE-501 / ISSUE-505 keep `branchName` while dropping `job`. The algorithm is unchanged; their fingerprints are not. |
```

Add a short subsection under "Inputs" stating what `job` means:

```markdown
### The job segment

`job` is the name of a CI job. It is empty when the finding is not about a job:
a branch, an include, a required template, component or action. Those findings
identify on their subject key instead. Before recipe version 2 several rules
put a branch name, an include source or a required path in this field, which
made identity depend on a mislabelled value.
```

- [ ] **Step 5: Run the full verification**

```bash
make test
make lint
make deadcode
```

Expected: all green.

- [ ] **Step 6: End-to-end comparison against real projects**

Rebuild and re-run the comparison used earlier in PR #404, over the six GitHub
repositories and the GitLab instance. Confirm that:
- no finding outside the ten blocks changes its fingerprint,
- the ten do change, exactly once,
- ISSUE-505 findings still produce the full protection shape in the JSON
  branch block.

- [ ] **Step 7: Commit**

```bash
git add docs/FINGERPRINT.md cmd/csv.go cmd/legacy_json_test.go
git commit -m "docs(fingerprint): record that job means a job

Documents the reordered subject-key list, what the job segment means and
when it is empty, and extends the recipe version 2 history to the full set
of blocks that moved.

Refs #403"
```

---

## Final step: squash

Once every task is complete and verified, rebase on `origin/main` and squash the
branch into a single commit, as agreed on PR #404. Fold the design spec and this
plan into that commit or drop them from the branch, depending on whether the
maintainer wants the process artifacts carried in the PR.
