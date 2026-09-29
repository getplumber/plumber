# zizmor parity for the GitHub analysis, implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `plumber analyze` on a GitHub repository report everything zizmor 1.30.1 reports, on the same inputs, with the same severity tiers, so a zizmor user loses nothing by switching.

**Architecture:** Four waves. Wave 1 widens the inputs and the one rule that is structurally behind (local action definitions and service images enter the IR; template injection becomes a context classifier). Wave 2 promotes the nineteen benched controls that already carry a Rego rule, fixtures, docs and an identity declaration, by adding the six wires each is missing. Wave 3 adds the seven audits with no Plumber counterpart as new controls. Wave 4 adds the opt-in knobs that reproduce zizmor's stricter defaults on the controls where Plumber's default is deliberately narrower. A wave 0 task first makes the catalog say which controls actually run.

**Tech Stack:** Go 1.25, cobra, logrus, OPA Rego (`internal/engine/opa`), `go:embed` policies, golangci-lint v2.10.1 (`make lint`), `make deadcode`, `make test`, semantic-release (CHANGELOG generated, never edited).

**Spec:** `docs/superpowers/specs/2026-09-29-zizmor-parity.md` (the audit-by-audit mapping, the design decisions, the comparison numbers).

## Global Constraints

- Public repository: no AI mention anywhere except the two commit trailer lines; commit messages and doc prose read as the maintainer's.
- TDD: the failing test first, RED recorded in the task report. `make lint` reports 0 issues; `make deadcode` reports only the pre-existing entries; `make test` green before every commit.
- Tests: `go test ./<pkg>/ -count=1` per package, foreground, explicit 600000 ms tool timeout for anything over 120 s; never background runs. The Rego rules are tested through `policies/rules_test.go` with fixtures under `policies/testdata/ISSUE-XXX/github/`, scanned by `githubpkg.ScanGitHubWorkflowsWithProgress` and evaluated by `evaluateStrict`, exactly as `TestIssue418` does today.
- Conventional commits (feat/fix/docs/test/refactor, scope = package), header at most 100 chars, lowercase first token after the type, body says why. At most five commits per PR (one per task group), each PR must pass the both-modes e2e (`plumber analyze` on a GitLab checkout and on a GitHub checkout) before it is marked ready.
- The finding bytes the platform hashes (`Finding.MarshalJSON` in `internal/engine/opa/engine.go`) never change for existing codes; a new identity field is added only through `finding/identity/declarations.go` and its parity test.
- Every new issue code lands in `control/codes.go` inside its numeric block (2xx variables and scripts, 4xx composition, 7xx third-party actions, 8xx triggers and permissions, 9xx repository hygiene), with a row in `docs/GITHUB_ISSUES.md` and an entry in `getplumber.io/src/data/issues.ts` (separate PR on that repo, opened by the same task, linked in the task report).
- Default enablement follows the spec's persona rule: zizmor regular audits ship `enabled: true`, auditor and pedantic audits ship `enabled: false` with a comment naming the persona.
- Exit codes and the `--no-controls` artifact contract do not change.

---

## Wave 0: the catalog tells the truth

### Task 0.1: `plumber catalog` carries a `status` field and config validation names benched controls

**Files:**
- Modify: `configuration/registry.go` (the `IsBenched(provider, name)` helper near line 741 already exists; export a `BenchedFor(provider) []string` next to it)
- Modify: `cmd/catalog.go` (the `plumber catalog` JSON writer; add `Status string \`json:"status"\`` to the entry struct it serialises)
- Modify: `configuration/plumberconfig.go` (`ValidateKnownKeys`, the "Unknown control in github.controls" message)
- Test: `configuration/registry_test.go`, `cmd/catalog_test.go`, `configuration/plumberconfig_test.go`

**Interfaces:**
- Produces: `configuration.BenchedFor(provider string) []string` (sorted names) and the catalog entry field `status` with the closed set `"shipping" | "benched"`. Later tasks remove names from the bench map and assert `status` flips to `shipping`.

- [ ] **Step 1: Write the failing tests**

```go
// configuration/registry_test.go
func TestBenchedFor_GitHubListsTheBenchMap(t *testing.T) {
	got := BenchedFor(ProviderGitHub)
	if len(got) == 0 {
		t.Fatal("expected at least one benched GitHub control on this tree")
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("BenchedFor must be sorted, got %v", got)
	}
	for _, n := range got {
		if !IsBenched(ProviderGitHub, n) {
			t.Fatalf("%s listed but IsBenched says no", n)
		}
	}
}

// cmd/catalog_test.go
func TestCatalogDocument_StatusFollowsTheBench(t *testing.T) {
	doc := buildCatalogDocument() // the builder behind `plumber catalog` in cmd/catalog.go; use its existing name
	seen := map[string]bool{}
	for _, e := range doc.Controls {
		seen[e.Status] = true
		want := "shipping"
		if configuration.IsBenched(configuration.ProviderGitHub, e.Name) && len(e.Providers) == 1 && e.Providers[0] == "github" {
			want = "benched"
		}
		if e.Status != want {
			t.Fatalf("%s: status %q, want %q", e.Name, e.Status, want)
		}
	}
	if !seen["shipping"] || !seen["benched"] {
		t.Fatalf("expected both statuses on this tree, saw %v", seen)
	}
}

// configuration/plumberconfig_test.go
func TestValidateKnownKeys_NamesBenchedControls(t *testing.T) {
	yamlDoc := "version: \"2.0\"\ngithub:\n  controls:\n    workflowsMustDeclareConcurrency:\n      enabled: true\n"
	_, _, warnings, err := LoadPlumberConfigFromBytes([]byte(yamlDoc), "test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "benched") || strings.Contains(joined, "Unknown control") {
		t.Fatalf("want a 'known but benched' warning, got:\n%s", joined)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./configuration/ ./cmd/ -run 'TestBenchedFor_GitHubListsTheBenchMap|TestCatalogDocument_StatusFollowsTheBench|TestValidateKnownKeys_NamesBenchedControls' -count=1`
Expected: FAIL, `undefined: BenchedFor`, `e.Status undefined`, and the warning text mismatch.

- [ ] **Step 3: Implement**

```go
// configuration/registry.go, after IsBenched
// BenchedFor returns the sorted control names benched for provider.
func BenchedFor(provider string) []string {
	m := benchedControls[provider]
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
```

In `cmd/catalog.go`, add `Status string \`json:"status"\`` to the entry struct and set it while building each entry:

```go
status := "shipping"
if len(meta.Providers) == 1 && configuration.IsBenched(meta.Providers[0], name) {
	status = "benched"
}
entry.Status = status
```

In `configuration/plumberconfig.go` (`ValidateKnownKeys`), before the "Unknown control" branch:

```go
if IsBenched(provider, name) {
	warnings = append(warnings, fmt.Sprintf("Control %q in %s.controls is known but benched in this release: it is not evaluated yet", name, provider))
	continue
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: the same command as step 2. Expected: PASS. Then `make lint` and `make test`.

- [ ] **Step 5: Commit**

```bash
git add configuration/registry.go configuration/registry_test.go cmd/catalog.go cmd/catalog_test.go configuration/plumberconfig.go configuration/plumberconfig_test.go
git commit -m "feat(catalog): status says whether a control ships, benched names are known"
```

---

## Wave 1: inputs and the injection classifier

### Task 1.1: `services:` images and `uses: docker://` step images enter the IR on GitHub

**Files:**
- Modify: `github/github_workflows.go:511-513` (job section parse, next to the `container:` call) and the step walker used by `extractGitHubRunScripts`
- Modify: `internal/ir/pipeline.go` (`Job.Services` exists; add `Job.StepImages []Image \`json:"stepImages,omitempty"\`` with a comment naming `uses: docker://` as the source)
- Modify: `policies/image_mutable_tag.rego`, `policies/image_pinned_by_digest.rego` (iterate `job.services[_]` and `job.stepImages[_]` beside `job.image`)
- Modify: `pbom/generate_github.go` (services and step images join `containerImages[]`, `jobs[]` lists them)
- Test: `github/github_workflows_test.go`, `policies/rules_test.go`, `pbom/generate_github_test.go`, fixtures `policies/testdata/ISSUE-102/github/violation_service_untagged.yml`, `policies/testdata/ISSUE-103/github/violation_docker_uses_tag.yml`, `policies/testdata/ISSUE-103/github/clean_service_digest.yml`

**Interfaces:**
- Consumes: `parseGitHubContainer(v any) (ir.Image, bool)`, `splitImageRef(ref string) ir.Image`.
- Produces: `ir.Job.Services` populated on GitHub, `ir.Job.StepImages` (new), and the Rego rules' finding field `imageRole: "container" | "service" | "step"`.

- [ ] **Step 1: Write the failing collector test**

```go
// github/github_workflows_test.go
func TestScan_ServicesAndDockerUsesBecomeImages(t *testing.T) {
	tmp := t.TempDir()
	wf := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `on: push
jobs:
  it:
    runs-on: ubuntu-latest
    services:
      nginx:
        image: nginx
      db:
        image: postgres:17@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    steps:
      - uses: docker://ghcr.io/wolfi-dev/sdk:latest
      - run: echo hi
`
	if err := os.WriteFile(filepath.Join(wf, "it.yml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	job := p.Jobs[0]
	if len(job.Services) != 2 || job.Services[0].Name != "nginx" || job.Services[0].Tag != "" || job.Services[1].Digest == "" {
		t.Fatalf("services not collected: %+v", job.Services)
	}
	if len(job.StepImages) != 1 || job.StepImages[0].Registry != "ghcr.io" || job.StepImages[0].Tag != "latest" {
		t.Fatalf("docker:// step image not collected: %+v", job.StepImages)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./github/ -run TestScan_ServicesAndDockerUsesBecomeImages -count=1`
Expected: FAIL, `job.StepImages undefined` (compile) then, after adding the field, services empty.

- [ ] **Step 3: Implement the collector**

```go
// internal/ir/pipeline.go, in Job after Services
// StepImages are the `uses: docker://<ref>` step images of the job,
// populated by github/github_workflows.go; empty on GitLab and for jobs
// whose steps reference no docker:// image.
StepImages []Image `json:"stepImages,omitempty"`
```

```go
// github/github_workflows.go, right after the container: block (line ~513)
if svcs, ok := ghCastStringMap(section["services"]); ok {
	names := make([]string, 0, len(svcs))
	for name := range svcs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if img, ok := parseGitHubContainer(svcs[name]); ok {
			job.Services = append(job.Services, img)
		}
	}
}
job.StepImages = extractGitHubDockerUses(section["steps"])
```

```go
// github/github_workflows.go, new helper next to extractGitHubRunScripts
// extractGitHubDockerUses returns one Image per `uses: docker://<ref>`
// step, in step order.
func extractGitHubDockerUses(steps any) []ir.Image {
	list, ok := steps.([]any)
	if !ok {
		return nil
	}
	var out []ir.Image
	for _, s := range list {
		m, ok := ghCastStringMap(s)
		if !ok {
			continue
		}
		uses, _ := m["uses"].(string)
		if rest, ok := strings.CutPrefix(uses, "docker://"); ok {
			out = append(out, splitImageRef(rest))
		}
	}
	return out
}
```

- [ ] **Step 4: Run the collector test, then write the failing rule tests**

Run: `go test ./github/ -run TestScan_ServicesAndDockerUsesBecomeImages -count=1`. Expected: PASS.

Fixtures:

```yaml
# policies/testdata/ISSUE-102/github/violation_service_untagged.yml
on: push
jobs:
  it:
    runs-on: ubuntu-latest
    services:
      nginx:
        image: nginx
    steps:
      - run: echo hi
```

```yaml
# policies/testdata/ISSUE-103/github/violation_docker_uses_tag.yml
on: push
jobs:
  it:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://ghcr.io/wolfi-dev/sdk:latest
```

```yaml
# policies/testdata/ISSUE-103/github/clean_service_digest.yml
on: push
jobs:
  it:
    runs-on: ubuntu-latest
    services:
      db:
        image: postgres:17@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    steps:
      - run: echo hi
```

```go
// policies/rules_test.go, a new table test in the ISSUE-102/103 family
func TestIssue102And103_ServicesAndStepImages(t *testing.T) {
	engine := newTestEngine(t)
	cases := []struct {
		code, fixture string
		want         int
	}{
		{"ISSUE-102", "violation_service_untagged.yml", 1},
		{"ISSUE-103", "violation_docker_uses_tag.yml", 1},
		{"ISSUE-103", "clean_service_digest.yml", 0},
	}
	for _, tc := range cases {
		t.Run(tc.code+"/"+tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join("testdata", tc.code, "github", tc.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := githubpkg.ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, imageConfigForTest())
			if err != nil {
				t.Fatal(err)
			}
			hits := 0
			for _, f := range findings {
				if f.Code == tc.code {
					hits++
				}
			}
			if hits != tc.want {
				t.Fatalf("%s: expected %d, got %d", tc.fixture, tc.want, hits)
			}
		})
	}
}
```

`newTestEngine` and `imageConfigForTest` are the helpers the existing ISSUE-102/103 tests in `rules_test.go` already use (the config enables `containerImageMustNotUseForbiddenTags` with `forbiddenTags: [latest]` and `pinByDigest: true`); reuse them under their existing names.

- [ ] **Step 5: Run the rule tests to verify they fail**

Run: `go test ./policies/ -run TestIssue102And103_ServicesAndStepImages -count=1`
Expected: FAIL, 0 findings on the two violation fixtures.

- [ ] **Step 6: Extend the two rules**

```rego
# policies/image_mutable_tag.rego: replace the single `job.image` iteration with
_images_of(job) := [i |
	i := {"img": job.image, "role": "container"}
	job.image
] | [i |
	svc := job.services[_]
	i := {"img": svc, "role": "service"}
] | [i |
	st := job.stepImages[_]
	i := {"img": st, "role": "step"}
]

deny contains finding if {
	job := input.pipeline.jobs[_]
	entry := _images_of(job)[_]
	img := entry.img
	not img.unresolved
	tag := _effective_tag(img)
	_is_forbidden(tag)
	finding := {
		"code":     "ISSUE-102",
		"severity": "high",
		"message":  sprintf("Job `%s` uses the forbidden tag `%s` of %s image `%s`.", [job.name, tag, entry.role, _full_ref(img)]),
		"job":      job.name,
		"link":     _full_ref(img),
		"imageRole": entry.role,
		"imageRepo": _image_repo(img),
	}
}

# An image with no tag and no digest resolves to `latest` at runtime.
_effective_tag(img) := img.tag if img.tag != ""
_effective_tag(img) := "latest" if {
	img.tag == ""
	img.digest == ""
}
```

Apply the same `_images_of` iteration and `imageRole` field to `policies/image_pinned_by_digest.rego` (its `deny` keeps its `ISSUE-103` code and `pinByDigest` gate). Add `"imageRole"` to both codes' entries in `finding/identity/declarations.go` only if the identity must separate a service from the container of the same job: it must (one job can carry `node:20` as container and as a service), so append `"imageRole"` to the `ISSUE-102` and `ISSUE-103` field lists and run `go test ./finding/... -count=1`.

- [ ] **Step 7: Run the rule tests, then the PBOM**

Run: `go test ./policies/ -run TestIssue102And103_ServicesAndStepImages -count=1`. Expected: PASS.

In `pbom/generate_github.go`, where jobs are walked for `job.Image`, walk `job.Services` and `job.StepImages` too, producing `ContainerImage` entries whose `Jobs` list names the job. Extend `pbom/generate_github_test.go` with a workflow carrying one service and one `docker://` step and assert `summary.totalImages == 3`. Run `go test ./pbom/ -count=1`.

- [ ] **Step 8: Docs and commit**

Add to `docs/PBOM.md` (provider table, GitHub row): "`container:`, `services:` and `uses: docker://` images across all jobs". Add a line to `docs/GITHUB_ISSUES.md` under ISSUE-102 and ISSUE-103: "Service containers and `docker://` step images are covered; an untagged image counts as `latest`."

```bash
git add internal/ir/pipeline.go github/github_workflows.go github/github_workflows_test.go policies/image_mutable_tag.rego policies/image_pinned_by_digest.rego policies/rules_test.go policies/testdata/ISSUE-102 policies/testdata/ISSUE-103 finding/identity/declarations.go pbom/generate_github.go pbom/generate_github_test.go docs/PBOM.md docs/GITHUB_ISSUES.md
git commit -m "feat(github): service containers and docker:// step images join the inventory and the image rules"
```

### Task 1.2: local action definitions are analysis inputs

**Files:**
- Create: `github/github_actions_local.go` (walks `.github/actions/**/action.yml|action.yaml` and every `uses: ./<path>` target reachable from a workflow, parses `runs:` composite steps into IR jobs)
- Modify: `internal/ir/pipeline.go` (`Job.Kind string \`json:"kind,omitempty"\`` with values `"workflow"` (default, omitted) and `"action"`; `Job.ActionPath string`)
- Modify: `github/github_workflows.go` (the scan entry point calls the new walker after the workflow loop; the step parser is reused for composite `steps:`)
- Modify: `control/github_stats.go` (`ActionsTotal int` counted and shown beside `WorkflowsTotal`)
- Modify: `cmd/render_details.go` (the "Workflows Scanned" stat line gains "Local actions scanned")
- Test: `github/github_actions_local_test.go`, `policies/rules_test.go` (one existing rule, ISSUE-209, gains an `action.yml` fixture), fixture `policies/testdata/ISSUE-209/github/actions/py-env/action.yml`

**Interfaces:**
- Produces: IR jobs with `Kind == "action"`, `Name == "<action dir>/<runs.name or 'composite'>"`, `WorkflowName == ""`, `File == "<action.yml path>"`, and the same `Scripts`, `Uses`, `Env`, `Shell` fields workflow jobs carry, so every rule that reads `input.pipeline.jobs[_]` covers actions with no change. Rules that must stay workflow-only (permissions, concurrency, triggers, explicit name) add `not job.kind == "action"` (Task 1.2 step 6 lists them).

- [ ] **Step 1: Write the failing walker test**

```go
// github/github_actions_local_test.go
func TestScan_LocalCompositeActionsBecomeActionJobs(t *testing.T) {
	tmp := t.TempDir()
	actDir := filepath.Join(tmp, ".github", "actions", "py-env")
	if err := os.MkdirAll(actDir, 0o755); err != nil {
		t.Fatal(err)
	}
	action := `name: Python env
runs:
  using: composite
  steps:
    - uses: actions/setup-python@v5
    - shell: python
      run: |
        import os
        with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write("X=${{ github.event.issue.title }}\n")
`
	if err := os.WriteFile(filepath.Join(actDir, "action.yml"), []byte(action), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, _, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	var action1 *ir.Job
	for i := range p.Jobs {
		if p.Jobs[i].Kind == "action" {
			action1 = &p.Jobs[i]
		}
	}
	if action1 == nil {
		t.Fatal("no action job collected")
	}
	if action1.ActionPath != ".github/actions/py-env" || len(action1.Uses) != 1 || len(action1.Scripts) != 1 || !strings.Contains(action1.Scripts[0], "GITHUB_ENV") {
		t.Fatalf("action job incomplete: %+v", *action1)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./github/ -run TestScan_LocalCompositeActionsBecomeActionJobs -count=1`
Expected: FAIL, `p.Jobs[i].Kind undefined`.

- [ ] **Step 3: Implement**

```go
// internal/ir/pipeline.go, in Job
// Kind is "" for a workflow job and "action" for a local action
// definition (.github/actions/**/action.yml or a `uses: ./path`
// target) parsed by github/github_actions_local.go. Rules that only
// make sense on workflows exclude action jobs explicitly.
Kind string `json:"kind,omitempty"`
// ActionPath is the repository-relative directory of the action
// definition an action job came from; empty for workflow jobs.
ActionPath string `json:"actionPath,omitempty"`
```

```go
// github/github_actions_local.go
package github

// scanLocalActions parses every local action definition into an IR job
// of kind "action". It walks .github/actions/** and, in addition, every
// `uses: ./<path>` target the workflow jobs reference, so an action kept
// outside .github/actions is still covered. A definition that is not
// composite (docker or node) still yields a job carrying its `runs:`
// image or entrypoint so inventory rules see it; only composite
// definitions carry steps.
func scanLocalActions(repoRoot string, workflowJobs []ir.Job) ([]ir.Job, error) {
	dirs := map[string]struct{}{}
	root := filepath.Join(repoRoot, ".github", "actions")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if base := d.Name(); base == "action.yml" || base == "action.yaml" {
			dirs[filepath.Dir(p)] = struct{}{}
		}
		return nil
	})
	for _, j := range workflowJobs {
		for _, u := range j.Uses {
			if rest, ok := strings.CutPrefix(u.Uses, "./"); ok {
				dirs[filepath.Join(repoRoot, filepath.Clean(rest))] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(dirs))
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	var out []ir.Job
	for _, dir := range names {
		job, ok, err := parseLocalAction(repoRoot, dir)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, job)
		}
	}
	return out, nil
}

// parseLocalAction builds one action job from dir/action.yml (or
// action.yaml). The composite `runs.steps` list goes through the same
// step parsers the workflow collector uses, so uses/run/shell/env land
// in the same IR fields.
func parseLocalAction(repoRoot, dir string) (ir.Job, bool, error) {
	var path string
	for _, base := range []string{"action.yml", "action.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, base)); err == nil {
			path = filepath.Join(dir, base)
			break
		}
	}
	if path == "" {
		return ir.Job{}, false, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ir.Job{}, false, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return ir.Job{}, false, fmt.Errorf("%s: %w", path, err)
	}
	rel, _ := filepath.Rel(repoRoot, dir)
	relFile, _ := filepath.Rel(repoRoot, path)
	name, _ := doc["name"].(string)
	if name == "" {
		name = "composite"
	}
	job := ir.Job{
		Name:       rel + "/" + name,
		Kind:       "action",
		ActionPath: filepath.ToSlash(rel),
		OriginFile: filepath.ToSlash(relFile),
		OriginKind: "action",
	}
	runs, _ := ghCastStringMap(doc["runs"])
	switch using, _ := runs["using"].(string); using {
	case "composite":
		job.Uses = extractGitHubUses(runs["steps"])
		job.Scripts = extractGitHubRunScripts(runs["steps"])
		job.Steps = extractGitHubSteps(runs["steps"])
		job.StepImages = extractGitHubDockerUses(runs["steps"])
	case "docker":
		if img, ok := runs["image"].(string); ok {
			if rest, ok := strings.CutPrefix(img, "docker://"); ok {
				i := splitImageRef(rest)
				job.Image = &i
			}
		}
	}
	return job, true, nil
}
```

Wire it at the end of the scan entry point in `github/github_workflows.go`, after the workflow loop and before the pipeline is returned:

```go
actionJobs, err := scanLocalActions(repoRoot, pipeline.Jobs)
if err != nil {
	return nil, nil, err
}
pipeline.Jobs = append(pipeline.Jobs, actionJobs...)
```

`extractGitHubUses` (line 741) and `extractGitHubRunScripts` (line 820) are the existing step walkers; `extractGitHubSteps` is introduced by Task 1.3 (do Task 1.3 step 4 first if this task lands earlier, or leave `job.Steps` unset until it does). `OriginFile` and `OriginKind` are the fields the location linker and `anonymous_definition.rego` already read.

- [ ] **Step 4: Run the walker test**

Run: `go test ./github/ -run TestScan_LocalCompositeActionsBecomeActionJobs -count=1`. Expected: PASS.

- [ ] **Step 5: Write the failing rule test (an action fixture for ISSUE-209)**

Fixture `policies/testdata/ISSUE-209/github/actions/py-env/action.yml` with the same content as the test above. In `policies/rules_test.go`, extend the existing ISSUE-209 table (`TestIssue209_GitHubEnvInjection` or its current name) with a case whose fixture is copied under `.github/actions/py-env/action.yml` instead of `.github/workflows/`, `wantCount: 1`. The copy helper is the same `os.MkdirAll` and `os.WriteFile` pair the table already uses, with the destination `filepath.Join(tmp, ".github", "actions", "py-env", "action.yml")`.

Run: `go test ./policies/ -run TestIssue209 -count=1`. Expected: FAIL, 0 findings (the rule reads `job.scripts`, but the fixture was never a job before Task 1.2; after step 3 it is, so this step may already pass: if it does, record that and move on).

- [ ] **Step 6: Exclude action jobs from workflow-only rules**

Add `not job.kind == "action"` to the `deny` bodies of: `undocumented_permissions.rego` (801), `excessive_permissions.rego` (803), `missing_concurrency.rego` (418), `anonymous_definition.rego` (422), `dangerous_triggers.rego` (802), `pull_request_target_head_checkout.rego` (804), `secrets_inherit.rego` (302), `cache_poisoning.rego` (705), `secrets_outside_env.rego` (305), `use_trusted_publishing.rego` (421). Every other rule keeps covering action jobs, which is zizmor's "Workflow, Action" input type.

Run: `go test ./policies/ -count=1`. Expected: PASS, and no existing fixture count changes.

- [ ] **Step 7: Stats, terminal, docs, commit**

`control/github_stats.go`: count `ActionsTotal` (jobs with `Kind == "action"`) and exclude them from `WorkflowsTotal` and `JobsTotal`. `cmd/render_details.go`: add `{Label: "Local actions scanned", Value: fmt.Sprintf("%d", stats.ActionsTotal)}` to the summary block that prints "Workflows Scanned". `README.md` (GitHub section) and `docs/GITHUB_ISSUES.md` (intro): one sentence, "Local action definitions under `.github/actions/` and any `uses: ./path` target are analysed like workflow jobs."

```bash
git add internal/ir/pipeline.go github/github_actions_local.go github/github_actions_local_test.go github/github_workflows.go policies/ control/github_stats.go control/types.go cmd/render_details.go README.md docs/GITHUB_ISSUES.md
git commit -m "feat(github): local action definitions are analysed like workflow jobs"
```

### Task 1.3: template injection becomes a context classifier

**Files:**
- Create: `policies/data/context_capabilities.csv` (copied from zizmor `crates/zizmor/data/context-capabilities.csv`, 4082 rows, MIT licence header kept), `policies/data/gen.go` (`//go:generate` turns the CSV into `context_capabilities_gen.go`, a `map[string]string` of `context -> "arbitrary" | "structured" | "fixed"`, glob rows such as `github.event.inputs.*` kept as-is)
- Modify: `internal/engine/opa/engine.go:474-491` (`buildInput` adds `"data": {"contextCapabilities": <map>}` and the workflow's `workflow_dispatch` input types under each job as `job.dispatchInputs`)
- Modify: `github/github_workflows.go` (collect `on.workflow_dispatch.inputs.<name>.type` and `options` into `ir.Job.DispatchInputs map[string]string` with values `string | choice | boolean | number | environment`)
- Modify: `internal/ir/pipeline.go` (`Job.DispatchInputs map[string]string`, and `Job.Steps []Step` where `Step{Name, Run, Shell string; Env map[string]string; Uses string}` is a new struct: today `Job.Scripts` is `[]string` and `extractGitHubStepEnvs` folds step envs into `Job.Variables`, which loses the per-step binding this rule needs; `Scripts` stays for the rules that read it)
- Rewrite: `policies/template_injection.rego` (keeps package name, code ISSUE-207, safe sinks `_safe_sink`, `_tojson_wrapped`, `_inside_quoted_heredoc`)
- Modify: `finding/identity/declarations.go` (`"ISSUE-207": {"file", "job", "step", "expression"}`)
- Test: `policies/rules_test.go`, fixtures under `policies/testdata/ISSUE-207/github/`

**Interfaces:**
- Consumes: `input.pipeline.jobs[_].steps[_]` with `run`, `shell`, `env`, `name`, `uses` (new, Task 1.3 step 4); the new `input.data.contextCapabilities`.
- Produces: one ISSUE-207 finding per `${{ }}` expression whose classification is `arbitrary` (severity `critical`, `confidence: high`) or `structured` (severity `high`, `confidence: high`) or unknown (severity `medium`, `confidence: low`). `fixed` contexts never fire. Finding fields: `job`, `step`, `expression`, `context`, `capability`, `confidence`.

- [ ] **Step 1: Write the failing classifier tests**

Fixtures (each one job, `on: workflow_dispatch` with `inputs: version: {type: string}`, `env: {type: choice, options: [a, b]}`, `verbose: {type: boolean}`):

```yaml
# policies/testdata/ISSUE-207/github/violation_actor_and_ref_name.yml
on: push
jobs:
  it:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "User: ${{ github.actor }}"
          echo "Ref: ${{ github.ref_name }}"
```
```yaml
# policies/testdata/ISSUE-207/github/violation_dispatch_string_input.yml
on:
  workflow_dispatch:
    inputs:
      version:
        type: string
      env:
        type: choice
        options: [staging, prod]
      verbose:
        type: boolean
jobs:
  it:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh ${{ inputs.version }} ${{ inputs.env }} ${{ inputs.verbose }}
```
```yaml
# policies/testdata/ISSUE-207/github/clean_fixed_contexts.yml
on: push
jobs:
  it:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event_name }} ${{ github.sha }} ${{ github.repository }} ${{ github.run_id }} ${{ github.triggering_actor }}"
```
```yaml
# policies/testdata/ISSUE-207/github/clean_env_binding.yml
on: issues
jobs:
  it:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
```
```yaml
# policies/testdata/ISSUE-207/github/violation_env_indirection.yml
on: issues
jobs:
  it:
    runs-on: ubuntu-latest
    env:
      T: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ env.T }}"
```
```yaml
# policies/testdata/ISSUE-207/github/violation_needs_output.yml
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      v: ${{ steps.s.outputs.v }}
    steps:
      - id: s
        run: echo "v=$(cat VERSION)" >> "$GITHUB_OUTPUT"
  b:
    needs: a
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ needs.a.outputs.v }}"
```

```go
// policies/rules_test.go
func TestIssue207_ContextClassifier(t *testing.T) {
	engine := newTestEngine(t)
	cases := []struct {
		fixture   string
		wantCount int
		wantSev   []string // severities in file order, empty when wantCount == 0
	}{
		{"violation_actor_and_ref_name.yml", 2, []string{"critical", "critical"}},
		{"violation_dispatch_string_input.yml", 1, []string{"critical"}},
		{"clean_fixed_contexts.yml", 0, nil},
		{"clean_env_binding.yml", 0, nil},
		{"violation_env_indirection.yml", 1, []string{"critical"}},
		{"violation_needs_output.yml", 1, []string{"medium"}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join("testdata", "ISSUE-207", "github", tc.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, tc.fixture), data, 0o644); err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := githubpkg.ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range findings {
				if f.Code == "ISSUE-207" {
					got = append(got, f.Severity)
				}
			}
			if len(got) != tc.wantCount {
				t.Fatalf("%s: expected %d findings, got %d (%v)", tc.fixture, tc.wantCount, len(got), got)
			}
			for i := range tc.wantSev {
				if got[i] != tc.wantSev[i] {
					t.Fatalf("%s: finding %d severity %q, want %q", tc.fixture, i, got[i], tc.wantSev[i])
				}
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./policies/ -run TestIssue207_ContextClassifier -count=1`
Expected: FAIL on `violation_actor_and_ref_name.yml` (0 findings today) and `violation_dispatch_string_input.yml`.

- [ ] **Step 3: Generate the capability table and feed it to the engine**

```go
// policies/data/gen.go
//go:generate go run ./internal/gencaps -in context_capabilities.csv -out context_capabilities_gen.go
package data
```

`policies/data/internal/gencaps/main.go` reads the CSV (`context,capability` per row, header skipped) and writes:

```go
// Code generated by gencaps; DO NOT EDIT.
package data

// ContextCapabilities maps a GitHub Actions expression context to how
// much of its expansion an attacker controls: "arbitrary" (free text),
// "structured" (attacker-influenced but constrained), "fixed" (never
// attacker-controlled). Glob rows such as "github.event.inputs.*"
// match any single trailing segment.
var ContextCapabilities = map[string]string{
	"github.action_path": "fixed",
	// ... 4082 rows
}
```

In `internal/engine/opa/engine.go` `buildInput`, add:

```go
"data": map[string]any{
	"contextCapabilities": data.ContextCapabilities,
},
```

- [ ] **Step 4: Collect `workflow_dispatch` input types and step env**

In `github/github_workflows.go`, while reading the `on:` block, capture `workflow_dispatch.inputs` into `wfCtx.dispatchInputs map[string]string` (value is the declared `type`, default `string`; `choice` when `options:` is present) and set `job.DispatchInputs = wfCtx.dispatchInputs` on every job of the workflow. Add the step list:

```go
// internal/ir/pipeline.go
// Step is one `steps:` entry of a GitHub job or composite action, kept
// with its own env so a rule can tell a value bound through env: from
// one interpolated into the script. Populated by github/github_workflows.go;
// empty on GitLab.
type Step struct {
	Name  string            `json:"name,omitempty"`
	Run   string            `json:"run,omitempty"`
	Shell string            `json:"shell,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
	Uses  string            `json:"uses,omitempty"`
}
```

`Job.Steps []Step \`json:"steps,omitempty"\`` and `Job.Env map[string]string \`json:"env,omitempty"\`` (the job-level `env:` alone, not the folded `Variables`). A new `extractGitHubSteps(v any) []ir.Step` next to `extractGitHubRunScripts` fills `Name` from `name:` (or `id:`, else the 1-based index as a string), `Run`, `Shell`, `Env` from the step's own `env:` (raw strings, `${{ }}` kept) and `Uses`; the job section parse sets `job.Steps` and `job.Env = normalizeGitHubEnv(section["env"])`.

- [ ] **Step 5: Rewrite the rule**

```rego
# policies/template_injection.rego
package template_injection

import rego.v1

# One finding per `${{ … }}` expression in a run: block whose context an
# attacker controls. The classification comes from
# input.data.contextCapabilities (zizmor's table) plus the heuristics
# below for inputs, env, matrix, needs and steps outputs.

deny contains finding if {
	job := input.pipeline.jobs[_]
	script := job.steps[si]
	script.run != ""
	lines := split(script.run, "\n")
	line := lines[li]
	expr := regex.find_all_string_submatch_n(`\$\{\{\s*([^}]*?)\s*\}\}`, line, -1)[_][1]
	not _safe_sink(lines, li, line)
	ctx := _head_context(expr)
	cap := _capability(job, script, ctx)
	cap != "fixed"
	cap != "safe"
	finding := {
		"code":       "ISSUE-207",
		"severity":   _severity(cap),
		"confidence": _confidence(cap),
		"message":    sprintf("Step `%s` of job `%s` expands `%s` (%s) inside a script.", [script.name, job.name, expr, cap]),
		"job":        job.name,
		"step":       script.name,
		"expression": expr,
		"context":    ctx,
		"capability": cap,
	}
}

_severity("arbitrary") := "critical"
_severity("structured") := "high"
_severity("unknown") := "medium"
_confidence("arbitrary") := "high"
_confidence("structured") := "high"
_confidence("unknown") := "low"

# The first dotted context of the expression, function calls stripped:
# `toJSON(github.event.issue)` -> github.event.issue.
_head_context(expr) := ctx if {
	m := regex.find_all_string_submatch_n(`([a-zA-Z_][\w-]*(?:\.[\w-]+|\[[^\]]*\])+)`, expr, 1)
	ctx := lower(m[0][1])
}

_capability(job, script, ctx) := "safe" if startswith(ctx, "secrets.")
_capability(job, script, ctx) := "fixed" if regex.match(`^(needs\.[^.]+\.result|steps\.[^.]+\.(outcome|conclusion))$`, ctx)
_capability(job, script, ctx) := _input_capability(job, ctx) if startswith(ctx, "inputs.")
_capability(job, script, ctx) := _input_capability(job, replace(ctx, "github.event.inputs.", "inputs.")) if startswith(ctx, "github.event.inputs.")
_capability(job, script, ctx) := _env_capability(job, script, ctx) if startswith(ctx, "env.")
_capability(job, script, ctx) := "unknown" if startswith(ctx, "matrix.")
_capability(job, script, ctx) := "unknown" if regex.match(`^(needs|steps)\.[^.]+\.outputs\.`, ctx)
_capability(job, script, ctx) := _table(ctx) if {
	not startswith(ctx, "inputs.")
	not startswith(ctx, "github.event.inputs.")
	not startswith(ctx, "env.")
	not startswith(ctx, "matrix.")
	not startswith(ctx, "secrets.")
	not regex.match(`^(needs|steps)\.`, ctx)
}

# Exact row first, then the longest glob row whose prefix matches.
_table(ctx) := input.data.contextCapabilities[ctx]
_table(ctx) := cap if {
	not input.data.contextCapabilities[ctx]
	globs := [k | some k, _ in input.data.contextCapabilities; endswith(k, ".*"); startswith(ctx, trim_suffix(k, "*"))]
	count(globs) > 0
	best := max_by_len(globs)
	cap := input.data.contextCapabilities[best]
}
_table(ctx) := "unknown" if {
	not input.data.contextCapabilities[ctx]
	count([k | some k, _ in input.data.contextCapabilities; endswith(k, ".*"); startswith(ctx, trim_suffix(k, "*"))]) == 0
}
max_by_len(xs) := best if {
	best := [x | x := xs[_]; count([y | y := xs[_]; count(y) > count(x)]) == 0][0]
}

# workflow_dispatch inputs: free text is arbitrary; choice, boolean,
# number and environment cannot carry a payload.
_input_capability(job, ctx) := "arbitrary" if {
	name := trim_prefix(ctx, "inputs.")
	job.dispatchInputs[name] == "string"
}
_input_capability(job, ctx) := "fixed" if {
	name := trim_prefix(ctx, "inputs.")
	job.dispatchInputs[name] != "string"
}
_input_capability(job, ctx) := "unknown" if {
	name := trim_prefix(ctx, "inputs.")
	not job.dispatchInputs[name]
}

# env.NAME resolves to its definition on the step or the job; the
# definition's own expression is classified in turn (one level, which
# is what GitHub evaluates).
_env_capability(job, script, ctx) := cap if {
	name := trim_prefix(ctx, "env.")
	def := object.get(script, ["env", name], object.get(job, ["env", name], ""))
	inner := regex.find_all_string_submatch_n(`\$\{\{\s*([^}]*?)\s*\}\}`, def, 1)
	count(inner) > 0
	cap := _table(_head_context(inner[0][1]))
}
_env_capability(job, script, ctx) := "fixed" if {
	name := trim_prefix(ctx, "env.")
	def := object.get(script, ["env", name], object.get(job, ["env", name], ""))
	count(regex.find_all_string_submatch_n(`\$\{\{`, def, 1)) == 0
}

# Safe sinks kept from the previous rule: a value bound through env: and
# read as $VAR is not an injection, and a toJSON(...) value inside a
# quoted heredoc body is data.
_safe_sink(lines, li, line) if {
	_tojson_wrapped(line)
	_inside_quoted_heredoc(lines, li)
}
```

Keep the existing `_tojson_wrapped`, `_inside_quoted_heredoc`, `_heredoc_open_word`, `_heredoc_close` and `_closed_between` helper bodies verbatim from the current file. Delete `unsafe_patterns` and `_matches_unsafe`.

Note for the implementer: `github.actor`, `github.ref_name`, `github.head_ref` and `github.ref` are not rows of zizmor's CSV; zizmor classifies them in code. Add them to the generated map by appending four rows to `policies/data/context_capabilities.csv` under a `# plumber additions` comment the generator skips: `github.actor,arbitrary`, `github.triggering_actor,fixed` (already present, keep the CSV's value), `github.ref_name,arbitrary`, `github.head_ref,arbitrary`, `github.ref,structured`, `github.base_ref,structured`.

- [ ] **Step 6: Run the classifier tests and the existing 207 tests**

Run: `go test ./policies/ -run 'TestIssue207' -count=1`. Expected: PASS for the new table; the existing ISSUE-207 fixtures now report one finding per expression, so update their `wantCount` values to the new per-expression counts (each fixture's expected count is the number of `${{` occurrences in its run blocks whose context is not fixed; record the old and new numbers in the task report).

Update `finding/identity/declarations.go`: `"ISSUE-207": {"file", "job", "step", "expression"}` and run `go test ./finding/... -count=1`.

- [ ] **Step 7: Wires that show the new fields, docs, commit**

`cmd/legacy_json_github.go` `buildTemplateInjectionBlock`: `projectFindings(findings, "step")` and copy `expression`, `context`, `capability`, `confidence` into each issue (extend `projectFindings` to pass through those four keys when present). `cmd/render_details.go`: the ISSUE-207 detail line prints `expression` and `capability`. `docs/GITHUB_ISSUES.md` ISSUE-207 section: replace the pattern list with the three capability tiers and the `inputs`, `env`, `matrix`, `needs`, `steps` heuristics, and say a finding is per expression. `README.md`: nothing.

```bash
go generate ./policies/data/
git add policies/data policies/template_injection.rego policies/rules_test.go policies/testdata/ISSUE-207 internal/engine/opa/engine.go github/github_workflows.go internal/ir/pipeline.go finding/identity/declarations.go cmd/legacy_json_github.go cmd/legacy_json.go cmd/render_details.go docs/GITHUB_ISSUES.md
git commit -m "feat(policies): template injection classifies every expression by context capability"
```

---

## Wave 2: promote the nineteen benched controls

Every control below already has: a Rego rule under `policies/`, at least three fixtures under `policies/testdata/ISSUE-XXX/github/`, a `rules_test.go` table, a `control/codes.go` entry, a `docs/GITHUB_ISSUES.md` section and a provisional identity declaration. Each is missing the same six wires, so each task has the same eight steps with the control's own names. The names are fixed here so every task can be implemented and reviewed alone.

| Task | Control name | Code | Config field | YAML key | Display name | JSON key | Default | zizmor persona |
|---|---|---|---|---|---|---|---|---|
| 2.1 | workflowsMustDeclareConcurrency | 418 | WorkflowsMustDeclareConcurrency | workflowsMustDeclareConcurrency | Workflows must declare concurrency | concurrencyResult | false | auditor |
| 2.2 | workflowMustNotContainObfuscation | 420 | WorkflowMustNotContainObfuscation | workflowMustNotContainObfuscation | Workflows must not contain obfuscation | obfuscationResult | true | regular |
| 2.3 | workflowsMustHaveExplicitName | 422 | WorkflowsMustHaveExplicitName | workflowsMustHaveExplicitName | Workflows must have an explicit name | explicitNameResult | false | auditor |
| 2.4 | workflowMustNotTrustSpoofableActorChecks | 210 | WorkflowMustNotTrustSpoofableActorChecks | workflowMustNotTrustSpoofableActorChecks | Workflows must not trust spoofable actor checks | botConditionsResult | true | regular |
| 2.5 | githubAppTokensMustBeRevokedOnExit | 306 | GithubAppTokensMustBeRevokedOnExit | githubAppTokensMustBeRevokedOnExit | GitHub App tokens must be revoked on exit | githubAppResult | true | regular |
| 2.6 | workflowMustNotReEnableInsecureCommands | 208 | WorkflowMustNotReEnableInsecureCommands | workflowMustNotReEnableInsecureCommands | Workflows must not re-enable insecure commands | insecureCommandsResult | true | regular |
| 2.7 | workflowMustNotUseKnownMisfeatures | 419 | WorkflowMustNotUseKnownMisfeatures | workflowMustNotUseKnownMisfeatures | Workflows must not use known misfeatures | misfeatureResult | true | regular |
| 2.8 | workflowMustPinPackageInstalls | 214 | WorkflowMustPinPackageInstalls | workflowMustPinPackageInstalls | Workflows must pin package installs | adhocPackagesResult | true | regular |
| 2.9 | workflowMustNotUnredactSecretsViaFromJSON | 303 | WorkflowMustNotUnredactSecretsViaFromJSON | workflowMustNotUnredactSecretsViaFromJSON | Workflows must not unredact secrets via fromJSON | unredactedSecretsResult | true | regular |
| 2.10 | workflowConditionsMustBeSound | 211 | WorkflowConditionsMustBeSound | workflowConditionsMustBeSound | Workflow conditions must be sound | unsoundConditionResult | true | regular |
| 2.11 | workflowContainsCallsMustBeSound | 212 | WorkflowContainsCallsMustBeSound | workflowContainsCallsMustBeSound | Workflow contains() calls must be sound | unsoundContainsResult | true | regular |
| 2.12 | publishWorkflowsMustUseOidcTrustedPublishing | 421 | PublishWorkflowsMustUseOidcTrustedPublishing | publishWorkflowsMustUseOidcTrustedPublishing | Publish workflows must use OIDC trusted publishing | trustedPublishingResult | true | regular |
| 2.13 | containerCredentialsMustComeFromSecrets | 704 | ContainerCredentialsMustComeFromSecrets | containerCredentialsMustComeFromSecrets | Container credentials must come from secrets | containerCredentialsResult | true | regular |
| 2.14 | dependabotMustNotAllowInsecureExternalCodeExecution | 901 | DependabotMustNotAllowInsecureExternalCodeExecution | dependabotMustNotAllowInsecureExternalCodeExecution | Dependabot must not allow insecure external code execution | dependabotExecutionResult | true | regular |
| 2.15 | dependabotEcosystemsMustHaveCooldown | 902 | DependabotEcosystemsMustHaveCooldown | dependabotEcosystemsMustHaveCooldown | Dependabot ecosystems must have a cooldown | dependabotCooldownResult | true | regular |
| 2.16 | deployJobsMustUseEnvironmentGate | 305 | DeployJobsMustUseEnvironmentGate | deployJobsMustUseEnvironmentGate | Deploy jobs must use an environment gate | secretsOutsideEnvResult | false | auditor |
| 2.17 | actionPinCommentsMustMatchSha | 708 | ActionPinCommentsMustMatchSha | actionPinCommentsMustMatchSha | Action pin comments must match the pinned SHA | refVersionMismatchResult | false | auditor |
| 2.18 | actionPinsMustNotBeStale | 709 | ActionPinsMustNotBeStale | actionPinsMustNotBeStale | Action pins must not be stale | staleActionRefsResult | false | auditor |
| 2.19 | actionsMustNotDuplicateRunnerBuiltins | 711 | ActionsMustNotDuplicateRunnerBuiltins | actionsMustNotDuplicateRunnerBuiltins | Actions must not duplicate runner built-ins | superfluousActionsResult | false | auditor |

Tasks 2.17, 2.18 and 2.19 read `uses[*].metadata` (the API enrichment); their names stay in `actionMetadataConsumers` (they already are) and their tests use the metadata stub the `TestIssue702` table already uses.

### Task 2.1: promote workflowsMustDeclareConcurrency (ISSUE-418)

**Files:**
- Modify: `configuration/plumberconfig.go` (`ControlsConfig` struct near line 408; `validControlSchema` map near line 29)
- Modify: `configuration/schema_docs.go` (near line 283)
- Modify: `control/catalog.go` (`GitHubControls`, after the `workflowsMustDeclarePermissions` entry at line 244)
- Modify: `control/types.go:275` (`GitHubAnalysisStats`), `control/github_stats.go:198`
- Modify: `cmd/legacy_json_github.go:54` (the control-name switch) and a new `buildConcurrencyBlock`
- Modify: `cmd/render_details.go:707` (stat lines switch)
- Modify: `defaultConfig/.plumber.yaml:1086` and `.plumber.yaml:880` (self-scan), `cmd/init.go:1463`
- Modify: `configuration/registry.go:684` (delete the bench line), `finding/identity/declarations.go:170` (drop the "benched" note)
- Test: `configuration/plumberconfig_test.go`, `control/catalog_test.go`, `cmd/legacy_json_github_test.go`, `cmd/analyze_github_e2e_test.go` (new file)

**Interfaces:**
- Produces: `ControlsConfig.WorkflowsMustDeclareConcurrency *EnabledOnlyControlConfig`, `GitHubAnalysisStats.WorkflowsMissingConcurrency int`, JSON block `concurrencyResult` with `metrics.workflowsTotal` and `metrics.workflowsMissingConcurrency`.

- [ ] **Step 1: Write the failing tests**

```go
// configuration/plumberconfig_test.go
func TestWorkflowsMustDeclareConcurrency_IsAKnownControl(t *testing.T) {
	yamlDoc := "version: \"2.0\"\ngithub:\n  controls:\n    workflowsMustDeclareConcurrency:\n      enabled: true\n"
	pc, _, warnings, err := LoadPlumberConfigFromBytes([]byte(yamlDoc), "test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	c := pc.ControlsFor("github").WorkflowsMustDeclareConcurrency
	if c == nil || !c.IsEnabled() {
		t.Fatal("control not parsed as enabled")
	}
}

// control/catalog_test.go
func TestGitHubControls_ListsConcurrency(t *testing.T) {
	pc := &configuration.PlumberConfig{}
	for _, e := range GitHubControls(pc) {
		if e.ControlName == "workflowsMustDeclareConcurrency" {
			if !e.Skipped {
				t.Fatal("absent config must read Skipped")
			}
			return
		}
	}
	t.Fatal("workflowsMustDeclareConcurrency missing from the GitHub catalog")
}

// cmd/analyze_github_e2e_test.go
// TestAnalyzeGitHub_Issue418ReachesJSON runs the real analysis on a temp
// repository carrying the ISSUE-418 violation fixture with the control
// enabled and asserts the finding lands in the JSON output block.
func TestAnalyzeGitHub_Issue418ReachesJSON(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "policies", "testdata", "ISSUE-418", "github", "violation_no_concurrency.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "version: \"2.0\"\nextends: plumber:default\ngithub:\n  controls:\n    workflowsMustDeclareConcurrency:\n      enabled: true\n"
	cfgPath := filepath.Join(tmp, ".plumber.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "out.json")
	root := newRootCommandForTest(t)
	root.SetArgs([]string{"analyze", "--config", cfgPath, "--output", out, "--print=false", "--repo-path", tmp, "--offline"})
	_ = root.Execute() // exit status is the gate, not the assertion
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no JSON written: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	block, ok := doc["concurrencyResult"].(map[string]any)
	if !ok {
		t.Fatalf("concurrencyResult block missing; keys: %v", keysOf(doc))
	}
	issues, _ := block["issues"].([]any)
	if len(issues) != 1 {
		t.Fatalf("expected 1 ISSUE-418 issue, got %d", len(issues))
	}
}
```

`newRootCommandForTest` and `keysOf` are small helpers to add in the same test file if the `cmd` package does not already expose a root-command constructor for tests (`newRootCommandForTest` returns `NewRootCmd()` or whatever the existing `main.go` calls; `keysOf` returns the sorted keys of a map). `--repo-path` and `--offline` are the existing analyze flags for pointing at a checkout and skipping API enrichment; if their names differ in the tree, use the tree's names.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./configuration/ ./control/ ./cmd/ -run 'TestWorkflowsMustDeclareConcurrency_IsAKnownControl|TestGitHubControls_ListsConcurrency|TestAnalyzeGitHub_Issue418ReachesJSON' -count=1`
Expected: FAIL (compile error on the missing field, catalog entry missing, block missing).

- [ ] **Step 3: Config field, schema, docs**

```go
// configuration/plumberconfig.go, in ControlsConfig after WorkflowsMustDeclarePermissions
// WorkflowsMustDeclareConcurrency control configuration (GitHub Actions only).
// Config-free; toggle via `enabled`. Off by default: zizmor ships it under
// its auditor persona only.
WorkflowsMustDeclareConcurrency *EnabledOnlyControlConfig `yaml:"workflowsMustDeclareConcurrency,omitempty"`
```
```go
// configuration/plumberconfig.go, validControlSchema
"workflowsMustDeclareConcurrency": {
	"enabled",
},
```
```go
// configuration/schema_docs.go
"workflowsMustDeclareConcurrency.enabled": {
	Description: "Turns the control on; when false or absent the control is skipped.",
},
```

- [ ] **Step 4: Catalog, stats, JSON, terminal**

```go
// control/catalog.go, GitHubControls, after the workflowsMustDeclarePermissions entry
entries = append(entries, ControlEntry{
	DisplayName: "Workflows must declare concurrency",
	ControlName: "workflowsMustDeclareConcurrency",
	Skipped:     c.WorkflowsMustDeclareConcurrency == nil || !c.WorkflowsMustDeclareConcurrency.IsEnabled(),
})
```
```go
// control/types.go, GitHubAnalysisStats, after WorkflowsMissingPermissions
WorkflowsMissingConcurrency int
```
```go
// control/github_stats.go, in the workflow-set loop that fills workflowsWithPermissions
if job.WorkflowHasConcurrency || job.JobHasConcurrency {
	workflowsWithConcurrency[wf] = struct{}{}
}
// after line 198
stats.WorkflowsMissingConcurrency = stats.WorkflowsTotal - len(workflowsWithConcurrency)
if stats.WorkflowsMissingConcurrency < 0 {
	stats.WorkflowsMissingConcurrency = 0
}
```
(declare `workflowsWithConcurrency := map[string]struct{}{}` next to `workflowsWithPermissions`).

```go
// cmd/legacy_json_github.go, in the control-name switch
case "workflowsMustDeclareConcurrency":
	return "concurrencyResult", buildConcurrencyBlock(common, result, findings)

// buildConcurrencyBlock is ISSUE-418. Denominator is total workflows;
// numerator is workflows with neither a workflow-level nor a job-level
// concurrency block.
func buildConcurrencyBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "file"),
		"metrics": map[string]any{
			"workflowsTotal":              s.WorkflowsTotal,
			"workflowsMissingConcurrency": s.WorkflowsMissingConcurrency,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}
```
```go
// cmd/render_details.go, stat-lines switch, after the workflowsMustDeclarePermissions case
case "workflowsMustDeclareConcurrency":
	return []statLine{
		{Label: "Total Workflows", Value: fmt.Sprintf("%d", stats.WorkflowsTotal)},
		{Label: "Missing concurrency block", Value: fmt.Sprintf("%d", stats.WorkflowsMissingConcurrency)},
	}
```

- [ ] **Step 5: Default config, self-scan config, wizard, bench removal**

```yaml
# defaultConfig/.plumber.yaml, github.controls, after workflowsMustDeclarePermissions
    # Concurrent runs of one workflow on one ref race on caches, artifacts
    # and deploy state. Off by default (zizmor: auditor persona); turn on
    # for deploy-heavy repositories.
    workflowsMustDeclareConcurrency:
      enabled: false
```
Same block in `.plumber.yaml` (the self-scan) with `enabled: true` (this repository declares concurrency everywhere; if the self-scan drops below 100 points, fix the workflow, never the config). In `cmd/init.go` next to line 1463: `gh.Controls.WorkflowsMustDeclareConcurrency = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(false)}`. Delete the `"workflowsMustDeclareConcurrency": {},` line from `benchedControls` in `configuration/registry.go`. In `finding/identity/declarations.go` line 170, replace the "(benched, not yet live: declaration provisional, revisit on unbench)" wording with "keyed on the workflow file: one finding per workflow" after confirming the rule emits `file` only.

- [ ] **Step 6: Run the tests to verify they pass**

Run: the step 2 command, then `go test ./policies/ -run TestIssue418 -count=1`, then `make lint`, `make deadcode`, `make test`, and the self-scan `go run . analyze --print=false` at the repository root must still report 100 points.

- [ ] **Step 7: Website docs**

Open a PR on `getplumber/getplumber.io` adding ISSUE-418 to `src/data/issues.ts` (GitHub sub-block: title "Workflow has no concurrency block", severity medium, the description and remediation copied from `control/codes.go`), and link it in this task's report.

- [ ] **Step 8: Commit**

```bash
git add configuration/ control/ cmd/ defaultConfig/.plumber.yaml .plumber.yaml finding/identity/declarations.go
git commit -m "feat(controls): workflowsMustDeclareConcurrency ships on github (issue 418)"
```

### Tasks 2.2 to 2.19: promote the remaining eighteen

Each task repeats Task 2.1's eight steps with the row's names from the table above. The differences are written out here so no task depends on reading another.

- **Step 1 tests**: the three tests of Task 2.1 with the config field, YAML key, JSON key and fixture path substituted. The e2e fixture for each is the row's first `violation_*.yml` under `policies/testdata/ISSUE-<code>/github/` (for 901 and 902 the fixture is a `.github/dependabot.yml`, copied to that path in the temp repository instead of a workflow; for 704 it is a workflow with `container: {image: x, credentials: {username: u, password: hunter2}}`).
- **Step 3**: `ControlsConfig` field of type `*EnabledOnlyControlConfig` with the row's YAML key; `validControlSchema` row `{"enabled"}`; `schema_docs.go` row `"<yamlKey>.enabled"`. Two controls take configuration and use their existing config type instead of `EnabledOnlyControlConfig`: `workflowMustPinPackageInstalls` (`*PackageInstallsControlConfig` with `managers []string`, default `[pip, npm, gem, cargo, go, apt, brew]`; schema row lists `enabled, managers`) and `actionsMustNotDuplicateRunnerBuiltins` (`*SuperfluousActionsControlConfig` with `runnerImages []string`, default `[ubuntu-latest, ubuntu-24.04, ubuntu-22.04]`; schema row `enabled, runnerImages`). Both types already exist in `plumberconfig.go` under those names; if a type is absent, add it with exactly those fields.
- **Step 4**: catalog entry with the row's display name; JSON block function named `build<JSONKey without "Result">Block` returning `issues: projectFindings(findings, "<key>")` where `<key>` is the rule's identity key (`"file"` for 418 and 422; `"job"` for 210, 208, 303, 211, 212, 421, 704, 305; `"step"` for 420, 419, 214, 306; `"uses"` for 708, 709, 711; `"ecosystem"` for 901, 902) and `metrics` carrying `jobsTotal` (or `workflowsTotal` for file-keyed rules, `actionRefsTotal` for uses-keyed rules, `ecosystemsTotal` for Dependabot rules); terminal stat lines: `{Label: statJobsChecked, Value: jobsTotal}` and `{Label: "Findings", Value: findingsCount}` (the `findingsCount` variable the second switch in `render_details.go` at line 1009 already computes).
- **Step 5**: default config block with a two-line comment (the first sentence of the code's `Description` in `control/codes.go`, then "Off by default (zizmor: auditor persona)" when the row's default is false); the self-scan `.plumber.yaml` block always `enabled: true`; wizard line; bench line deleted; declaration note revised.
- **Step 6**: same commands; the self-scan must stay at 100 points. Where a promoted control fires on this repository's own workflows, fix the workflow in the same task (for example 214 will flag an unpinned `pip install` in `.github/workflows/ci.yml` if one exists: pin it).
- **Step 7**: website PR per code.
- **Step 8**: commit `feat(controls): <controlName> ships on github (issue <code>)`. Group the commits into at most five PRs: {2.1, 2.2, 2.3, 2.4}, {2.5, 2.6, 2.7, 2.8}, {2.9, 2.10, 2.11, 2.12}, {2.13, 2.14, 2.15, 2.16}, {2.17, 2.18, 2.19}.

After 2.19 the `benchedControls[ProviderGitHub]` map contains only the seven cross-provider GitLab-only names plus 213, 215, 308, 706, 712, 903, 904, 905; add a test in `configuration/registry_test.go` pinning exactly that list so a regression re-benching a shipped control fails the build:

```go
func TestBenchedGitHub_IsExactlyTheDeferredSet(t *testing.T) {
	want := []string{
		"containerImageMustComeFromAuthorizedSources", "dockerfilesMustPinBaseImageByDigest",
		"includesMustBeUpToDate", "includesMustNotUseForbiddenVersions",
		"pipelineMustIncludeComponent", "pipelineMustIncludeTemplate",
		"pipelineMustNotIncludeHardcodedJobs", "pipelineMustNotOverrideJobVariables",
		"pipelineMustNotUseUnsafeVariableExpansion", "releaseWorkflowsMustSignArtefacts",
		"repositoriesMustConfigureDependencyUpdates", "repositoriesMustPublishSecurityPolicy",
		"repositoriesMustRunSAST", "workflowMustNotExportEntireGitHubContext",
		"workflowMustNotIndexSecretsDynamically", "workflowMustNotInjectVarsInScripts",
	}
	got := BenchedFor(ProviderGitHub)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("benched GitHub set drifted:\n got %v\nwant %v", got, want)
	}
}
```

---

## Wave 3: the seven audits with no Plumber counterpart

Each task is a full new control: rule, fixtures, codes, identity, config, catalog, JSON, terminal, default config, wizard, docs. The step shape is the one `CONTRIBUTING.md` "Adding a New Control" prescribes; the concrete values are below.

### Task 3.1: self-repository refs (ISSUE-423, workflowsMustUseSelfRepositorySyntax)

**Files:**
- Create: `policies/self_repository.rego`, `policies/testdata/ISSUE-423/github/{violation_same_repo_action.yml,violation_same_repo_reusable.yml,clean_self_syntax.yml,clean_other_repo.yml}`
- Modify: `control/codes.go` (`CodeSelfRepositoryRef ErrorCode = "ISSUE-423"`, entry with `ControlName: "workflowsMustUseSelfRepositorySyntax"`, severity low), `finding/identity/declarations.go` (`"ISSUE-423": {"file", "job", "uses", "step"}`), `configuration/plumberconfig.go`, `configuration/schema_docs.go`, `configuration/registry.go` (`controlsMeta` entry: Providers github, Category "Pipeline Composition", ID "CTRL-423", DisplayName "Workflows must use the self-repository syntax", Description "Verifies that in-repository actions and reusable workflows are referenced with GitHub's self-repository syntax instead of the repository's own slug and a ref, which re-resolves the ref at run time and can diverge from the commit being built."), `control/catalog.go`, `cmd/legacy_json_github.go` (`selfRepositoryResult`), `cmd/render_details.go`, `defaultConfig/.plumber.yaml` (`enabled: true`), `.plumber.yaml`, `cmd/init.go`, `docs/GITHUB_ISSUES.md`
- Test: `policies/rules_test.go` (`TestIssue423_SelfRepository`)

**Interfaces:**
- Consumes: `input.pipeline.jobs[_].uses[_]` with `uses` (the raw `owner/repo/path@ref` string), `name` (the step name) and `line`; `input.pipeline.jobs[_].reusableWorkflowUses` (the job-level `uses:` of a reusable-workflow call); `input.pipeline.projectPath` (the `owner/repo` of the analysed checkout).
- Produces: one finding per reference whose slug (the text before `@`) starts with `input.pipeline.projectPath` and does not start with `./` or `self/`.

- [ ] **Step 1: Fixtures and failing test**

```yaml
# violation_same_repo_action.yml
on: push
jobs:
  it:
    runs-on: ubuntu-latest
    steps:
      - uses: owner/repo/.github/actions/setup@main
```
```yaml
# violation_same_repo_reusable.yml
on: push
jobs:
  it:
    uses: owner/repo/.github/workflows/reusable.yml@v1
```
```yaml
# clean_self_syntax.yml
on: push
jobs:
  it:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/setup
      - uses: self/.github/actions/setup
```
```yaml
# clean_other_repo.yml
on: push
jobs:
  it:
    runs-on: ubuntu-latest
    steps:
      - uses: other/repo/.github/actions/setup@v1
```

The test is the `TestIssue418` table shape with `ISSUE-423`, fixtures and counts `{2? no: 1, 1, 0, 0}` (one finding per fixture's single same-repo reference). The scan call passes `"owner/repo"` as the project path, which is what makes the first two fixtures violations.

- [ ] **Step 2: Run to verify it fails** (`go test ./policies/ -run TestIssue423 -count=1`: FAIL, 0 findings).

- [ ] **Step 3: The rule**

```rego
package self_repository

import rego.v1

_self_ref(ref) if {
	not startswith(ref, "./")
	not startswith(ref, "self/")
	not startswith(ref, "docker://")
	slug := split(ref, "@")[0]
	startswith(lower(slug), lower(input.pipeline.projectPath))
}

deny contains finding if {
	job := input.pipeline.jobs[_]
	u := job.uses[_]
	_self_ref(u.uses)
	finding := {
		"code":     "ISSUE-423",
		"severity": "low",
		"message":  sprintf("Job `%s` references its own repository as `%s`; use the self-repository syntax so the ref never diverges from the commit under test.", [job.name, u.uses]),
		"job":      job.name,
		"step":     u.name,
		"uses":     u.uses,
		"line":     object.get(u, "line", 0),
	}
}

deny contains finding if {
	job := input.pipeline.jobs[_]
	job.reusableWorkflowUses != ""
	_self_ref(job.reusableWorkflowUses)
	finding := {
		"code":     "ISSUE-423",
		"severity": "low",
		"message":  sprintf("Job `%s` calls its own reusable workflow as `%s`; use the self-repository syntax.", [job.name, job.reusableWorkflowUses]),
		"job":      job.name,
		"step":     "",
		"uses":     job.reusableWorkflowUses,
	}
}
```

The second body covers `jobs.<id>.uses` reusable-workflow calls, which the collector stores on `job.reusableWorkflowUses`.

- [ ] **Step 4: Run to verify it passes**, then the wires of Task 2.1 steps 3 to 5 with the names above (JSON block keyed on `"uses"`, stat lines `Action refs checked` and `Self-repository refs`), the identity declaration, the docs section in `docs/GITHUB_ISSUES.md` (title, why it matters, remediation "replace `owner/repo/path@ref` with `./path` for actions and `self/path` for reusable workflows"), and the website PR.

- [ ] **Step 5: Commit** `feat(controls): flag self-repository references that bypass the self syntax (issue 423)`.

### Task 3.2: typosquatted action slugs (ISSUE-718, actionsMustNotBeTyposquats)

**Files:** as Task 3.1 with `policies/typosquat_uses.rego`, `policies/data/well_known_actions.go` (a Go slice of 150 well-known `owner/repo` slugs, copied from zizmor's `crates/zizmor/data/` list, MIT header kept, exposed through `buildInput` as `input.data.wellKnownActions`), fixtures `ISSUE-718/github/{violation_actions_checkout_typo.yml,violation_owner_swap.yml,clean_exact.yml,clean_unrelated.yml}`, code entry severity high, `ControlName: "actionsMustNotBeTyposquats"`, identity `{"file", "job", "uses", "step"}`, config `EnabledOnlyControlConfig`, default `enabled: true`, JSON `typosquatResult`.

- [ ] **Step 1: Fixtures and failing test** (`uses: actions/chekout@v4` and `uses: action/checkout@v4` are violations; `actions/checkout@v4` and `myorg/deploy@v1` are clean; counts 1, 1, 0, 0).

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: The rule** (Rego has no edit distance built-in; the rule flags a slug that is not in the list but whose owner or repo is within one insertion, deletion or substitution of a listed slug's owner or repo, computed with a small recursive `_lev1` over the two strings limited to length difference at most one, or equals a listed slug with the owner replaced):

```rego
package typosquat_uses

import rego.v1

deny contains finding if {
	job := input.pipeline.jobs[_]
	u := job.uses[_]
	not startswith(u.uses, "./")
	not startswith(u.uses, "docker://")
	slug := lower(_slug(split(u.uses, "@")[0]))
	not _known(slug)
	known := input.data.wellKnownActions[_]
	_close(slug, lower(known))
	finding := {
		"code":     "ISSUE-718",
		"severity": "high",
		"message":  sprintf("Job `%s` uses `%s`, one edit away from the well-known `%s`.", [job.name, u.uses, known]),
		"job":      job.name,
		"step":     u.name,
		"uses":     u.uses,
		"line":     object.get(u, "line", 0),
		"lookalike": known,
	}
}

_slug(loc) := concat("/", array.slice(split(loc, "/"), 0, 2))
_known(slug) if input.data.wellKnownActions[_] == slug

_close(a, b) if {
	pa := split(a, "/"); pb := split(b, "/")
	pa[1] == pb[1]
	_edit1(pa[0], pb[0])
}
_close(a, b) if {
	pa := split(a, "/"); pb := split(b, "/")
	pa[0] == pb[0]
	_edit1(pa[1], pb[1])
}

# _edit1 is true when a and b differ by exactly one insertion, deletion
# or substitution (a != b is implied by the callers' not _known guard).
_edit1(a, b) if {
	count(a) == count(b)
	count([i | some i; a[i] != b[i]]) == 1
}
_edit1(a, b) if {
	count(a) == count(b) + 1
	some i
	concat("", [substring(a, 0, i), substring(a, i + 1, -1)]) == b
}
_edit1(a, b) if {
	count(b) == count(a) + 1
	some i
	concat("", [substring(b, 0, i), substring(b, i + 1, -1)]) == a
}
```

- [ ] **Step 4: Run to verify it passes**, wires as Task 2.1 steps 3 to 5 with these names, docs (`docs/GITHUB_ISSUES.md`: "Typosquatting relies on slugs one keystroke away from an action everybody trusts; the finding names the lookalike"), website PR.

- [ ] **Step 5: Commit** `feat(controls): flag action slugs one edit away from a well-known action (issue 718)`.

### Task 3.3: actions that install unpinned tools (ISSUE-719, actionsMustNotInstallUnpinnedTools)

**Files:** `policies/unpinned_tools.rego`, `policies/data/unpinned_tools.go` (table of `{slug, versionInput}` pairs exposed as `input.data.unpinnedTools`: `astral-sh/setup-uv` `version`, `pnpm/action-setup` `version`, `ruby/setup-ruby` `bundler`, `golangci/golangci-lint-action` `version`, `dtolnay/rust-toolchain` `toolchain`, `pypa/hatch` `version`, `oven-sh/setup-bun` `bun-version`, `denoland/setup-deno` `deno-version`, `mozilla-actions/sccache-action` `version`, `taiki-e/install-action` `tool`, `jaxxstorm/action-install-gh-release` `tag`, `sigstore/cosign-installer` `cosign-release`, `anchore/sbom-action/download-syft` `syft-version`; copy the rest from zizmor's `unpinned_tools.rs` table), fixtures `ISSUE-719/github/{violation_setup_uv_no_version.yml,violation_pnpm_latest.yml,clean_setup_uv_pinned.yml,clean_unlisted_action.yml}`, code severity medium, `ControlName: "actionsMustNotInstallUnpinnedTools"`, identity `{"file", "job", "uses", "step"}`, default `enabled: true`, JSON `unpinnedToolsResult`.

- [ ] **Step 1: Fixtures and failing test** (`uses: astral-sh/setup-uv@v5` with no `with.version` and `pnpm/action-setup@v4` with `version: latest` are violations; `setup-uv` with `version: "0.5.9"` and `actions/setup-node@v4` are clean; counts 1, 1, 0, 0). The step `with:` map is already on the IR as `uses[*].with` (`ir.Action.With map[string]any`); the rule reads `u.with`.

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: The rule**

```rego
package unpinned_tools

import rego.v1

deny contains finding if {
	job := input.pipeline.jobs[_]
	u := job.uses[_]
	tool := input.data.unpinnedTools[_]
	_slug(split(u.uses, "@")[0]) == tool.slug
	_unpinned(u, tool.versionInput)
	finding := {
		"code":     "ISSUE-719",
		"severity": "medium",
		"message":  sprintf("Job `%s` uses `%s` without pinning `%s`; the tool it installs floats to its latest release on every run.", [job.name, u.uses, tool.versionInput]),
		"job":      job.name,
		"step":     u.name,
		"uses":     u.uses,
		"line":     object.get(u, "line", 0),
		"input":    tool.versionInput,
	}
}

_slug(loc) := concat("/", array.slice(split(loc, "/"), 0, 2))
_unpinned(u, key) if not u.with[key]
_unpinned(u, key) if lower(u.with[key]) == "latest"
_unpinned(u, key) if u.with[key] == ""
```

- [ ] **Step 4: Run to verify it passes**, wires, docs (remediation: "set the action's version input to an exact release"), website PR.

- [ ] **Step 5: Commit** `feat(controls): flag setup actions that install a floating tool version (issue 719)`.

### Task 3.4: overly broad permissions (ISSUE-805, workflowsMustNotGrantBroadPermissions)

**Files:** `policies/broad_permissions.rego`, fixtures `ISSUE-805/github/{violation_workflow_level_write.yml,violation_job_write_all_scope.yml,clean_read_only_workflow.yml,clean_job_scoped_write.yml}`, code severity medium, `ControlName: "workflowsMustNotGrantBroadPermissions"`, identity `{"file", "job", "scope"}`, config type `BroadPermissionsControlConfig{Enabled *bool; AllowedWorkflowLevelWrites []string \`yaml:"allowedWorkflowLevelWrites"\`}` (default empty), default `enabled: true`, JSON `broadPermissionsResult`. This is zizmor's excessive-permissions minus the two halves Plumber already ships (801 missing block, 803 write-all).

- [ ] **Step 1: Fixtures and failing test** (workflow-level `permissions: {contents: read, pull-requests: write, issues: write}` yields 2 findings, one per write scope; a job-level `permissions: write-all` is 803's and yields 0 here; `permissions: {contents: read}` yields 0; a job-level `permissions: {contents: write}` on a job that runs `git push` yields 0 because job-level scoping is the recommended shape).

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: The rule**

```rego
package broad_permissions

import rego.v1

# A write scope granted at the WORKFLOW level reaches every job of the
# workflow, including the ones that never need it. Job-level writes are
# the remediation, so they are never flagged here.
deny contains finding if {
	job := input.pipeline.jobs[_]
	not job.kind == "action"
	job.workflowPermissions[scope] == "write"
	not _allowed(scope)
	finding := {
		"code":     "ISSUE-805",
		"severity": "medium",
		"message":  sprintf("Workflow `%s` grants `%s: write` to every job; move the write to the job that needs it.", [job.workflowName, scope]),
		"job":      job.name,
		"scope":    scope,
	}
}

_allowed(scope) if input.config.broadPermissions.allowedWorkflowLevelWrites[_] == scope
```

`job.workflowPermissions` is the workflow-level `permissions:` map before job override; the collector stores the effective permissions in `job.Permissions` today (line 514 to 518 of `github/github_workflows.go`), so add `WorkflowPermissions any \`json:"workflowPermissions,omitempty"\`` to `ir.Job`, set from `wfCtx.perms`, and keep `Permissions` as it is. One finding per (workflow, scope): the rule fires per job, so dedupe on `file` and `scope` in the identity declaration (`{"file", "scope"}`) and let the engine's fingerprint collapse the copies.

- [ ] **Step 4: Run to verify it passes**, wires (stat lines `Workflows checked`, `Workflow-level write scopes`), docs (relationship to 801 and 803 spelled out), website PR.

- [ ] **Step 5: Commit** `feat(controls): flag workflow-level write permissions (issue 805)`.

### Task 3.5: unsound ternaries (ISSUE-216, workflowTernariesMustBeSound)

**Files:** `policies/unsound_ternary.rego`, fixtures `ISSUE-216/github/{violation_falsy_true_branch.yml,violation_empty_string_branch.yml,clean_literal_true_branch.yml,clean_no_ternary.yml}`, code severity low, `ControlName: "workflowTernariesMustBeSound"`, identity `{"file", "job", "step", "expression"}`, default `enabled: true`, JSON `unsoundTernaryResult`.

- [ ] **Step 1: Fixtures and failing test** (`${{ inputs.flag && '' || 'default' }}` and `${{ github.event_name == 'push' && 0 || 1 }}` are violations; `${{ cond && 'yes' || 'no' }}` is clean; counts 1, 1, 0, 0). The rule scans every `${{ }}` in `run:` (through `job.steps[*].run`, Task 1.3), `with:` (`uses[*].with`) and `if:` (`job.conditions`, the field the existing 211 rule reads).

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: The rule**

```rego
package unsound_ternary

import rego.v1

# `cond && A || B` behaves as a ternary only when A is truthy. A falsy A
# ('', 0, false, null) makes the expression always evaluate to B.
deny contains finding if {
	job := input.pipeline.jobs[_]
	expr := _expressions(job)[_]
	m := regex.find_all_string_submatch_n(`&&\s*('(?:[^']*)'|"(?:[^"]*)"|0|false|null)\s*\|\|`, expr.text, 1)
	count(m) > 0
	_falsy(m[0][1])
	finding := {
		"code":       "ISSUE-216",
		"severity":   "low",
		"message":    sprintf("Step `%s` of job `%s` uses `%s` as a ternary whose true branch is always falsy; the expression always yields the false branch.", [expr.step, job.name, expr.text]),
		"job":        job.name,
		"step":       expr.step,
		"expression": expr.text,
	}
}

_falsy("''")
_falsy(`""`)
_falsy("0")
_falsy("false")
_falsy("null")

_expressions(job) := [e |
	s := job.steps[_]
	t := regex.find_all_string_submatch_n(`\$\{\{([^}]*)\}\}`, s.run, -1)[_][1]
	e := {"text": trim_space(t), "step": s.name}
] | [e |
	u := job.uses[_]
	some k, v in u.with
	is_string(v)
	t := regex.find_all_string_submatch_n(`\$\{\{([^}]*)\}\}`, v, -1)[_][1]
	e := {"text": trim_space(t), "step": u.name}
] | [e |
	c := job.conditions[_]
	t := regex.find_all_string_submatch_n(`\$\{\{([^}]*)\}\}`, c, -1)[_][1]
	e := {"text": trim_space(t), "step": ""}
]
```

- [ ] **Step 4: Run to verify it passes**, wires, docs (remediation: "use a truthy placeholder and map it afterwards, or a `fromJSON` lookup"), website PR.

- [ ] **Step 5: Commit** `feat(controls): flag pseudo-ternaries whose true branch is falsy (issue 216)`.

### Task 3.6: undocumented permissions (ISSUE-806, workflowsMustDocumentPermissions)

**Files:** `policies/undocumented_permission_blocks.rego`, fixtures `ISSUE-806/github/{violation_uncommented_block.yml,clean_commented_block.yml,clean_no_block.yml}`, code severity low, `ControlName: "workflowsMustDocumentPermissions"`, identity `{"file", "job"}`, default `enabled: false` (zizmor: auditor persona), JSON `documentedPermissionsResult`.

- [ ] **Step 1: Fixtures and failing test** (`permissions:` block with no `#` comment on the block line or the line above is a violation; a block preceded by `# needs contents:write to push the tag` is clean; no block is clean, that is 801's; counts 1, 0, 0). The rule needs the raw workflow text, which the IR does not carry today: add `RawWorkflow string \`json:"rawWorkflow,omitempty"\`` to `ir.Job`, set on every job of a workflow from the bytes the collector reads at `github/github_workflows.go:62` onwards (the same text it parses), and leave it empty on GitLab and on action jobs.

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: The rule**

```rego
package undocumented_permission_blocks

import rego.v1

deny contains finding if {
	job := input.pipeline.jobs[_]
	not job.kind == "action"
	lines := split(job.rawWorkflow, "\n")
	some i
	regex.match(`^\s*permissions:\s*(\{.*\})?\s*$`, lines[i])
	not _commented(lines, i)
	finding := {
		"code":     "ISSUE-806",
		"severity": "low",
		"message":  sprintf("Workflow `%s` declares permissions without a comment saying why each scope is needed.", [job.workflowName]),
		"job":      job.name,
	}
}

_commented(lines, i) if contains(lines[i], "#")
_commented(lines, i) if {
	i > 0
	regex.match(`^\s*#`, lines[i - 1])
}
```

- [ ] **Step 4: Run to verify it passes**, wires, docs, website PR.

- [ ] **Step 5: Commit** `feat(controls): flag permissions blocks that carry no explanatory comment (issue 806)`.

### Task 3.7: self-hosted runners (ISSUE-424, workflowsMustNotUseSelfHostedRunners) and pre-commit http repos (ISSUE-906, preCommitReposMustUseHttps)

Two small controls, one task, two commits.

**Files (424):** `policies/self_hosted_runner.rego`, fixtures `ISSUE-424/github/{violation_self_hosted_label.yml,violation_runs_on_expression.yml,clean_github_hosted.yml}`, code severity low, identity `{"file", "job"}`, default `enabled: false` (zizmor: pedantic), JSON `selfHostedRunnerResult`. Collector: add `RunsOn []string \`json:"runsOn,omitempty"\`` to `ir.Job`, filled from `runs-on` (a string becomes a one-element list; a list is kept; a `group:`/`labels:` map contributes its labels). Rule: fires when `job.runsOn` contains `self-hosted`, or any element starts with `${{` (unknowable), or an element matches none of `ubuntu-*`, `windows-*`, `macos-*`.

**Files (906):** `github/github_repo_artifacts.go` (read `.pre-commit-config.yaml`, collect `repos[*].repo` into `ir.NormalizedPipeline.PreCommitRepos []string`), `policies/precommit_insecure_url.rego`, fixtures `ISSUE-906/github/{violation_http_repo.yml,clean_https_repo.yml,clean_local_repo.yml}` (the fixture file is copied to `.pre-commit-config.yaml` at the temp repository root), code severity medium, identity `{"file", "repo"}`, default `enabled: true`, JSON `preCommitUrlSchemeResult`. Rule: a `repo:` starting with `http://` fires; `https://`, `local` and `meta` do not.

```rego
package precommit_insecure_url

import rego.v1

deny contains finding if {
	repo := input.pipeline.preCommitRepos[_]
	startswith(lower(repo), "http://")
	finding := {
		"code":     "ISSUE-906",
		"severity": "medium",
		"message":  sprintf("`.pre-commit-config.yaml` fetches `%s` over plain HTTP; the hook source can be replaced in transit.", [repo]),
		"repo":     repo,
	}
}
```

- [ ] **Steps**: fixtures and failing tests for both codes, RED recorded; rules; wires as Task 2.1 steps 3 to 5; docs; website PR; commits `feat(controls): flag self-hosted runner usage (issue 424)` and `feat(controls): flag pre-commit hook sources fetched over http (issue 906)`.

---

## Wave 4: knobs that reproduce zizmor's stricter defaults

### Task 4.1: `flagTriggerWithoutCheckout` on workflowMustNotUseDangerousTriggers (802)

**Files:**
- Modify: `configuration/plumberconfig.go` (`DangerousTriggersControlConfig{Enabled *bool; FlagTriggerWithoutCheckout *bool \`yaml:"flagTriggerWithoutCheckout,omitempty"\`}` replaces `EnabledOnlyControlConfig` for this control; `validControlSchema` row `{"enabled", "flagTriggerWithoutCheckout"}`; `schema_docs.go` row)
- Modify: `policies/dangerous_triggers.rego` (a second `deny` body under `input.config.dangerousTriggers.flagTriggerWithoutCheckout == true` that fires on the trigger alone, `pull_request_target` included, severity medium, `confidence: medium`, message "subscribes to `<event>`; with the knob on, every subscription is reported, as zizmor does")
- Modify: `defaultConfig/.plumber.yaml`, `.plumber.yaml`, `docs/GITHUB_ISSUES.md` (802 section gains a "zizmor parity" paragraph), `README.md` (the "Coming from zizmor" table, created by Task 4.4)
- Test: `policies/rules_test.go` (`TestIssue802_TriggerWithoutCheckoutKnob`: the `dependabot-auto-merge` shape, `on: pull_request_target` with no checkout, yields 0 with the knob off and 1 with it on), `configuration/plumberconfig_test.go`

- [ ] **Step 1: Failing test** with the fixture `policies/testdata/ISSUE-802/github/knob_pull_request_target_no_checkout.yml`:

```yaml
name: Dependabot auto-merge
on: pull_request_target
permissions:
  pull-requests: write
  contents: write
jobs:
  dependabot:
    runs-on: ubuntu-latest
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    steps:
      - run: gh pr merge --auto --merge "$PR_URL"
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The test runs `evaluateStrict` twice, with `map[string]any{"dangerousTriggers": map[string]any{"enabled": true}}` (want 0) and with `"flagTriggerWithoutCheckout": true` added (want 1).

- [ ] **Step 2: Run to verify it fails** (the second evaluation returns 0).

- [ ] **Step 3: Rule body**

```rego
deny contains finding if {
	input.config.dangerousTriggers.flagTriggerWithoutCheckout == true
	job := input.pipeline.jobs[_]
	not job.kind == "action"
	event := job.triggers[_]
	event in {"pull_request_target", "workflow_run", "issue_comment", "pull_request_review", "pull_request_review_comment", "discussion", "discussion_comment", "gollum", "fork"}
	not _checks_out_untrusted_code(job)
	finding := {
		"code":       "ISSUE-802",
		"severity":   "medium",
		"confidence": "medium",
		"message":    sprintf("Job `%s` runs under `%s` without checking out untrusted code; reported because flagTriggerWithoutCheckout is on.", [job.name, event]),
		"job":        job.name,
		"trigger":    event,
	}
}
```

`job.triggers` is the `ir.Job.Triggers []string` the existing bodies of this rule read (line 81 onwards).

- [ ] **Step 4: Run to verify it passes**, default config comment ("Off by default: Plumber reports the exploitable combination only. Set `flagTriggerWithoutCheckout: true` to report every subscription, which is zizmor's behaviour."), docs, commit `feat(policies): dangerous triggers can report the subscription alone (zizmor parity knob)`.

### Task 4.2: `flagPublishingWorkflows` on releaseWorkflowsMustNotRestoreUntrustedCache (705)

Same shape as Task 4.1 on `policies/cache_poisoning.rego`: today a job is "release context" only when the workflow subscribes to `release` or a tag push. With `input.config.cachePoisoning.flagPublishingWorkflows == true`, a job is also release context when any of its `uses` is in zizmor's publishing list (`pypa/gh-action-pypi-publish`, `docker/build-push-action` with `push: true`, `goreleaser/goreleaser-action`, `softprops/action-gh-release`, `ncipollo/release-action`, `actions/create-release`, `JS-DevTools/npm-publish`, `rubygems/release-gem`, `svenstaro/upload-release-action`, `cycjimmy/semantic-release-action`, `googleapis/release-please-action`) or the job runs `npm publish`, `cargo publish`, `gem push`, `twine upload`, `docker push` in a `run:` step. The fixture is `00-learnXinY`'s shape: `on: [push, pull_request]`, an `actions/cache@v4` step with a non-ref-scoped key and a later `docker push`; want 0 with the knob off and 1 with it on. Commit `feat(policies): cache poisoning can widen to publishing workflows (zizmor parity knob)`.

### Task 4.3: `forbiddenGithubActions` denylist on githubActionMustComeFromAuthorizedSources (713)

Add `ForbiddenGithubActions []string \`yaml:"forbiddenGithubActions,omitempty"\`` to the control's config type, the `validControlSchema` row and `schema_docs.go`; in `policies/action_authorized_sources.rego` a `deny` body fires ISSUE-713 with `reason: "forbidden"` for any `uses` whose slug matches an entry (exact `owner/repo`, or `owner/*`), regardless of the allow rules. Fixture `policies/testdata/ISSUE-713/github/violation_forbidden_slug.yml` (`uses: actions/checkout@v4` with `forbiddenGithubActions: ["actions/checkout"]`: want 1, and the same workflow without the entry: want 0, since `actions/` is trusted). Commit `feat(policies): authorized action sources take a denylist (zizmor forbidden-uses parity)`.

### Task 4.4: the "Coming from zizmor" reference

**Files:**
- Create: `docs/ZIZMOR.md`: the 41-row table from the spec (audit, Plumber control, code, default, the knob that reproduces zizmor's default when Plumber's differs), the one-paragraph note on personas becoming defaults, and a ready-to-paste `.plumber.yaml` overlay named "zizmor auditor" that enables every auditor-persona control and sets the three knobs
- Modify: `README.md` (one sentence linking `docs/ZIZMOR.md` from the GitHub section), `docs/GITHUB_ISSUES.md` (intro link)
- Test: `docs/zizmor_table_test.go` (a test in package `docs` that parses the table and asserts every control name it mentions exists in `configuration.controlsMeta` and every audit name appears exactly once; the same shape as `TestControlCategoriesFollowTheCodeBlocks`)

- [ ] **Step 1: Failing test** (the table file does not exist).
- [ ] **Step 2: Write the document** with the overlay:

```yaml
# .plumber.yaml, zizmor auditor persona equivalent
version: "2.0"
extends: plumber:default
github:
  controls:
    workflowsMustDeclareConcurrency: { enabled: true }
    workflowsMustHaveExplicitName: { enabled: true }
    deployJobsMustUseEnvironmentGate: { enabled: true }
    actionPinCommentsMustMatchSha: { enabled: true }
    actionPinsMustNotBeStale: { enabled: true }
    actionsMustNotDuplicateRunnerBuiltins: { enabled: true }
    workflowsMustDocumentPermissions: { enabled: true }
    workflowsMustNotUseSelfHostedRunners: { enabled: true }
    actionsMustBePinnedByCommitSha: { enabled: true, trustedOwners: [] }
    workflowMustNotUseDangerousTriggers: { enabled: true, flagTriggerWithoutCheckout: true }
    releaseWorkflowsMustNotRestoreUntrustedCache: { enabled: true, flagPublishingWorkflows: true }
```

- [ ] **Step 3: Run the test, then run `go run . analyze --config docs/zizmor-auditor.plumber.yaml --print=false` on a clone of `austenstone/actions-playground` at `a84f5c0`** and record in the task report, per zizmor audit, the zizmor count and the Plumber count on that repository. Every audit with a zizmor count above zero must have a Plumber count above zero; a lower Plumber count is acceptable only where the spec names the difference as deliberate (fixed contexts under template injection; job-level writes under broad permissions).
- [ ] **Step 4: Commit** `docs: coming from zizmor, the audit-to-control table and the auditor overlay`.

---

## Self-review

**Spec coverage.** All 41 audits have a row and a task: 10 ship already (no task), 19 promote in Wave 2, 7 are new in Wave 3, 3 partial ones widen in Wave 1 (template injection, unpinned images, github-env through action inputs), 3 gain knobs in Wave 4 (dangerous triggers, cache poisoning, forbidden uses). Design decision 6 (catalog honesty) is Task 0.1 plus the bench-set pin at the end of Wave 2. Decision 4 (inputs) is Tasks 1.1 and 1.2.

**Placeholders.** None: every code step carries its code; the eighteen repeated promotions carry their names in the Wave 2 table and their differences in the bullet list.

**Type consistency.** `BenchedFor(provider string) []string` (Task 0.1) is what the Wave 2 pin test calls. `ir.Job.Kind`, `ir.Job.StepImages`, `ir.Job.DispatchInputs`, `ir.Job.WorkflowPermissions`, `ir.NormalizedPipeline.PreCommitRepos` are each introduced by exactly one task before any rule reads them (1.2, 1.1, 1.3, 3.4, 3.7). `input.data.contextCapabilities`, `input.data.wellKnownActions`, `input.data.unpinnedTools` all travel through the one `"data"` key `buildInput` gains in Task 1.3. The JSON block builders follow `buildPermissionsBlock`'s signature `(legacyCommon, *control.AnalysisResult, []opaengine.Finding) map[string]any` throughout.
