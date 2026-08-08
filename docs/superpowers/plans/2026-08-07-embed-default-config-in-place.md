# Embed the Default Config In Place Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `go install github.com/getplumber/plumber@<version>` work again by embedding `defaultConfig/.plumber.yaml` directly instead of copying it to a git-ignored path that never reaches the published module zip (fixes [#405](https://github.com/getplumber/plumber/issues/405)).

**Architecture:** `//go:embed` cannot reach outside its own package directory, so the Go file moves next to the YAML rather than the other way round. A new `defaultConfig/embed.go` embeds `.plumber.yaml` in place, `internal/defaultconfig/` is deleted, and the nine `cp` steps that regenerated the git-ignored file across the Makefile, Dockerfile and workflows all disappear. A new CI job builds from the committed tree only, so a git-ignored build input can never ship again.

**Tech Stack:** Go 1.25/1.26 (`//go:embed`), GNU Make, Docker, GitHub Actions, golangci-lint v2.

Spec: `docs/superpowers/specs/2026-08-07-embed-default-config-in-place-design.md`

## Global Constraints

- Branch `fix/405-embed-default-config-in-place` is already checked out, branched from `origin/main` at `d4bf27b`. Do not branch again.
- **No em dashes or other "AI tell" characters** in any committed prose: code comments, doc comments, commit messages, Markdown. Use commas, periods, parentheses and colons.
- `defaultConfig/.plumber.yaml` must not be moved, renamed, or edited. Its content is a public contract: getplumber.io publishes `curl` commands against its `raw.githubusercontent.com` URL.
- Commits follow Conventional Commits (`fix:`, `docs:`, `ci:`, `refactor:`) with a scope where one fits. The functional commit must be `fix(config):` so semantic-release cuts a patch.
- Every commit must leave CI green, with one deliberate exception: Task 1 commits a failing guard, and Task 2 turns it green. Do not push between those two tasks.
- The package directory `defaultConfig/` is mixed-case while the package name is lowercase `defaultconfig`. This is verified to build, vet and lint cleanly under this repo's `.golangci.yml`. Do not "fix" the directory name.

## File Structure

**Created:**
- `defaultConfig/embed.go` - the only Go file in the shipped-default package. Holds the `//go:embed .plumber.yaml` directive and the `Get()` accessor. Sole responsibility: hand the embedded baseline bytes to callers.

**Deleted:**
- `internal/defaultconfig/embed.go` - replaced by the above.
- `internal/defaultconfig/default.yaml` - the git-ignored generated copy. Untracked locally, so this is a filesystem delete, not a git delete.

**Modified:**
- 13 Go files: import path swap only, no logic change.
- `Makefile`, `Dockerfile`, `.gitignore` - drop the generation step.
- `.github/workflows/{ci,codeql,plumber-action,release}.yml` - drop the generation step; `ci.yml` also gains the guard job.
- `cmd/init_test.go` - drop the now-tautological test and its `bytes` import.
- `CONTRIBUTING.md` - drop the `make embed` workflow it documents.

---

### Task 1: Add the clean-tree build guard

This task is the failing test for the whole change. It reproduces #405 as a CI job and proves the job is genuinely red before any fix lands.

**Files:**
- Modify: `.github/workflows/ci.yml` (insert a job after the `build` job, which ends at line 38)

**Interfaces:**
- Consumes: nothing.
- Produces: a CI job named `clean-tree-build` (display name "Build from committed tree"). Task 2 relies on this job going green.

- [ ] **Step 1: Run the guard locally to watch it fail**

```bash
tmp=$(mktemp -d)
git archive HEAD | tar -x -C "$tmp"
(cd "$tmp" && go build ./...)
```

Expected: FAIL with

```
defaultConfig or internal/defaultconfig/embed.go:18:12: pattern default.yaml: no matching files found
```

The exact prefix is `internal/defaultconfig/embed.go:18:12`. If this command *succeeds*, stop and investigate: it means `internal/defaultconfig/default.yaml` got committed at some point, and the premise of this plan is wrong.

Note why this fails while a plain `go build ./...` in the repo succeeds: `git archive` exports only tracked files, and `internal/defaultconfig/default.yaml` is git-ignored. Your working tree still has the generated copy sitting there from an earlier `make build`.

- [ ] **Step 2: Add the CI job**

In `.github/workflows/ci.yml`, insert this immediately after the `build` job's last line (`        run: go build ./...`, line 38) and before `  test:` on line 40. Keep one blank line on each side.

```yaml
  clean-tree-build:
    name: Build from committed tree
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: '1.26.5'

      # Build from what git actually tracks. Every other job builds the
      # working tree, which can contain generated or git-ignored files that
      # never reach the published module zip, so they all stayed green while
      # `go install` was broken for months (getplumber/plumber#405). This job
      # is the only one that sees what a consumer sees.
      - name: Build from committed tree only
        run: |
          set -eo pipefail
          tmp=$(mktemp -d)
          git archive HEAD | tar -x -C "$tmp"
          cd "$tmp"
          go build ./...
```

`set -eo pipefail` matters: the default shell for a `run` block is `bash -e`, without `pipefail`, so a failing `git archive` piped into a succeeding `tar` would pass silently.

- [ ] **Step 3: Verify the YAML parses and the job is registered**

```bash
python3 -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/ci.yml')); print(list(d['jobs']))"
```

Expected output contains `clean-tree-build`:

```
['build', 'clean-tree-build', 'test', 'lint', 'govulncheck', 'grype']
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: build from the committed tree to catch git-ignored build inputs

Every existing job builds the working tree, so a build input that is
git-ignored and generated by a cp step stays invisible to CI while
breaking every consumer that compiles the published module zip. This job
extracts git archive HEAD into a temp directory and builds there, which
is what a go install sees.

It fails on the current tree, reproducing getplumber/plumber#405.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

Do not push yet. This commit is intentionally red and Task 2 makes it green.

---

### Task 2: Embed the default config in place

This is one atomic commit by necessity. The `cp` steps write into `internal/defaultconfig/`, so deleting that directory without removing the `cp` steps in the same commit leaves every build path failing on `cp: No such file or directory`. There is no ordering that splits this while keeping each commit green.

**Files:**
- Create: `defaultConfig/embed.go`
- Delete: `internal/defaultconfig/embed.go`, `internal/defaultconfig/default.yaml` (untracked)
- Modify (import path only): `cmd/analyze_gitlab.go:20`, `cmd/config.go:13`, `cmd/config_explain.go:7`, `cmd/config_resolve.go:12`, `cmd/config_resolve_test.go:15`, `cmd/config_slim.go:14`, `cmd/config_slim_test.go:13`, `cmd/init.go:15`, `cmd/init_test.go:11`, `configuration/plumberconfig.go:9`, `configuration/resolve.go:7`, `configuration/resolve_test.go:9`, `control/cache_poisoning_contract_test.go:9`
- Modify: `cmd/init_test.go` (delete a test and the `bytes` import), `Makefile`, `Dockerfile`, `.gitignore`, `.github/workflows/ci.yml`, `.github/workflows/codeql.yml`, `.github/workflows/plumber-action.yml`, `.github/workflows/release.yml`

**Interfaces:**
- Consumes: the `clean-tree-build` job from Task 1.
- Produces: package `github.com/getplumber/plumber/defaultConfig`, package name `defaultconfig`, exporting exactly one identifier:
  ```go
  func Get() []byte
  ```
  Same signature and semantics as the deleted `internal/defaultconfig.Get`. Task 4 verifies its bytes are unchanged.

- [ ] **Step 1: Create the new package**

Create `defaultConfig/embed.go` with exactly this content:

```go
// Package defaultconfig embeds the shipped default Plumber configuration,
// the baseline every zero-config user gets.
//
// This file lives beside the YAML it embeds because //go:embed cannot reach
// outside its own package directory, and embedding the source in place is
// what keeps the module self-contained. The previous arrangement generated a
// copy into internal/defaultconfig/ with a cp step in every build path and
// git-ignored the result, so the file was absent from the published module
// zip and `go install` failed for every consumer while every build path here
// stayed green (getplumber/plumber#405).
//
// The source is defaultConfig/.plumber.yaml, NOT the repo-root .plumber.yaml
// (which is Plumber's own self-scan config). The two are independent
// artifacts (getplumber/plumber#352): editing Plumber's self-scan config
// never silently changes the shipped default.
package defaultconfig

import _ "embed"

//go:embed .plumber.yaml
var config []byte

// Get returns the embedded default configuration as a byte slice.
func Get() []byte {
	return config
}
```

The byte slice is unexported because the old exported `Config` var had zero uses outside its own package. All 38 call sites go through `Get()`.

- [ ] **Step 2: Repoint all 13 imports**

```bash
grep -rl '"github.com/getplumber/plumber/internal/defaultconfig"' --include='*.go' . \
  | xargs sed -i '' 's|"github.com/getplumber/plumber/internal/defaultconfig"|defaultconfig "github.com/getplumber/plumber/defaultConfig"|'
gofmt -w .
```

Note the macOS `sed -i ''` form. On Linux use `sed -i` with no argument.

The explicit `defaultconfig` alias is deliberate: the import path's last element is `defaultConfig` but the package name is `defaultconfig`, and spelling the alias out means a reader never has to open the package to learn what identifier it binds. `gofmt` re-sorts each import block, which is why it runs immediately after.

- [ ] **Step 3: Verify the swap is complete and mechanical**

```bash
grep -rn "internal/defaultconfig" --include='*.go' . ; echo "go files remaining: $?"
git diff --stat -- '*.go'
```

Expected: the grep prints nothing (exit 1). `git diff --stat` shows 13 files with 1 insertion and 1 deletion each, except any file where `gofmt` also reordered the import block.

- [ ] **Step 4: Delete the old package**

```bash
git rm internal/defaultconfig/embed.go
rm -f internal/defaultconfig/default.yaml
rmdir internal/defaultconfig
```

`embed.go` is tracked, so `git rm` stages its deletion. `default.yaml` is git-ignored and therefore untracked, so it needs a filesystem `rm`. The `rmdir` then succeeds only if the directory is genuinely empty, which is the check you want.

- [ ] **Step 5: Delete the tautological test**

In `cmd/init_test.go`, delete `TestEmbeddedDefaultMatchesSource` together with its doc comment. It spans from the comment beginning `// The embedded default (defaultconfig.Get) must be byte-identical to the source` through the closing brace at line 164. The whole block to remove:

```go
// The embedded default (defaultconfig.Get) must be byte-identical to the source
// defaultConfig/.plumber.yaml. Every build path regenerates the embed from the
// source (`make embed` / the CI+Docker `cp` step) before build/test; this
// asserts that link directly, so a stale or skipped regeneration — which would
// ship a drifted default to `config generate`, the init wizard, and zero-config
// analyze while every self-consistent test stays green — fails here instead.
func TestEmbeddedDefaultMatchesSource(t *testing.T) {
	src, err := os.ReadFile("../defaultConfig/.plumber.yaml")
	if err != nil {
		t.Fatalf("read source default: %v", err)
	}
	if !bytes.Equal(src, defaultconfig.Get()) {
		t.Errorf("embedded default (%d bytes) differs from defaultConfig/.plumber.yaml (%d bytes) — run `make embed` to regenerate the embed from source",
			len(defaultconfig.Get()), len(src))
	}
}
```

It asserted that the embed matches `../defaultConfig/.plumber.yaml`, which is now the file being embedded, so it can only ever pass. The regeneration it guarded no longer exists.

Then remove the now-unused `"bytes"` import from the import block at the top of the file. `bytes.Equal` on line 159 was its only use in the entire file. Leave `"os"`: it is still used on lines 177, 755 and 765.

- [ ] **Step 6: Verify the package compiles and tests pass**

```bash
go build ./... && go test ./cmd/... ./configuration/... ./control/...
```

Expected: PASS. If `bytes` was left in, this fails with `"bytes" imported and not used`.

- [ ] **Step 7: Remove the generation step from the Makefile**

Four edits to `Makefile`:

1. Line 1, drop `embed` from `.PHONY`:
```make
.PHONY: build clean test lint deadcode vuln
```

2. Delete lines 6 through 13 entirely (the comment block, the `embed:` target, its recipe, and the trailing blank line). The `#352` distinction that comment explained now lives in `defaultConfig/embed.go`.

3. Drop the `embed` prerequisite from all seven targets that declare it. `build: embed` becomes `build:`, and likewise for `build-all`, `test`, `lint`, `deadcode`, `vuln` and `run`. Leave `install: build` alone.

4. In the `clean` target, delete the line `	rm -f internal/defaultconfig/default.yaml`, leaving only `	rm -f $(BINARY) $(BINARY)-*`.

- [ ] **Step 8: Remove the generation step from the Dockerfile**

Delete lines 25 and 26 plus the blank line that separated them from the build:

```dockerfile
# Copy default config for embedding
RUN cp defaultConfig/.plumber.yaml internal/defaultconfig/default.yaml
```

Then fix the dangling reference in the runtime-stage comment at line 58. Change:

```dockerfile
# default (see the cp into internal/defaultconfig above), so a scan with no
```

to:

```dockerfile
# default (embedded by defaultConfig/embed.go), so a scan with no
```

- [ ] **Step 9: Remove the generation step from the four workflows**

Delete this two-line step, plus its trailing blank line, everywhere it appears:

```yaml
      - name: Prepare embedded config
        run: cp defaultConfig/.plumber.yaml internal/defaultconfig/default.yaml
```

Occurrences: `.github/workflows/ci.yml` lines 34-35 (`build` job), 52-53 (`test`), 77-78 (`lint`), 126-127 (`govulncheck`); `.github/workflows/codeql.yml` lines 34-35; `.github/workflows/release.yml` lines 119-120. Delete from the bottom up so earlier line numbers stay valid.

`.github/workflows/plumber-action.yml` is different: the `cp` is one line inside a multi-line `run` block at lines 36-39. Collapse the block:

```yaml
      - name: Build Plumber from source
        run: |
          cp defaultConfig/.plumber.yaml internal/defaultconfig/default.yaml
          go build -o plumber .
```

becomes:

```yaml
      - name: Build Plumber from source
        run: go build -o plumber .
```

- [ ] **Step 10: Un-ignore the vanished file**

In `.gitignore`, delete lines 42 and 43:

```
# Embedded config (copied from .plumber.yaml during build)
internal/defaultconfig/default.yaml
```

- [ ] **Step 11: Verify no reference survives anywhere**

```bash
grep -rn "internal/defaultconfig" --exclude-dir=.git --exclude-dir=docs .
```

Expected: three hits and no more, all in `CONTRIBUTING.md` (lines 120, 622, 818). Task 3 clears those. Anything outside `CONTRIBUTING.md` is a miss: go back and fix it.

```bash
grep -rn "make embed\|cp defaultConfig" --exclude-dir=.git --exclude-dir=docs .
```

Expected: hits only in `CONTRIBUTING.md`.

- [ ] **Step 12: Run the guard from Task 1 and watch it pass**

```bash
git add -A
tmp=$(mktemp -d)
git archive "$(git write-tree)" | tar -x -C "$tmp"
(cd "$tmp" && go build ./...)
```

Expected: PASS, no output. The changes are not committed yet, so `git archive HEAD` would still archive the broken state. `git write-tree` writes a tree object from the staged index instead, which is exactly what the pending commit will contain. This is the moment the bug is fixed.

- [ ] **Step 13: Run the full local gate with no embed step**

```bash
go build ./... && go test ./... && golangci-lint run ./... && gofmt -l .
```

Expected: tests PASS, golangci-lint prints `0 issues.`, `gofmt -l` prints nothing. Note there is no `make embed` anywhere in that command, which is the point.

- [ ] **Step 14: Verify the Makefile still works**

```bash
make clean && make build && ./plumber config generate -o /tmp/gen-check.yaml -f && diff /tmp/gen-check.yaml defaultConfig/.plumber.yaml && echo "GENERATE MATCHES SOURCE"
```

Expected: `make build` succeeds with no `embed` target, and the diff is empty.

- [ ] **Step 15: Verify the Docker build**

```bash
docker build -t plumber:405-check .
```

Expected: succeeds. This is the build path most likely to break, because it copies the source tree and previously depended on the `cp`.

- [ ] **Step 16: Commit**

```bash
git add -A
git commit -m "fix(config): embed the shipped default in place

go install failed on every version since the configuration package
started importing internal/defaultconfig: that package embedded
default.yaml, the file was git-ignored, and it therefore never reached
the published module zip. Local builds and CI regenerated it with a cp
step first, so nothing here ever noticed.

go:embed cannot reach outside its own package directory, so the Go file
moves next to the YAML instead. defaultConfig/.plumber.yaml stays exactly
where it is, which matters because getplumber.io publishes curl commands
against its raw URL.

Nothing generates a build input anymore, so the nine cp steps across the
Makefile, Dockerfile and workflows are gone, along with the gitignore
entry and the test that asserted the copy matched its source.

Fixes #405

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Documentation follow-through

`CONTRIBUTING.md` documents the `make embed` ritual in ten places. Every one is now wrong, and the "always use `make build` instead of `go build`" rule existed only because of the embed, so it gets dropped rather than reworded.

**Files:**
- Modify: `CONTRIBUTING.md`

**Interfaces:**
- Consumes: the package path `github.com/getplumber/plumber/defaultConfig` from Task 2.
- Produces: nothing consumed by later tasks.

The line numbers below are as of the start of this task and the steps run top to bottom, so each edit shifts every line number after it. Locate each block by its quoted text, not by line number. The numbers are there to tell you roughly where to look.

- [ ] **Step 1: Fix the Building section (lines 113-121)**

Replace the block that runs from line 113 through line 121, shown here between markers:

`````markdown
<<<BEGIN EXISTING TEXT TO DELETE>>>
Always use `make build` instead of `go build` directly. The Makefile embeds the shipped default config (`defaultConfig/.plumber.yaml`) into the binary (required for `plumber config generate` to work):

```bash
make build
```

This runs two steps:
1. Copies `defaultConfig/.plumber.yaml` into `internal/defaultconfig/default.yaml` (with a build header)
2. Compiles the Go binary
<<<END EXISTING TEXT TO DELETE>>>
`````

with:

`````markdown
<<<BEGIN REPLACEMENT TEXT>>>
```bash
make build
```

`go build .` works too. The shipped default config (`defaultConfig/.plumber.yaml`) is embedded in place by `defaultConfig/embed.go`, so there is no generation step to run first.
<<<END REPLACEMENT TEXT>>>
`````

The `<<<BEGIN>>>` and `<<<END>>>` marker lines are not part of the file content. They exist only to delimit where the nested fenced code block starts and stops. Do not write them into `CONTRIBUTING.md`.

Line 120 was doubly stale: it also claimed the copy added a build header, which the plain `cp` never did.

- [ ] **Step 2: Fix the Make Targets table (lines 133-139)**

Drop the "Embed config + " prefix from four rows and fix the `clean` row:

```markdown
| Target | Description |
|--------|-------------|
| `make build` | Build binary |
| `make build-all` | Cross-compile for Linux, macOS, and Windows |
| `make test` | Run all tests |
| `make lint` | Lint code |
| `make run` | `go run .` (quick dev iteration) |
| `make install` | Build + install to `/usr/local/bin/` |
| `make clean` | Remove binary |
```

- [ ] **Step 3: Fix the repo tree diagram (lines 233-234 and 302-304)**

At line 233-234, change:

```
├── defaultConfig/
│   └── .plumber.yaml          # Shipped default, embedded in the binary (make build)
```

to:

```
├── defaultConfig/
│   ├── .plumber.yaml          # Shipped default, embedded in the binary
│   └── embed.go               # go:embed directive for the file above
```

At lines 302-304, delete the whole `defaultconfig` entry from the `internal/` block:

```
│   └── defaultconfig/         # Embedded default config (generated by make build)
│       ├── embed.go           # go:embed directive
│       └── default.yaml       # Auto-generated — do not edit directly
```

The preceding `engine/opa/` entry then becomes the last child, so change its `├──` prefix to `└──` and re-indent its `engine.go` child line accordingly.

- [ ] **Step 4: Fix the four checklist references**

- Line 344, in the "where do I add a control" table, change the Default config row from:
  `| **Default config** | `defaultConfig/.plumber.yaml` + `.plumber.yaml` (self-scan), then `make embed` |`
  to:
  `| **Default config** | `defaultConfig/.plumber.yaml` + `.plumber.yaml` (self-scan) |`

- Line 622, delete the whole checklist item:
  `- [ ] **`make embed`** regenerates `internal/defaultconfig/default.yaml` from `defaultConfig/.plumber.yaml`. **Don't edit the generated file directly** ...`
  There is no generated file to regenerate and none to avoid editing.

- Line 665, change:
  `- [ ] **`make embed && make test && make lint`** — every gate must pass before commit.`
  to:
  `- [ ] **`make test && make lint`**: every gate must pass before commit.`
  (Note the em dash removal, per the global constraint.)

- Line 818, in the Configuration numbered list, delete step 3:
  `3. Run `make build` to regenerate `internal/defaultconfig/default.yaml``
  and renumber the two steps that follow it to 3 and 4.

- [ ] **Step 5: Verify no stale reference survives**

```bash
grep -n "internal/defaultconfig\|make embed" CONTRIBUTING.md
```

Expected: no output.

```bash
grep -rn "internal/defaultconfig\|make embed\|cp defaultConfig" --exclude-dir=.git --exclude-dir=docs .
```

Expected: no output. Every reference in the repo is now gone, outside the `docs/superpowers/` spec and this plan, which describe the change and are meant to keep the old names.

- [ ] **Step 6: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs(contributing): drop the make embed workflow

The shipped default is embedded in place now, so there is no generated
file to regenerate, no cp step to describe, and no reason to require
make build over go build.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: End-to-end differential verification

The reviewer's explicit gate. Every config path reads the embedded bytes, so a wrong or truncated embed would surface here and nowhere else. The method is differential: a binary built from `origin/main` and a binary built from this branch must produce byte-identical output for every config state.

**Files:**
- Create: nothing committed. Uses a scratch worktree and temp files.
- Modify: nothing.

**Interfaces:**
- Consumes: `defaultconfig.Get()` from Task 2, via the CLI.
- Produces: nothing. This task gates the PR.

- [ ] **Step 1: Build both binaries**

```bash
git worktree add /tmp/plumber-base origin/main
make -C /tmp/plumber-base build
cp /tmp/plumber-base/plumber /tmp/plumber-old
go build -o /tmp/plumber-new .
/tmp/plumber-old version; /tmp/plumber-new version
```

`/tmp/plumber-base` needs `make build` because `origin/main` still has the `cp` step. The branch binary needs only `go build`, which is itself part of the result.

- [ ] **Step 2: Compare the zero-config path**

```bash
work=$(mktemp -d)
(cd "$work" && /tmp/plumber-old config resolve > /tmp/old-none.yaml)
(cd "$work" && /tmp/plumber-new config resolve > /tmp/new-none.yaml)
diff /tmp/old-none.yaml /tmp/new-none.yaml && echo "ZERO-CONFIG IDENTICAL"
```

Expected: no diff. With no `.plumber.yaml` in the directory and no `-c` flag, `resolveConfigToFile` falls back to `LoadPlumberConfigFromBytes(defaultconfig.Get(), ...)`, so this output is a direct function of the embedded bytes. A truncated embed fails here loudly.

- [ ] **Step 3: Compare the full-config path**

```bash
/tmp/plumber-old config resolve -c "$PWD/.plumber.yaml" > /tmp/old-full.yaml
/tmp/plumber-new config resolve -c "$PWD/.plumber.yaml" > /tmp/new-full.yaml
diff /tmp/old-full.yaml /tmp/new-full.yaml && echo "FULL-CONFIG IDENTICAL"
```

Expected: no diff. This repo's root `.plumber.yaml` is a full self-scan config, and the embedded default still forms the base layer underneath it.

- [ ] **Step 4: Compare the overlay path**

```bash
cat > "$work/overlay.yaml" <<'EOF'
extends: plumber:default
version: "2.0"
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      includePlumberDefaults: true
      trustedGithubActions:
        - myorg
EOF
/tmp/plumber-old config resolve -c "$work/overlay.yaml" > /tmp/old-overlay.yaml
/tmp/plumber-new config resolve -c "$work/overlay.yaml" > /tmp/new-overlay.yaml
diff /tmp/old-overlay.yaml /tmp/new-overlay.yaml && echo "OVERLAY IDENTICAL"
grep -q "myorg" /tmp/new-overlay.yaml && echo "OVERLAY ACTUALLY APPLIED"
```

Expected: no diff, and `myorg` present. `extends: plumber:default` merges the sparse overlay onto the embedded baseline, so this exercises the merge path rather than the fallback path. The `grep` guards against a false pass where both binaries silently ignored the overlay.

- [ ] **Step 5: Compare the generated template**

```bash
/tmp/plumber-old config generate -o /tmp/old-gen.yaml -f
/tmp/plumber-new config generate -o /tmp/new-gen.yaml -f
diff /tmp/old-gen.yaml /tmp/new-gen.yaml && echo "GENERATE IDENTICAL"
diff /tmp/new-gen.yaml defaultConfig/.plumber.yaml && echo "GENERATE MATCHES SOURCE"
```

Expected: both diffs empty. The second one is the byte-for-byte proof that the embed carries the whole 55217-byte source, replacing the test deleted in Task 2 Step 5 with a stronger end-to-end check.

- [ ] **Step 6: Compare a real analyze run per config state**

Needs a token: `gh auth login` or `GH_TOKEN` in the environment.

```bash
# Zero-config: plumber-lab-github has no .plumber.yaml.
lab=~/workspace/github.com/getplumber/plumber-lab-github
(cd "$lab" && /tmp/plumber-old analyze --output /tmp/old-lab.json)
(cd "$lab" && /tmp/plumber-new analyze --output /tmp/new-lab.json)
diff /tmp/old-lab.json /tmp/new-lab.json && echo "ANALYZE ZERO-CONFIG IDENTICAL"

# Full config: this repo's own self-scan config.
/tmp/plumber-old analyze --output /tmp/old-self.json
/tmp/plumber-new analyze --output /tmp/new-self.json
diff /tmp/old-self.json /tmp/new-self.json && echo "ANALYZE FULL-CONFIG IDENTICAL"
```

Expected: no diffs. If a diff appears, check whether it is a genuinely non-deterministic field (a duration or timestamp) before treating it as a regression: re-run the *same* binary twice against the same target and diff those two runs. A field that differs between two runs of one binary is noise, not a regression.

- [ ] **Step 7: Prove the original bug is actually fixed**

```bash
tmp=$(mktemp -d)
git archive HEAD | tar -x -C "$tmp"
(cd "$tmp" && go build ./... && echo "CLEAN-TREE BUILD PASSES")
```

Expected: PASS. This is the reproduction from the issue, run against committed state.

- [ ] **Step 8: Clean up the scratch worktree**

```bash
git worktree remove /tmp/plumber-base --force
rm -f /tmp/plumber-old /tmp/plumber-new
git worktree list
```

Expected: `/tmp/plumber-base` no longer listed. Leaving a stale worktree entry behind has bitten this repo before (commit `cefefa6`).

- [ ] **Step 9: Confirm the tree is clean and push**

```bash
git status --short
git branch --show-current
git log --oneline origin/main..HEAD
```

Expected: no uncommitted changes, branch is `fix/405-embed-default-config-in-place`, and three commits (the guard, the fix, the docs). Verify the branch name before pushing: this is a shared checkout and the branch can change under you.

```bash
git push -u origin fix/405-embed-default-config-in-place
```

Then open the PR with `Fixes #405` in the body, and confirm the `Build from committed tree` check appears and is green.

---

## Post-merge

Not part of this plan, but do not lose them:

1. **The release gates platform work.** The functional commit is a `fix:`, so semantic-release cuts a patch on merge to `main`. Platform can only unpin once that version is published. Verify with `GOMODCACHE=$(mktemp -d) go install github.com/getplumber/plumber@<new tag>` against the real proxy.
2. **The lab repos carry the same pattern.** `plumber-inject-http-client` has the identical `cp` in its Makefile and Dockerfile, and the other forks likely do too. Worth its own issue.
