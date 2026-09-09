# Catalog Source-of-Truth Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export the CLI's full control/issue catalog (immutable ids, descriptions, config schemas) through Go accessors and a `plumber catalog` JSON command, so the platform and docs stop hand-maintaining copies.

**Architecture:** Extend the existing registries in place (`configuration/registry.go` for controls, `control/codes.go` for issue types), derive config-schema structure by reflection over the real config structs welded to an authored prose table by parity tests, aggregate everything in `control.Catalog()`, and expose it via a new cobra `catalog` command with a golden-tested JSON envelope.

**Tech Stack:** Go 1.26, stdlib `reflect`, cobra (already used), table-driven tests, golden files under `testdata/`.

**Spec:** `docs/superpowers/specs/2026-09-08-catalog-source-of-truth-design.md` (committed on this branch). Read it first.

## Global Constraints

- No em dashes anywhere (code, comments, commits). Conventional commits enforced.
- No new dependencies. `go.mod` must not change.
- No analysis/scoring behavior change: only the touched files may differ; `go test ./...` stays green.
- All new exported identifiers carry doc comments in the repo's existing comment style (explain the why, not the what).
- Before any push: `gofmt -l` clean, `go test ./...` green, pinned `golangci-lint run` (v2.10.1) 0 issues.
- Branch: `feat/catalog-source-of-truth` (already exists, spec committed). Every task commits on it.

---

### Task 1: Immutable CTRL-XXX ids in the control registry

**Files:**
- Modify: `configuration/registry.go` (ControlMeta struct + all `controlsMeta` entries)
- Create: `configuration/registry_id_test.go`
- Create: `configuration/testdata/control_ids_golden.txt`

**Interfaces:**
- Consumes: existing `configuration.ControlMeta`, `ControlsCatalog()` (registry.go).
- Produces: `ControlMeta.ID string` populated for every entry; golden file freezing id-to-name pairs. Later tasks read `entry.ID` via `ControlsCatalog()`.

- [ ] **Step 1: Write the failing tests**

Create `configuration/registry_id_test.go`:

```go
package configuration

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every control carries a CTRL-XXX id: the rename-stable key the platform
// can hang durable state on (#458). Format and uniqueness are pinned here;
// the id-to-name pairing is frozen by the golden below.
func TestControlIDsAreWellFormedAndUnique(t *testing.T) {
	idPattern := regexp.MustCompile(`^CTRL-\d{3}$`)
	seen := map[string]string{}
	for _, e := range ControlsCatalog() {
		if !idPattern.MatchString(e.ID) {
			t.Errorf("control %q has id %q, want CTRL-XXX", e.Name, e.ID)
		}
		if prev, dup := seen[e.ID]; dup {
			t.Errorf("id %s assigned to both %q and %q", e.ID, prev, e.Name)
		}
		seen[e.ID] = e.Name
	}
}

// The id-to-name pairing is immutable: a control rename shows up as a
// reviewable diff of this golden file (update it deliberately with
// -update-ids); an id CHANGE for an existing name is the contract break
// this test exists to catch. See docs/superpowers/specs/
// 2026-09-08-catalog-source-of-truth-design.md.
func TestControlIDsMatchGolden(t *testing.T) {
	var lines []string
	for _, e := range ControlsCatalog() {
		lines = append(lines, fmt.Sprintf("%s %s", e.ID, e.Name))
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"

	const golden = "testdata/control_ids_golden.txt"
	if *updateIDs {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update-ids once to seed it): %v", err)
	}
	if got != string(want) {
		t.Errorf("control id table diverged from golden.\nIf you RENAMED a control, update the golden deliberately (go test ./configuration/ -run TestControlIDsMatchGolden -update-ids) and say so in the commit.\nIf an ID changed for an existing name, that is a contract break: restore the id.\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}
```

Add the flag at the top of the same file (after imports):

```go
import "flag"

var updateIDs = flag.Bool("update-ids", false, "rewrite testdata/control_ids_golden.txt from the registry")
```

(Merge `"flag"` into the import block.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./configuration/ -run 'TestControlIDs' -v`
Expected: FAIL. `TestControlIDsAreWellFormedAndUnique` reports every control with id `""`; the golden test fails on the missing file.

- [ ] **Step 3: Add the ID field and generate the assignments**

In `configuration/registry.go`, extend `ControlMeta` (after `Category string`):

```go
	// ID is the control's immutable identifier (CTRL-XXX), the rename-stable
	// key the platform hangs durable state on (#458). Assigned once from the
	// control's lowest registered issue code so ids follow the same numeric
	// blocks as the issues (1xx container images, 2xx variables, ...); frozen
	// afterwards by TestControlIDsMatchGolden. Never renumber an existing
	// control: rename the NAME if wording must change, the id stays.
	ID string
```

Generate the one-time assignment table. Write this throwaway program to `/tmp/genids/main.go` (do NOT commit it):

```go
package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
)

func main() {
	lowest := map[string]int{}
	for _, info := range control.AllCodes() {
		n, err := strconv.Atoi(strings.TrimPrefix(string(info.Code), "ISSUE-"))
		if err != nil || info.ControlName == "" {
			continue
		}
		if cur, ok := lowest[info.ControlName]; !ok || n < cur {
			lowest[info.ControlName] = n
		}
	}
	var names []string
	for _, e := range configuration.ControlsCatalog() {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	for _, name := range names {
		if n, ok := lowest[name]; ok {
			fmt.Printf("%s: CTRL-%03d\n", name, n)
		} else {
			fmt.Printf("%s: NO-ISSUE-CODE\n", name)
		}
	}
}
```

Run: `cd /tmp/genids && go mod init genids && go mod edit -replace github.com/getplumber/plumber=<repo-root> && go mod tidy && go run .` (or simpler: drop the file as `configuration/genids_test.go` with a `TestGenerateIDs` that t.Logs the table, run it once, then DELETE it before committing).

Paste each printed id into the matching `controlsMeta` entry as `ID: "CTRL-NNN",`. For any control printed as `NO-ISSUE-CODE`: give it the next free number in the hundred-block matching its Category (e.g. a Repository Hygiene control gets the next free CTRL-9xx), and note which in the commit message.

- [ ] **Step 4: Seed the golden and verify everything passes**

Run: `mkdir -p configuration/testdata && go test ./configuration/ -run TestControlIDsMatchGolden -update-ids`
Then: `go test ./configuration/ -v -run 'TestControlIDs'`
Expected: both PASS. Inspect `configuration/testdata/control_ids_golden.txt`: one `CTRL-NNN name` pair per line, all 66 controls present.

- [ ] **Step 5: Run the package suite and commit**

Run: `go test ./configuration/`
Expected: PASS (existing catalog tests unaffected).

```bash
git add configuration/registry.go configuration/registry_id_test.go configuration/testdata/control_ids_golden.txt
git commit -m "feat(catalog): immutable CTRL-XXX ids for every control (#458)"
```

---

### Task 2: Control descriptions in the registry

**Files:**
- Modify: `configuration/registry.go` (all `controlsMeta` entries)
- Create: `configuration/registry_description_test.go`

**Interfaces:**
- Consumes: `controlsMeta`, `ControlsCatalog()`, and `control.AllCodes()` as the wording source (read-only, from the sibling package via the test's import if needed - see Step 3 note).
- Produces: `ControlMeta.Description string` populated for every entry. Later tasks read `entry.Description`.

- [ ] **Step 1: Write the failing test**

Create `configuration/registry_description_test.go`:

```go
package configuration

import (
	"strings"
	"testing"
)

// Every control carries a one-sentence description: the CLI's own wording,
// exported so the platform console and docs never author a divergent copy
// (#458). Non-empty, sentence-shaped, and not a lazy DisplayName echo.
func TestEveryControlHasADescription(t *testing.T) {
	for _, e := range ControlsCatalog() {
		d := strings.TrimSpace(e.Description)
		if d == "" {
			t.Errorf("control %q has no Description", e.Name)
			continue
		}
		if !strings.HasSuffix(d, ".") {
			t.Errorf("control %q Description does not end with a period: %q", e.Name, d)
		}
		if d == e.DisplayName || d == e.DisplayName+"." {
			t.Errorf("control %q Description is just the DisplayName; write a real sentence", e.Name)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./configuration/ -run TestEveryControlHasADescription -v`
Expected: FAIL listing every control with no Description.

- [ ] **Step 3: Author the descriptions**

Add to `ControlMeta` (after `ID string`):

```go
	// Description is the one-sentence, user-facing explanation of what the
	// control verifies: the CLI's own wording, served to the platform and
	// docs so no consumer authors a divergent copy (#458).
	Description string
```

Then add `Description: "..."` to every `controlsMeta` entry. Source the wording from the control's registered issue codes in `control/codes.go` (`errorCodeRegistry` entries whose `ControlName` matches): condense the issue Titles/Descriptions into ONE sentence stating what the control verifies. Rules: active voice, starts with "Verifies", "Requires", "Flags" or "Detects", ends with a period, no em dashes. Worked examples to match in tone:

```go
	"branchMustBeProtected": {
		// ...existing fields...
		Description: "Verifies that the analyzed branch is protected so direct pushes and force pushes are blocked by the platform's branch protection rules.",
	},
	"containerImageMustNotUseForbiddenTags": {
		Description: "Flags container images referenced by mutable or forbidden tags (such as latest) and, when configured, requires images to be pinned by digest.",
	},
	"cicdVariablesMustBeProtected": {
		Description: "Verifies that CI/CD settings variables are marked protected so they are not exposed to pipelines running on unprotected branches.",
	},
	"actionsMustBePinnedByCommitSha": {
		Description: "Requires third-party GitHub Actions to be pinned to a full commit SHA instead of a mutable tag or branch reference.",
	},
	"pipelineMustNotEnableDebugTrace": {
		Description: "Detects pipelines that enable CI debug tracing, which prints masked variable values into job logs.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache": {
		Description: "Flags release and publish jobs that restore a build cache whose key is not scoped to the release ref, closing the cross-branch cache poisoning vector.",
	},
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./configuration/ -run TestEveryControlHasADescription -v`
Expected: PASS.

- [ ] **Step 5: Run the package suite and commit**

Run: `go test ./configuration/`
Expected: PASS.

```bash
git add configuration/registry.go configuration/registry_description_test.go
git commit -m "feat(catalog): one-sentence description for every control (#458)"
```

---

### Task 3: Issue-code immutability contract + rego literal pin

**Files:**
- Modify: `control/codes.go` (doc comment on `ErrorCode` only)
- Create: `control/codes_contract_test.go`

**Interfaces:**
- Consumes: `control.AllCodes()`, the `policies/*.rego` files on disk.
- Produces: contract guarantees only (tests); no new API. Closes the #448 residual: no rego-emitted code can exist outside the registry.

- [ ] **Step 1: Write the failing-or-passing contract tests**

Create `control/codes_contract_test.go`:

```go
package control

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// ISSUE-XXX codes are the immutable ids of issue types (#458): the platform
// keys durable state on them, so a code is never renumbered and never
// reused. Uniqueness across the registry is the enforceable half of that
// contract; never-reuse is enforced by review of this file's diff.
func TestIssueCodesAreUnique(t *testing.T) {
	seen := map[ErrorCode]string{}
	for _, info := range AllCodes() {
		if prev, dup := seen[info.Code]; dup {
			t.Errorf("code %s registered twice (%q and %q)", info.Code, prev, info.Title)
		}
		seen[info.Code] = info.Title
	}
}

// Every ISSUE-XXX literal in the rego policies is a registered code. An
// unregistered code would ship findings with no title, no severity and a
// message-only identity that collapses N findings into one platform issue
// (#448): this pin makes that impossible to merge.
func TestEveryRegoIssueCodeIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, info := range AllCodes() {
		registered[string(info.Code)] = true
	}

	pattern := regexp.MustCompile(`ISSUE-\d+`)
	files, err := filepath.Glob(filepath.Join("..", "policies", "*.rego"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no rego policies found: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range pattern.FindAllString(string(data), -1) {
			if !registered[code] {
				t.Errorf("%s emits %s which is not registered in control/codes.go; register it (and its identity declaration) before shipping", filepath.Base(f), code)
			}
		}
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./control/ -run 'TestIssueCodesAreUnique|TestEveryRegoIssueCodeIsRegistered' -v`
Expected: PASS if the registry is already complete (likely). If `TestEveryRegoIssueCodeIsRegistered` FAILS, the failure lists real unregistered codes: STOP and report them in the task summary instead of registering them yourself (registering a code needs severity/title decisions, which is Thomas's call).

- [ ] **Step 3: Document the contract on the type**

In `control/codes.go`, extend the `ErrorCode` doc comment to:

```go
// ErrorCode represents a unique Plumber issue code (ISSUE-XXX format).
//
// ISSUE codes are immutable identifiers (#458): the platform keys durable
// state (issues, history, dismissals) on them. A code is never renumbered,
// never reused for a different meaning, and survives any rename of titles
// or control names. TestIssueCodesAreUnique pins uniqueness;
// TestEveryRegoIssueCodeIsRegistered pins that no policy emits an
// unregistered code.
type ErrorCode string
```

- [ ] **Step 4: Run the package suite**

Run: `go test ./control/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control/codes.go control/codes_contract_test.go
git commit -m "test(catalog): pin issue-code immutability and rego registration (#458, #448)"
```

---

### Task 4: Config-schema reflection engine

**Files:**
- Create: `configuration/schema.go`
- Create: `configuration/schema_test.go`

**Interfaces:**
- Consumes: the `ControlsConfig` struct and its `*ControlConfig` field types (plumberconfig.go), stdlib `reflect`.
- Produces (exact, later tasks depend on these):

```go
type SchemaField struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"` // "string" | "bool" | "integer" | "number" | "array" | "object"
	Optional    bool          `json:"optional"`
	Description string        `json:"description,omitempty"`
	Elem        *SchemaField  `json:"elem,omitempty"`   // array item or map value type
	Fields      []SchemaField `json:"fields,omitempty"` // object members, struct order
	Enum        []string      `json:"enum,omitempty"`
	Default     string        `json:"default,omitempty"`
}
type ControlConfigSchema struct {
	Control string        `json:"control"`
	Fields  []SchemaField `json:"fields"`
}
func reflectControlSchemas() map[string]ControlConfigSchema
```

- [ ] **Step 1: Write the failing test**

Create `configuration/schema_test.go`:

```go
package configuration

import (
	"reflect"
	"testing"
)

// The schema STRUCTURE is reflected from the real config structs so it can
// never drift from the code (#458): field names come from yaml tags, types
// from Go types, optionality from pointers/omitempty. Three representative
// controls pin the walker: flat bool-only, flat with arrays, and nested.
func TestReflectControlSchemas(t *testing.T) {
	schemas := reflectControlSchemas()

	t.Run("every ControlsConfig control field yields a schema", func(t *testing.T) {
		typ := reflect.TypeOf(ControlsConfig{})
		for i := 0; i < typ.NumField(); i++ {
			name := yamlName(typ.Field(i))
			if name == "" {
				continue
			}
			if _, ok := schemas[name]; !ok {
				t.Errorf("control %q has no reflected schema", name)
			}
		}
	})

	t.Run("enabled-only control is a single optional bool", func(t *testing.T) {
		s := schemas["cicdVariablesMustBeProtected"]
		if len(s.Fields) != 1 {
			t.Fatalf("fields = %+v, want exactly [enabled]", s.Fields)
		}
		f := s.Fields[0]
		if f.Name != "enabled" || f.Type != "bool" || !f.Optional {
			t.Errorf("enabled field = %+v, want optional bool named enabled", f)
		}
	})

	t.Run("forbidden-tags control carries its array field", func(t *testing.T) {
		s := schemas["containerImageMustNotUseForbiddenTags"]
		var found bool
		for _, f := range s.Fields {
			if f.Type == "array" {
				found = true
				if f.Elem == nil || f.Elem.Type != "string" {
					t.Errorf("array field %q Elem = %+v, want string items", f.Name, f.Elem)
				}
			}
		}
		if !found {
			t.Errorf("no array field reflected: %+v", s.Fields)
		}
	})

	t.Run("nested structs become object fields with members", func(t *testing.T) {
		s := schemas["mergeRequestSettingsMustBeCompliant"]
		var found bool
		for _, f := range s.Fields {
			if f.Type == "object" && len(f.Fields) > 0 {
				found = true
			}
		}
		if !found {
			t.Errorf("expected at least one object field with members, got %+v", s.Fields)
		}
	})
}
```

Note for the implementer: before writing assertions, read the three referenced structs in `configuration/plumberconfig.go` (`EnabledOnlyControlConfig`, `ImageForbiddenTagsControlConfig`, `MRSettingsControlConfig`). Each subtest pins an invariant, not a specific struct: if `EnabledOnlyControlConfig` carries more than one field, assert on the `enabled` field's shape instead of the count; if `ImageForbiddenTagsControlConfig` has no `[]string` field or `MRSettingsControlConfig` no nested struct, swap in a control struct that does (grep the control config structs) and keep the invariant (arrays carry Elem, structs recurse into object Fields) unchanged.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./configuration/ -run TestReflectControlSchemas -v`
Expected: FAIL with `undefined: reflectControlSchemas` (and `yamlName`).

- [ ] **Step 3: Implement the walker**

Create `configuration/schema.go`:

```go
package configuration

import (
	"reflect"
	"strings"
)

// SchemaField describes one field of a control's configuration: name and
// nesting from the yaml tags, type from the Go type, optionality from
// pointers/omitempty. Structure is REFLECTED from the real config structs
// so it can never drift from the code; Description/Enum/Default are welded
// on from the authored table in schema_docs.go (#458).
type SchemaField struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Optional    bool          `json:"optional"`
	Description string        `json:"description,omitempty"`
	Elem        *SchemaField  `json:"elem,omitempty"`
	Fields      []SchemaField `json:"fields,omitempty"`
	Enum        []string      `json:"enum,omitempty"`
	Default     string        `json:"default,omitempty"`
}

// ControlConfigSchema is the machine-readable shape of one control's
// .plumber.yaml block: what the platform renders config forms from and
// validates against, generated from the CLI's own structs (#458).
type ControlConfigSchema struct {
	Control string        `json:"control"`
	Fields  []SchemaField `json:"fields"`
}

// yamlName returns the effective yaml key of a struct field, or "" when the
// field is skipped (yaml:"-" or unexported).
func yamlName(f reflect.StructField) string {
	if f.PkgPath != "" {
		return ""
	}
	tag := f.Tag.Get("yaml")
	name := strings.Split(tag, ",")[0]
	if name == "-" {
		return ""
	}
	if name == "" {
		return strings.ToLower(f.Name[:1]) + f.Name[1:]
	}
	return name
}

func yamlOmitempty(f reflect.StructField) bool {
	for _, opt := range strings.Split(f.Tag.Get("yaml"), ",")[1:] {
		if opt == "omitempty" {
			return true
		}
	}
	return false
}

// reflectControlSchemas walks ControlsConfig: each control-pointer field
// becomes one schema keyed by its yaml name, its struct type walked
// recursively into fields.
func reflectControlSchemas() map[string]ControlConfigSchema {
	out := map[string]ControlConfigSchema{}
	typ := reflect.TypeOf(ControlsConfig{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := yamlName(f)
		if name == "" {
			continue
		}
		t := f.Type
		for t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			continue
		}
		out[name] = ControlConfigSchema{Control: name, Fields: structFields(t)}
	}
	return out
}

func structFields(t reflect.Type) []SchemaField {
	var fields []SchemaField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := yamlName(f)
		if name == "" {
			continue
		}
		sf := typeToField(f.Type)
		sf.Name = name
		if f.Type.Kind() == reflect.Ptr || yamlOmitempty(f) {
			sf.Optional = true
		}
		fields = append(fields, sf)
	}
	return fields
}

func typeToField(t reflect.Type) SchemaField {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return SchemaField{Type: "string"}
	case reflect.Bool:
		return SchemaField{Type: "bool"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return SchemaField{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return SchemaField{Type: "number"}
	case reflect.Slice, reflect.Array:
		elem := typeToField(t.Elem())
		return SchemaField{Type: "array", Elem: &elem}
	case reflect.Map:
		elem := typeToField(t.Elem())
		return SchemaField{Type: "object", Elem: &elem}
	case reflect.Struct:
		return SchemaField{Type: "object", Fields: structFields(t)}
	default:
		return SchemaField{Type: "string"}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./configuration/ -run TestReflectControlSchemas -v`
Expected: PASS. If a subtest fails on a real struct's shape (e.g. an interface-typed field), extend `typeToField` for that kind rather than weakening the test.

- [ ] **Step 5: Run the package suite and commit**

Run: `go test ./configuration/`
Expected: PASS.

```bash
git add configuration/schema.go configuration/schema_test.go
git commit -m "feat(catalog): reflect control config schemas from the real structs (#458)"
```

---

### Task 5: Authored field docs + parity + public schema accessors

**Files:**
- Create: `configuration/schema_docs.go`
- Create: `configuration/schema_docs_test.go`
- Modify: `configuration/schema.go` (add the two public accessors at the end)

**Interfaces:**
- Consumes: `reflectControlSchemas()`, `SchemaField`, `ControlConfigSchema` (Task 4).
- Produces (exact, later tasks depend on these):

```go
func ConfigSchemaFor(controlName string) (ControlConfigSchema, bool)
func ConfigSchemas() []ControlConfigSchema // sorted by Control
```

- [ ] **Step 1: Write the failing parity test**

Create `configuration/schema_docs_test.go`:

```go
package configuration

import (
	"strings"
	"testing"
)

// collectPaths returns every dotted field path of a schema
// ("control.field" and "control.parent.child" for nested objects).
func collectPaths(prefix string, fields []SchemaField, out map[string]bool) {
	for _, f := range fields {
		p := prefix + "." + f.Name
		out[p] = true
		if len(f.Fields) > 0 {
			collectPaths(p, f.Fields, out)
		}
		if f.Elem != nil && len(f.Elem.Fields) > 0 {
			collectPaths(p+"[]", f.Elem.Fields, out)
		}
	}
}

// The reflected structure and the authored prose are welded together: a
// struct field without a doc entry fails here, and a doc entry matching no
// struct field fails here, so the exported schema can never drift from the
// code in either direction (#458, same pattern as the identity parity test).
func TestFieldDocsParity(t *testing.T) {
	reflected := map[string]bool{}
	for name, s := range reflectControlSchemas() {
		collectPaths(name, s.Fields, reflected)
	}
	for path := range reflected {
		doc, ok := controlFieldDocs[path]
		if !ok {
			t.Errorf("field %s has no entry in controlFieldDocs; describe it in schema_docs.go", path)
			continue
		}
		if strings.TrimSpace(doc.Description) == "" {
			t.Errorf("field %s has an empty Description", path)
		}
	}
	for path := range controlFieldDocs {
		if !reflected[path] {
			t.Errorf("controlFieldDocs entry %s matches no reflected field; remove the stale entry", path)
		}
	}
}

// The public accessors serve the welded schema: structure from reflection,
// prose and constraints from the table.
func TestConfigSchemaAccessors(t *testing.T) {
	s, ok := ConfigSchemaFor("cicdVariablesMustBeProtected")
	if !ok {
		t.Fatal("known control has no schema")
	}
	if len(s.Fields) == 0 || s.Fields[0].Description == "" {
		t.Errorf("schema fields not welded with docs: %+v", s.Fields)
	}
	if _, ok := ConfigSchemaFor("noSuchControl"); ok {
		t.Error("unknown control must return ok=false")
	}
	all := ConfigSchemas()
	if len(all) == 0 {
		t.Fatal("ConfigSchemas returned nothing")
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Control >= all[i].Control {
			t.Errorf("ConfigSchemas not sorted: %q before %q", all[i-1].Control, all[i].Control)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./configuration/ -run 'TestFieldDocsParity|TestConfigSchemaAccessors' -v`
Expected: FAIL with `undefined: controlFieldDocs`, `undefined: ConfigSchemaFor`.

- [ ] **Step 3: Author the docs table and accessors**

Create `configuration/schema_docs.go`:

```go
package configuration

import "sort"

// FieldDoc is the authored half of a schema field: the prose and
// constraints reflection cannot know. Structure lives in schema.go;
// TestFieldDocsParity welds the two so neither can drift.
type FieldDoc struct {
	Description string
	Enum        []string
	Default     string
}

// controlFieldDocs is keyed by dotted field path: "control.field",
// "control.parent.child" for nested objects, "control.list[].member" for
// struct-valued array items. Source each Description from the field's own
// doc comment in plumberconfig.go, condensed to one sentence.
var controlFieldDocs = map[string]FieldDoc{
	// Worked examples; the parity test enumerates every missing path.
	"cicdVariablesMustBeProtected.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"containerImageMustNotUseForbiddenTags.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	// ... every remaining path reported by TestFieldDocsParity ...
}

func applyDocs(prefix string, fields []SchemaField) []SchemaField {
	out := make([]SchemaField, len(fields))
	for i, f := range fields {
		p := prefix + "." + f.Name
		if doc, ok := controlFieldDocs[p]; ok {
			f.Description = doc.Description
			f.Enum = append([]string(nil), doc.Enum...)
			f.Default = doc.Default
		}
		if len(f.Fields) > 0 {
			f.Fields = applyDocs(p, f.Fields)
		}
		if f.Elem != nil && len(f.Elem.Fields) > 0 {
			elem := *f.Elem
			elem.Fields = applyDocs(p+"[]", f.Elem.Fields)
			f.Elem = &elem
		}
		out[i] = f
	}
	return out
}
```

Append to `configuration/schema.go`:

```go
// ConfigSchemaFor returns the welded schema (reflected structure plus
// authored docs) for one control, and whether the control has a config
// block at all.
func ConfigSchemaFor(controlName string) (ControlConfigSchema, bool) {
	s, ok := reflectControlSchemas()[controlName]
	if !ok {
		return ControlConfigSchema{}, false
	}
	s.Fields = applyDocs(controlName, s.Fields)
	return s, true
}

// ConfigSchemas returns every control's welded schema, sorted by control
// name so output is deterministic.
func ConfigSchemas() []ControlConfigSchema {
	reflected := reflectControlSchemas()
	out := make([]ControlConfigSchema, 0, len(reflected))
	for name := range reflected {
		s, _ := ConfigSchemaFor(name)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Control < out[j].Control })
	return out
}
```

(Move the `sort` import to whichever of the two files uses it.)

Now run `go test ./configuration/ -run TestFieldDocsParity` repeatedly: every failure names a missing path. For each, read that field's doc comment in `plumberconfig.go` and write the one-sentence entry. Repeat until the parity test passes. Do not delete struct fields to silence it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./configuration/ -run 'TestFieldDocsParity|TestConfigSchemaAccessors' -v`
Expected: PASS.

- [ ] **Step 5: Run the package suite and commit**

Run: `go test ./configuration/`
Expected: PASS.

```bash
git add configuration/schema.go configuration/schema_docs.go configuration/schema_docs_test.go
git commit -m "feat(catalog): authored field docs welded to reflected schemas by parity (#458)"
```

---

### Task 6: The Catalog aggregate

**Files:**
- Create: `control/catalog_document.go`
- Create: `control/catalog_document_test.go`

**Interfaces:**
- Consumes: `configuration.ControlsCatalog()` (with ID/Description from Tasks 1-2), `configuration.ConfigSchemaFor()` (Task 5), `AllCodes()` (this package).
- Produces (exact, Task 7 depends on these):

```go
type CatalogIssueType struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	DocURL      string `json:"docUrl"`
	ControlName string `json:"controlName"`
}
type CatalogControl struct {
	ID           string                             `json:"id"`
	Name         string                             `json:"name"`
	DisplayName  string                             `json:"displayName"`
	Category     string                             `json:"category"`
	Providers    []string                           `json:"providers"`
	Description  string                             `json:"description"`
	ConfigSchema *configuration.ControlConfigSchema `json:"configSchema,omitempty"`
	IssueCodes   []string                           `json:"issueCodes"`
}
type CatalogDocument struct {
	CatalogVersion int                `json:"catalogVersion"`
	CLIVersion     string             `json:"cliVersion"`
	Controls       []CatalogControl   `json:"controls"`
	IssueTypes     []CatalogIssueType `json:"issueTypes"`
}
func Catalog(cliVersion string) CatalogDocument
```

- [ ] **Step 1: Write the failing test**

Create `control/catalog_document_test.go`:

```go
package control

import "testing"

// Catalog is the single aggregate the platform imports and the catalog
// command serializes (#458): every control with its id, wording, schema and
// issue mapping, plus every issue type, in deterministic order.
func TestCatalogDocument(t *testing.T) {
	doc := Catalog("1.2.3")

	if doc.CatalogVersion != 1 || doc.CLIVersion != "1.2.3" {
		t.Fatalf("envelope = v%d cli %q, want v1 cli 1.2.3", doc.CatalogVersion, doc.CLIVersion)
	}
	if len(doc.Controls) == 0 || len(doc.IssueTypes) == 0 {
		t.Fatal("empty catalog")
	}

	byName := map[string]CatalogControl{}
	for i, c := range doc.Controls {
		byName[c.Name] = c
		if c.ID == "" || c.DisplayName == "" || c.Description == "" || c.Category == "" {
			t.Errorf("control %q missing id/display/description/category: %+v", c.Name, c)
		}
		if i > 0 && doc.Controls[i-1].Name >= c.Name {
			t.Errorf("controls not sorted by name at %q", c.Name)
		}
	}

	// Every issue type's ControlName that exists in the registry appears in
	// that control's IssueCodes (the backlink inverted).
	for _, it := range doc.IssueTypes {
		if it.Code == "" || it.Severity == "" || it.Title == "" {
			t.Errorf("issue type missing basics: %+v", it)
		}
		c, ok := byName[it.ControlName]
		if !ok {
			continue // codes for benched/unregistered controls are allowed
		}
		var found bool
		for _, code := range c.IssueCodes {
			if code == it.Code {
				found = true
			}
		}
		if !found {
			t.Errorf("issue %s not listed in control %q IssueCodes", it.Code, it.ControlName)
		}
	}

	// A control with a config block carries its schema.
	if c := byName["cicdVariablesMustBeProtected"]; c.ConfigSchema == nil {
		t.Error("cicdVariablesMustBeProtected has a config block but no schema in the catalog")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./control/ -run TestCatalogDocument -v`
Expected: FAIL with `undefined: Catalog`.

- [ ] **Step 3: Implement the aggregate**

Create `control/catalog_document.go` with the four types from the Interfaces block above (copy them verbatim, including json tags), then:

```go
// Catalog assembles the CLI's whole catalog into one document: the single
// source the platform imports (Go) and the catalog command serializes
// (JSON) so no consumer maintains a divergent copy (#458). cliVersion is
// injected by the caller (cmd passes the build version; tests pass a
// constant) so the document itself stays deterministic.
func Catalog(cliVersion string) CatalogDocument {
	codesByControl := map[string][]string{}
	issueTypes := make([]CatalogIssueType, 0)
	for _, info := range AllCodes() {
		issueTypes = append(issueTypes, CatalogIssueType{
			Code:        string(info.Code),
			Severity:    string(info.Severity),
			Title:       info.Title,
			Description: info.Description,
			Remediation: info.Remediation,
			DocURL:      info.DocURL,
			ControlName: info.ControlName,
		})
		if info.ControlName != "" {
			codesByControl[info.ControlName] = append(codesByControl[info.ControlName], string(info.Code))
		}
	}
	sort.Slice(issueTypes, func(i, j int) bool { return issueTypes[i].Code < issueTypes[j].Code })
	for _, codes := range codesByControl {
		sort.Strings(codes)
	}

	entries := configuration.ControlsCatalog() // already sorted by name
	controls := make([]CatalogControl, 0, len(entries))
	for _, e := range entries {
		c := CatalogControl{
			ID:          e.ID,
			Name:        e.Name,
			DisplayName: e.DisplayName,
			Category:    e.Category,
			Providers:   e.Providers,
			Description: e.Description,
			IssueCodes:  append([]string{}, codesByControl[e.Name]...),
		}
		if s, ok := configuration.ConfigSchemaFor(e.Name); ok {
			schema := s
			c.ConfigSchema = &schema
		}
		controls = append(controls, c)
	}

	return CatalogDocument{
		CatalogVersion: 1,
		CLIVersion:     cliVersion,
		Controls:       controls,
		IssueTypes:     issueTypes,
	}
}
```

(Imports: `sort`, `github.com/getplumber/plumber/configuration`.)

Note: `IssueCodes: append([]string{}, ...)` deliberately yields `[]` not `nil` so the JSON serializes as `[]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./control/ -run TestCatalogDocument -v`
Expected: PASS. A failure like "no reflected schema" for a control name here means the registry name and the yaml key disagree; report it, do not paper over it.

- [ ] **Step 5: Run the package suite and commit**

Run: `go test ./control/`
Expected: PASS.

```bash
git add control/catalog_document.go control/catalog_document_test.go
git commit -m "feat(catalog): aggregate Catalog() document over controls, schemas and issue types (#458)"
```

---

### Task 7: The `plumber catalog` command + golden JSON

**Files:**
- Create: `cmd/catalog.go`
- Create: `cmd/catalog_test.go`
- Create: `cmd/testdata/catalog_golden.json`

**Interfaces:**
- Consumes: `control.Catalog(cliVersion)` (Task 6), `Version` var (cmd/version.go), cobra `rootCmd` (cmd/).
- Produces: the `plumber catalog` subcommand; `cmd/testdata/catalog_golden.json` freezing the wire shape.

- [ ] **Step 1: Write the failing test**

Create `cmd/catalog_test.go`:

```go
package cmd

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var updateCatalog = flag.Bool("update-catalog", false, "rewrite testdata/catalog_golden.json")

// The catalog JSON is the docs site's build input and the platform's
// fallback wire format (#458): its shape is a contract, frozen here.
// Consumers are forward-tolerant, so ADDING fields only needs a golden
// refresh; removing or renaming any is the break this test exists to catch.
func TestCatalogCommandGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCatalogJSON(&buf, "test"); err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("catalog output is not JSON: %v", err)
	}
	if doc["catalogVersion"] != float64(1) || doc["cliVersion"] != "test" {
		t.Fatalf("envelope wrong: %v %v", doc["catalogVersion"], doc["cliVersion"])
	}

	const golden = "testdata/catalog_golden.json"
	if *updateCatalog {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (seed once with -update-catalog): %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Error("catalog JSON diverged from golden. If the change is additive (new field, new control, wording), refresh deliberately: go test ./cmd/ -run TestCatalogCommandGolden -update-catalog. If a field was removed or renamed, that is a consumer break: do not refresh, fix the code.")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestCatalogCommandGolden -v`
Expected: FAIL with `undefined: writeCatalogJSON`.

- [ ] **Step 3: Implement the command**

Create `cmd/catalog.go`:

```go
package cmd

import (
	"encoding/json"
	"io"
	"os"

	"github.com/getplumber/plumber/control"
	"github.com/spf13/cobra"
)

// writeCatalogJSON serializes the full catalog document. Split from the
// cobra handler so the golden test exercises the exact bytes the command
// emits, with a caller-controlled version for determinism.
func writeCatalogJSON(w io.Writer, cliVersion string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(control.Catalog(cliVersion))
}

// catalogCmd dumps the CLI's control/issue catalog as JSON: ids, names,
// descriptions, categories, providers, config schemas and issue types
// (#458). The platform imports control.Catalog() directly; this command is
// the same document for non-Go consumers (the docs site build).
var catalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Print the control and issue catalog as JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		return writeCatalogJSON(os.Stdout, Version)
	},
}

func init() {
	rootCmd.AddCommand(catalogCmd)
}
```

- [ ] **Step 4: Seed the golden and verify it passes**

Run: `mkdir -p cmd/testdata && go test ./cmd/ -run TestCatalogCommandGolden -update-catalog && go test ./cmd/ -run TestCatalogCommandGolden -v`
Expected: PASS. Eyeball `cmd/testdata/catalog_golden.json`: controls sorted, schemas present, issue types complete.

Then a live smoke: `go build -o /tmp/plumber-catalog . && /tmp/plumber-catalog catalog | head -30`
Expected: pretty JSON starting with `"catalogVersion": 1`.

- [ ] **Step 5: Run the package suite and commit**

Run: `go test ./cmd/`
Expected: PASS.

```bash
git add cmd/catalog.go cmd/catalog_test.go cmd/testdata/catalog_golden.json
git commit -m "feat(catalog): plumber catalog command with golden-pinned JSON contract (#458)"
```

---

### Task 8: Full verification and PR

**Files:**
- No new files. Verification + push only.

**Interfaces:**
- Consumes: everything above.
- Produces: the pushed branch and the PR.

- [ ] **Step 1: Full battery**

Run, each expected clean:
- `gofmt -l cmd control configuration finding gitlab github policies` (empty output)
- `go build ./...`
- `go test ./...` (full suite green)
- `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@5d1e709b7be35cb2025444e19de266b056b7b7ee && golangci-lint run` (0 issues)

- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin feat/catalog-source-of-truth
```

Open a PR titled `feat(catalog): export the control/issue catalog as the single source of truth` with body: closes #458 summary of the four deliverables (ids, descriptions, schemas, catalog command), the parity/golden guard list, and the out-of-scope note (platform wiring and docs-site integration are consumer-side tasks). Reference the spec path. End the body with the repo's standard generated-with footer.

- [ ] **Step 3: Wait for CI green and report**

Watch `gh pr checks`; all checks must pass. Report the PR URL, any golden files created, and any control listed as NO-ISSUE-CODE in Task 1 or reported unregistered in Task 3.
