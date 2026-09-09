# Catalog as single source of truth (issue #458)

Date: 2026-09-08
Status: approved (brainstorm with Thomas, 2026-09-08)
Issue: https://github.com/getplumber/plumber/issues/458

## Problem

The CLI owns the control and issue-type catalog (the one-engine rule), but parts of it are authored here without being exported: per-control config schemas, control descriptions, and rename-stable ids. The platform and getplumber.io are forced to hand-maintain second copies that drift from the CLI's own definitions.

## Ground truth (what already exists on main, not rebuilt)

- `configuration.ControlsCatalog()` / `ControlMetaFor()`: name, providers, displayName, category (#440).
- `control.AllCodes()` / `ErrorCodeInfo`: per-issue Title, Description, Remediation, Severity, DocURL, ControlName, per-provider overrides.
- `finding/identity/parity_test.go`: every registered code has an identity declaration and vice versa.
- `gitlab.DeriveIncludeJobs`: the case-divergent nested-include bug is fixed (`strings.EqualFold`).

## Decisions (locked in brainstorm)

1. **Surface: Go API + CLI command.** The platform (which imports this module) consumes Go accessors; a `plumber catalog` command dumps the same document as JSON for the docs site. One source, two doors.
2. **Schemas: reflection + authored table + parity test.** Structure comes from the real config structs; prose and constraints from one authored table; a parity test welds them together.
3. **Ids: CTRL-XXX for controls, ISSUE-XXX reaffirmed for issue types.** Same numeric blocks as the issue codes; golden-pinned. No second numbering scheme.
4. **Docs scope: JSON contract only.** The CLI deliverable stops at the command plus its documented, golden-tested output. Site build integration is the site repo's task.

## Design

### Architecture

All catalog data stays where it is authored today; we extend it in place and add one aggregator:

- `configuration.ControlMeta` gains `ID string` (CTRL-XXX) and `Description string`. The `controlsMeta` table entries are extended in place.
- New `configuration.ConfigSchemaFor(controlName) (ControlConfigSchema, bool)` and `ConfigSchemas() map[string]ControlConfigSchema`.
- New aggregate `control.Catalog() CatalogDocument`: per control `{id, name, displayName, category, providers, description, configSchema, issueCodes}` (control-to-issue mapping derived from the existing `ErrorCodeInfo.ControlName` backlink), plus the issue-type list from `AllCodes()`.
- New `plumber catalog` command printing that document as JSON in a versioned envelope: `{catalogVersion: 1, cliVersion, controls: [...], issueTypes: [...]}`. JSON only, deterministic ordering, golden-tested.

### Config schemas (reflection + authored table + parity)

- Structure is **reflected** from the real `*ControlConfig` structs referenced by `configuration.ControlsConfig`: yaml tag = field name; pointer / omitempty = optional; Go type maps to `string | bool | integer | number | array | object`; nested structs recurse (e.g. MR settings sub-objects); maps become `object` with a value type.
- What reflection cannot know - per-field **description**, and optional `enum` / `default` - lives in one authored table keyed `controlName.field` (dotted path for nested fields).
- **Parity test**: fails when a reflected field has no table entry, or a table entry matches no reflected field. The schema can never drift from the code (same pattern as the identity parity test).
- Output shape is JSON-Schema-ish (`type`, `properties`, `required`, `items`, `enum`, `default`, `description`) without claiming full JSON-Schema compliance.

### Immutable ids

- Each control gets `CTRL-XXX` following the same numeric block as its issue codes (1xx container images, 2xx variables, ...), assigned once in `controlsMeta`.
- Guards: format (`^CTRL-\d{3}$`) and uniqueness test, plus a **golden id-to-name pin**: renaming a control surfaces as a reviewable golden diff; changing an existing id fails loudly.
- ISSUE-XXX is documented (comment on `ErrorCode` + a uniqueness / never-reused test) as the issue-type immutable id.

### #448 residual

Audit whether rego-emitted ISSUE codes are forced into the `codes.go` registry (`policies/identity_harness_test.go` coverage); add the missing pin if not. Expected to be test-only.

### Testing

- TDD per slice (red before green).
- Parity tests as above; golden test on the `plumber catalog` JSON output (consumers are forward-tolerant per the repo's golden-test taxonomy).
- No analysis behavior changes: the full suite must stay green with no changes outside the touched files.

## Out of scope

- Platform `GET /controls` wiring (monorepo task).
- getplumber.io build integration (site repo task).
- Any change to analysis or scoring behavior.
