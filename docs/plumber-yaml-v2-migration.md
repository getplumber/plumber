# `.plumber.yaml` v1 → v2 migration guide

Plumber's configuration schema moved from a flat top-level `controls:` block (schema v1) to a per-provider layout (schema v2). This page covers what changed, why, and how to upgrade.

---

## TL;DR — 30-second migration

```bash
plumber config migrate --in-place
```

Comments preserved. Original backed up to `.plumber.yaml.bak`. Done.

If you'd rather review first:

```bash
plumber config migrate              # writes .plumber.yaml.v2
diff .plumber.yaml .plumber.yaml.v2 # eyeball it
mv .plumber.yaml.v2 .plumber.yaml   # promote when satisfied
```

---

## What changed

### Before (schema v1)

```yaml
version: "1.0"           # or omitted entirely
controls:
  containerImageMustNotUseForbiddenTags:
    enabled: true
    tags: [latest]
  branchMustBeProtected:
    enabled: true
engine:
  enabled: true
```

### After (schema v2)

```yaml
version: "2.0"
gitlab:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
      tags: [latest]
    branchMustBeProtected:
      enabled: true
github:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
      trustedOwners: [actions, github]
```

Three things move:
1. **`controls:` is nested under a provider section.** The top-level `controls:` block is now `gitlab.controls:`. GitHub-only controls (e.g. `actionsMustBePinnedByCommitSha`) live under `github.controls:`.
2. **`engine:` is gone.** The Rego/OPA engine is the only engine in current Plumber and runs unconditionally. The setting was a vestigial migration-era toggle and has been removed.
3. **`version:` is now `"2.0"`.** The migrate tool bumps it for you.

---

## Why

The flat `controls:` block forced GitLab and GitHub to share configuration values for any control that exists on both providers. That's wrong for many controls:

| Control | GitLab needs | GitHub needs |
|---|---|---|
| `containerImageMustComeFromAuthorizedSources.trustedUrls` | `registry.gitlab.com/...`, `$CI_REGISTRY_IMAGE/...` | `ghcr.io/<org>/...` |
| `pipelineMustIncludeComponent.requiredGroups` | GitLab CI components | GitHub reusable workflows |
| `pipelineMustNotExecuteUnverifiedScripts.trustedUrls` | GitLab-internal mirrors | GitHub-internal mirrors |

Before v2 you could only set one value, so the same `.plumber.yaml` couldn't run cleanly against both providers. v2 fixes that.

The Rego rule code is unchanged — only the YAML location and values differ between providers.

---

## Backward compatibility

Plumber still accepts v1 files. When you load one:

- The flat `controls:` block is moved under `gitlab.controls:` in memory (the legacy schema was historically GitLab-only).
- A deprecation warning is printed: *"legacy config schema detected (top-level 'controls:'). Run `plumber config migrate` to upgrade to schema v2.0."*
- The `engine:` block, if present, prints a separate warning: *"engine.enabled has been removed in schema v1.0 and is now ignored."*

Your CI pipelines will continue to work without immediate change, but the warnings are real — v1 support will be removed in 1.0.0.

---

## Sharing config across providers

Use standard YAML anchors. Plumber doesn't add a custom inheritance grammar; the YAML library resolves anchors before Plumber sees the data.

```yaml
version: "2.0"

# Define once, reference twice.
_shared:
  pipelineMustNotEnableDebugTrace: &debug_trace
    enabled: true
    forbiddenVariables: [CI_DEBUG_TRACE, CI_DEBUG_SERVICES]

gitlab:
  controls:
    pipelineMustNotEnableDebugTrace: *debug_trace

github:
  controls:
    pipelineMustNotEnableDebugTrace: *debug_trace
```

Plumber ignores unknown top-level keys like `_shared:` (warning only), so the convention is safe.

---

## Edge cases the migrate tool handles

- **File already on v2** (`version: "2.0"` and no top-level `controls:`/`engine:`): no-op, exits with a friendly message.
- **Mixed v1 + v2** (top-level `controls:` AND a `gitlab.controls:` block already present): refused. Resolve manually — keep the nested `gitlab.controls:` and delete the top-level `controls:`. Plumber prints the rationale on exit.
- **Stale version field** (`version: "1.0"` but the file is already nested): silently bumps to `"2.0"`. Your intent is clear; no warning needed.
- **Comments** (head, foot, inline): preserved by the yaml.v3 node API. Verified on real configs.

---

## Deprecation timeline

| Version | v1 (flat) | v2 (per-provider) |
|---|---|---|
| 0.2.x | Loads natively (was the only schema). | Not understood. |
| 0.3.x (current) | Loads with deprecation warning + auto-conversion. | Loads natively. |
| 1.0.0 | **Rejected.** Run `plumber config migrate` before upgrading. | Loads natively. |

---

## Manual migration cookbook

If you'd rather not use `plumber config migrate` (e.g. you have a heavily-templated CI config and want to do it by hand):

1. Open `.plumber.yaml`.
2. At the top, change `version: "1.0"` → `version: "2.0"` (or add it if missing).
3. Wrap the entire `controls:` block under a new `gitlab:` key:
   ```yaml
   # Before
   controls:
     branchMustBeProtected:
       enabled: true
   # After
   gitlab:
     controls:
       branchMustBeProtected:
         enabled: true
   ```
4. Delete the `engine:` block entirely (if present).
5. If you want any GitHub-specific controls, add a `github:` section:
   ```yaml
   github:
     controls:
       actionsMustBePinnedByCommitSha:
         enabled: true
         trustedOwners: [actions, github]
   ```
6. Validate: `plumber config validate` (no warnings) and `plumber analyze` (still produces expected output).

---

## Questions / problems

If your migration runs into trouble, open an issue at [github.com/getplumber/plumber/issues](https://github.com/getplumber/plumber/issues) with the error message and a sanitised excerpt of your config.
