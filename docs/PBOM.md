# Pipeline Bill of Materials (PBOM)

> ⚠️ **EARLY STAGE FEATURE** ⚠️
>
> PBOM is a **new feature being built from the ground up**. Unlike traditional SBOMs for application code, there is no existing recognized standard for documenting CI/CD pipeline dependencies. Plumber is leading in this space.
>
> 📣 Your feedback shapes the future: [open an issue](https://github.com/getplumber/plumber/issues) with suggestions.

---

## Overview

A **PBOM (Pipeline Bill of Materials)** is an inventory of all dependencies used in a CI/CD pipeline. Think of it as an SBOM, but for your pipeline infrastructure instead of your application code. The inventory contents differ per provider:

| Provider | Container images | "Includes" equivalent |
|---|---|---|
| **GitLab** | `image:` + `services:` blocks across all jobs | GitLab CI components, templates, project includes, local includes, remote URL includes |
| **GitHub** | `container:` + `services:` blocks across all jobs | Third-party action references (`uses: owner/repo@ref`) and reusable-workflow calls (`jobs.<name>.uses: …/.github/workflows/x.yml@ref`) |

The same two output formats are produced on both providers:

| Format | Flag | Best for |
|--------|------|----------|
| **Plumber PBOM** | `--pbom <file>` | Detailed pipeline-specific inventory with compliance metadata |
| **CycloneDX SBOM** | `--pbom-cyclonedx <file>` | Integration with GitLab reporting, security tools (Grype, Trivy, Dependency-Track) |

```bash
# Generate both
plumber analyze --pbom pbom.json --pbom-cyclonedx pipeline-sbom.json
```

The provider stamped into the PBOM is auto-detected from the active analyzer (`gitlab` or `github`); see the [`project`](#project-object) section for the per-provider field shape.

---

## Why CycloneDX (Not SPDX)?

| Aspect | CycloneDX | SPDX |
|--------|-----------|------|
| **Primary focus** | Security & vulnerability tracking | License compliance & provenance |
| **Tool ecosystem** | Grype, Trivy, Dependency-Track | Good, but security tools prefer CycloneDX |
| **Component types** | Native `container` type fits our use case | Primarily software packages |
| **Format** | Clean JSON, easy to generate and parse | More complex, verbose |
| **Standardization** | OWASP project | ISO/IEC 5962:2021 |

CycloneDX was chosen because Plumber's primary use case is pipeline security, and the tools in the ecosystem (Gitlab, Grype, Trivy, Dependency-Track) have first-class CycloneDX support. SPDX export could be added as a future enhancement for license compliance use cases.

---

## Vulnerability Detection: What to Expect

🔬 **Important:** The PBOM will show **few to no vulnerabilities** in most scanners. This is expected and by design.

| Component Type | Example | Has CVEs in Public Databases? |
|----------------|---------|-------------------------------|
| Docker images | `golang:1.22`, `alpine:3.18` | Limited (image metadata only) |
| GitLab CI components | `gitlab.com/components/sast` | **No** |
| GitLab templates | `Security/SAST.gitlab-ci.yml` | **No** |
| Remote/local includes | Custom YAML files | **No** |
| GitHub Actions | `actions/checkout@<sha>` | **Limited.** GitHub's own [security advisories database](https://github.com/advisories) tracks Action-specific CVEs — Plumber's `actionsMustNotCarryKnownCVEs` control (currently benched, ships next) checks every `uses:` against that DB at analysis time. Generic CVE scanners do not. |
| GitHub reusable workflows | `myorg/shared/.github/workflows/x.yml` | **No** |

**Why?** GitLab CI templates and components are configuration files, not software packages. No vulnerability database (NVD, OSV, etc.) tracks CVEs for them. Docker image PURLs provide metadata-level lookups only, not the full vulnerability surface of the image contents.

**The PBOM's value today is inventory and visibility:**
- Know exactly what's in your pipeline
- Track versions and detect outdated components
- Compliance documentation (prove what tools your pipelines use)
- Drift detection over time (e.g., via Dependency-Track)

**For actual image vulnerability scanning**, scan the images directly:

```bash
trivy image golang:1.22
grype docker.io/library/golang:1.22
```

---

## Format 1: Plumber PBOM (`--pbom`)

The native Plumber PBOM format provides a detailed, pipeline-specific inventory with compliance metadata from the analysis.

### Structure

Top-level keys are emitted in this order (human-readable flow: context → aggregates → score → inventories):

```json
{
  "pbomVersion": "1.0.0",
  "generatedAt": "2026-02-09T15:26:20Z",
  "project": { ... },
  "summary": { ... },
  "plumberScore": { ... },
  "containerImages": [ ... ],
  "includes": [ ... ]
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `pbomVersion` | string | PBOM specification version (currently `"1.0.0"`) |
| `generatedAt` | string | ISO 8601 timestamp of generation |
| `project` | object | Information about the analyzed project |
| `summary` | object | Aggregate statistics |
| `plumberScore` | object | Optional. Present when `plumber analyze` is run with `--score` and/or `--score-point`. Letter score (A–E), points (0–100), and severity counts (see below; per-code detail is exposed in the JSON `--output` only). |
| `containerImages` | array | All container images used in the pipeline |
| `includes` | array | All includes (components, templates, local, remote, project) |

### `project` Object

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Full project path (e.g., `mygroup/myproject` on GitLab, `owner/repo` on GitHub) |
| `provider` | string | `"gitlab"` or `"github"` — the analyzer that produced this PBOM |
| `url` | string | Provider host. Full URL on GitLab (`https://gitlab.com`); host or `host/api/v3` on GitHub |
| `id` | number | GitLab project ID. **GitLab-only** — omitted on the GitHub path |
| `gitlabUrl` | string | GitLab instance URL. **GitLab-only**, kept for backward compat with v0.2.x consumers; new readers should prefer `provider` + `url` |
| `branch` | string | Branch that was analyzed. Only present when `--branch` is specified. |

**GitLab example:**

```json
{
  "path": "mygroup/myproject",
  "id": 77812080,
  "provider": "gitlab",
  "url": "https://gitlab.com",
  "gitlabUrl": "https://gitlab.com"
}
```

**GitHub example:**

```json
{
  "path": "getplumber/plumber",
  "provider": "github",
  "url": "github.com"
}
```

### `containerImages[]` Array

Each entry represents a Docker/OCI image used in a pipeline job.

| Field | Type | Description |
|-------|------|-------------|
| `image` | string | Full image reference (e.g., `docker.io/library/golang:1.22`) |
| `registry` | string | Container registry (e.g., `docker.io`, `registry.gitlab.com`) |
| `name` | string | Image name without registry/tag (e.g., `golang`, `security-products/sobelow`) |
| `tag` | string | Image tag (e.g., `1.22`, `latest`). Omitted if no tag specified. |
| `jobs` | string[] | Pipeline jobs using this image |
| `authorized` | bool | Whether the image passes the authorized sources control. Only present when the control is enabled. |
| `forbiddenTag` | bool | Whether the image uses a forbidden tag. Only present when the control is enabled. |

**Example:**

```json
{
  "image": "docker.io/golangci/golangci-lint:latest",
  "registry": "docker.io",
  "name": "golangci/golangci-lint",
  "tag": "latest",
  "jobs": ["go_lint"],
  "authorized": true,
  "forbiddenTag": true
}
```

### `includes[]` Array

Each entry represents a CI/CD include dependency. Fields vary by include type: only relevant fields appear in the output. The `type` vocabulary is provider-scoped:

- **GitLab:** `"component"`, `"template"`, `"local"`, `"remote"`, `"project"`
- **GitHub:** `"action"` (third-party `uses: owner/repo@ref` step), `"reusableWorkflow"` (`jobs.<name>.uses: …/.github/workflows/x.yml@ref`)

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | See vocabulary above |
| `location` | string | Path or URL of the include. For GitHub `action` entries: `owner/repo`. For `reusableWorkflow`: `owner/repo/.github/workflows/x.yml` |
| `project` | string | GitLab: source project path for `project` includes. GitHub: action owner (e.g., `actions`) for `action` entries. |
| `version` | string | Pinned version. For GitHub `action` entries: the ref the workflow pinned (typically a 40-char SHA). For GitHub `reusableWorkflow`: the ref after `@`. |
| `latestVersion` | string | GitLab: latest available release of the include. GitHub: the human-readable `# vX.Y.Z` comment annotation that lives next to the SHA in the workflow file (when present). |
| `upToDate` | bool | GitLab: whether the include is on its latest release. GitHub `action` entries: tri-state pinning indicator — `false` means the ref is **not** a 40-char SHA (i.e. unpinned, ISSUE-104 candidate). |
| `componentName` | string | GitLab `component` only |
| `fromCatalog` | bool | GitLab `component` only |
| `nested` | bool | GitLab only: `true` when this include was pulled in by another include. |
| `overridden` | bool | GitLab only: `true` when one or more of the include's jobs were overridden locally with forbidden CI/CD keywords. |
| `overriddenJobs` | array | GitLab only: details of which jobs are overridden and with which keywords. Only present when `overridden` is `true`. JSON uses camelCase (`overriddenJobs`, `overriddenKeys`), not snake_case. |

Each entry in `overriddenJobs[]`:

| Field | Type | Description |
|-------|------|-------------|
| `jobName` | string | Name of the overridden job |
| `overriddenKeys` | string[] | CI/CD job keys redefined locally on top of the upstream include (the same “forbidden override” keywords Plumber uses for compliance, e.g., `script`, `image`, `rules`) |

**Example (component):**

```json
{
  "type": "component",
  "location": "gitlab.com/components/sast/sast",
  "version": "3.4.0",
  "latestVersion": "3.4.0",
  "upToDate": true,
  "componentName": "sast",
  "fromCatalog": true
}
```

**Example (overridden component):**

```json
{
  "type": "component",
  "location": "gitlab.com/components/secret-detection/secret-detection",
  "version": "2.2.0",
  "latestVersion": "2.2.0",
  "upToDate": true,
  "componentName": "secret-detection",
  "fromCatalog": true,
  "overridden": true,
  "overriddenJobs": [
    {
      "jobName": "secret_detection",
      "overriddenKeys": ["script"]
    }
  ]
}
```

**Example (local include):**

```json
{
  "type": "local",
  "location": ".gitlab/ci/test-jobs.yml"
}
```

**Example (GitHub action — pinned by SHA, with version comment):**

```json
{
  "type": "action",
  "location": "actions/checkout",
  "project": "actions",
  "version": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
  "latestVersion": "v6.0.2"
}
```

**Example (GitHub reusable workflow):**

```json
{
  "type": "reusableWorkflow",
  "location": "myorg/shared/.github/workflows/release.yml",
  "version": "v1.2.0"
}
```

### `summary` Object

All fields are always present (default to `0`). The provider-specific include counters are emitted as `0` on the other provider's path; CycloneDX consumers can ignore them.

| Field | Type | Description |
|-------|------|-------------|
| `totalImages` | number | Total container images found (both providers) |
| `uniqueRegistries` | number | Number of distinct container registries (both providers) |
| `totalIncludes` | number | Total includes of all types (both providers) |
| `components` | number | GitLab CI/CD component includes |
| `projectIncludes` | number | Cross-project file includes (GitLab) |
| `localIncludes` | number | Local file includes (GitLab) |
| `remoteIncludes` | number | Remote URL includes (GitLab) |
| `templates` | number | GitLab template includes |
| `actions` | number | GitHub third-party action references |
| `reusableWorkflows` | number | GitHub reusable-workflow calls |

### `plumberScore` Object (optional)

Present only when analysis is run with `--score` and/or `--score-point`. Field meanings and the exact formula (weights, log₂ growth, per-severity caps, Critical malus, letter thresholds) are documented in **[scoring.md](scoring.md)**. Issue severities per code follow the [issues](https://getplumber.io/docs/use-plumber/issues/) documentation.

| Field | Type | Description |
|-------|------|-------------|
| `profileId` | string | Scoring profile identifier (e.g. `scoring-v3`) |
| `rawPoints` | number | Points (0–100) after severity losses, before Critical malus |
| `finalPoints` | number | Points (0–100) after Critical malus when applicable |
| `score` | string | Letter score `A`–`E` derived from final points (set when either `--score` or `--score-point` is used) |
| `criticalMalusApplied` | bool | Whether any Critical issue forced final points into the E band |
| `criticalMalusMax` | number | Maximum final points when Critical malus applies (30) |
| `counts` | object | Issue counts by severity: `critical`, `high`, `medium`, `low` |

---

## Format 2: CycloneDX SBOM (`--pbom-cyclonedx`)

The CycloneDX output follows the [CycloneDX 1.5 specification](https://cyclonedx.org/docs/1.5/json/) for compatibility with standard security tools.

When `plumber analyze` is run with `--score` and/or `--score-point`, the BOM includes **metadata properties** (and duplicate properties on the root application component). Names use the `plumber:score-*` prefix for profile and counts, `plumber:points-*` for numeric points, and `plumber:score` for the letter:

| Property | Description |
|----------|-------------|
| `plumber:score-profile` | Scoring profile id |
| `plumber:points-raw` | Raw points (0–100), before Critical malus |
| `plumber:points-final` | Final points (0–100), after Critical malus |
| `plumber:score` | Letter score `A`–`E` (when `--score` or `--score-point` is used) |
| `plumber:score-count-critical` | Count of Critical issues |
| `plumber:score-count-high` | Count of High issues |
| `plumber:score-count-medium` | Count of Medium issues |
| `plumber:score-count-low` | Count of Low issues |
| `plumber:score-critical-malus` | `true` if Critical malus applied |

### Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:...",
  "metadata": { ... },
  "components": [ ... ]
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `bomFormat` | string | Always `"CycloneDX"` |
| `specVersion` | string | CycloneDX spec version (`"1.5"`) |
| `version` | number | BOM version (always `1`) |
| `serialNumber` | string | Unique BOM identifier (URN UUID) |
| `metadata` | object | BOM metadata (timestamp, tool, subject) |
| `components` | array | All pipeline components |

### `metadata` Object

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | ISO 8601 generation timestamp |
| `tools[]` | array | Tool that generated the BOM (`plumber`) |
| `component` | object | The subject of the BOM (the project being analyzed) |

### `components[]` Array

Each component represents a pipeline dependency. Two categories:

#### Container Images → `type: "container"`

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"container"` |
| `bom-ref` | string | Unique reference (e.g., `container:0`) |
| `name` | string | Image name |
| `version` | string | Image tag |
| `purl` | string | Package URL ([spec](https://github.com/package-url/purl-spec)) |

**PURL format for Docker images:**

```
pkg:docker/namespace/name@tag
pkg:docker/namespace/name@tag?repository_url=registry
```

Examples:
- `pkg:docker/library/golang@1.22` (Docker Hub official)
- `pkg:docker/golangci/golangci-lint@latest` (Docker Hub user)
- `pkg:docker/security-products/sobelow@6?repository_url=registry.gitlab.com` (GitLab registry)

#### Includes → mapped types

| Include Type | CycloneDX Type | Description |
|--------------|----------------|-------------|
| `component` | `library` | GitLab CI/CD components (reusable libraries) |
| `template` | `library` | GitLab CI templates (reusable pipeline libraries) |
| `local` | `file` | Local file includes |
| `remote` | `file` | Remote URL includes |
| `project` | `file` | Cross-project file includes |
| `action` | `library` | GitHub third-party actions (reusable libraries) |
| `reusableWorkflow` | `library` | GitHub reusable-workflow files (reusable pipeline libraries) |

**PURL format for includes:**

```
pkg:gitlab/org/component@version          (GitLab components)
pkg:gitlab/project/path/file@version      (GitLab project includes)
pkg:github/owner/repo@<sha-or-ref>        (GitHub actions)
pkg:github/owner/repo/.github/workflows/x.yml@ref   (GitHub reusable workflows)
pkg:generic/sanitized-location@version    (other types)
```

For GitHub actions the `version` field on the component is the actual ref the workflow pinned (typically a 40-char SHA when the project follows ISSUE-104 pinning); the `plumber:latest-version` property carries the human-readable `# vX.Y.Z` annotation when present.

### Custom Properties (`plumber:*`)

CycloneDX components carry Plumber-specific metadata as properties:

| Property | Applies To | Description |
|----------|------------|-------------|
| `plumber:registry` | containers | Container registry URL |
| `plumber:full-image` | containers | Full image reference |
| `plumber:jobs` | containers | Comma-separated list of jobs using this image |
| `plumber:authorized` | containers | `"true"` / `"false"` whether the image passes the authorized sources control |
| `plumber:forbidden-tag` | containers | `"true"` / `"false"` whether the image uses a forbidden tag |
| `plumber:include-type` | includes | Original include type (`component`, `template`, etc.) |
| `plumber:project` | includes | Source project for project includes |
| `plumber:latest-version` | includes | Latest available version |
| `plumber:up-to-date` | includes | `"true"` / `"false"` |
| `plumber:component-name` | includes | Component name |
| `plumber:from-catalog` | includes | `"true"` if from GitLab CI/CD Catalog |
| `plumber:nested` | includes | GitLab only. `"true"` if nested include |
| `plumber:overridden` | includes | GitLab only. `"true"` if the include's jobs are overridden with forbidden keywords |
| `plumber:overridden-job` | includes | GitLab only. `"jobName:key1,key2"` — one property per overridden job with its forbidden keys |
| `plumber:gitlab-url` | metadata.component | **GitLab only.** GitLab instance URL |
| `plumber:project-id` | metadata.component | **GitLab only.** GitLab project ID |
| `plumber:provider` | metadata.component | **GitHub only.** Always `"github"` — distinguishes the GitHub PBOM lineage from the historical GitLab one |
| `plumber:url` | metadata.component | **GitHub only.** GitHub host (`github.com` or a GHES host) |

---

## GitLab CI Integration

When using the Plumber component in GitLab CI, the CycloneDX output is automatically uploaded as a [GitLab CycloneDX report](https://docs.gitlab.com/ci/yaml/artifacts_reports/#artifactsreportscyclonedx). GitLab natively understands this format and will display the dependency list in the pipeline's **Licenses** tab (GitLab Ultimate) or as a downloadable artifact (all tiers).

```yaml
include:
  - component: gitlab.com/getplumber/plumber/plumber@v0.1.29
```

Both `plumber-pbom.json` (native PBOM) and `plumber-cyclonedx-sbom.json` (CycloneDX) are generated and stored as pipeline artifacts by default.

## GitHub Actions Integration

There is no first-class GitHub Actions reusable workflow yet (on the roadmap — see the README). For now, run the binary directly from a workflow step and surface the artifacts via standard `actions/upload-artifact`:

```yaml
jobs:
  plumber:
    runs-on: ubuntu-latest
    permissions:
      contents: read         # read workflow files + repo metadata
      # administration: read # uncomment if you also want ISSUE-505 (force-push, code-owner) evaluated
    steps:
      - uses: actions/checkout@<sha>   # pin via SHA per ISSUE-104
      - run: |
          curl -LO https://github.com/getplumber/plumber/releases/latest/download/plumber-linux-amd64
          chmod +x plumber-linux-amd64
          ./plumber-linux-amd64 analyze \
            --output plumber-report.json \
            --pbom plumber-pbom.json \
            --pbom-cyclonedx plumber-cyclonedx-sbom.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - uses: actions/upload-artifact@<sha>
        if: always()
        with:
          name: plumber-artifacts
          path: |
            plumber-report.json
            plumber-pbom.json
            plumber-cyclonedx-sbom.json
```

The CycloneDX file is the same shape as on GitLab — Dependency-Track, Grype, Trivy can ingest it directly.

---

## Tool Compatibility

The CycloneDX SBOM output has been tested with:

| Tool | Command | Notes |
|------|---------|-------|
| CycloneDX CLI | `cyclonedx validate --input-file sbom.json --input-format json` | Validates format correctness |
| Grype | `grype sbom:sbom.json` | Few/no vulns expected (see above) |
| Trivy | `trivy sbom sbom.json` | Few/no vulns expected (see above) |
| Dependency-Track | Upload via API or Web UI | Good for inventory tracking over time |

See [PBOM_TESTING.md](./PBOM_TESTING.md) for detailed setup and usage instructions for each tool.

---

## See Also

- [PBOM_TESTING.md](./PBOM_TESTING.md): Hands-on testing guide with security tools
- [CycloneDX 1.5 Specification](https://cyclonedx.org/docs/1.5/json/)
- [Package URL (PURL) Specification](https://github.com/package-url/purl-spec)
