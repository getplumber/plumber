# Pipeline Bill of Materials (PBOM)

> ⚠️ **EARLY STAGE FEATURE** ⚠️
>
> PBOM is a **new feature being built from the ground up**. Unlike traditional SBOMs for application code, there is no existing recognized standard for documenting CI/CD pipeline dependencies. Plumber is leading in this space.
>
> 📣 Your feedback shapes the future: [open an issue](https://github.com/getplumber/plumber/issues) with suggestions.

---

## Overview

A **PBOM (Pipeline Bill of Materials)** is an inventory of all dependencies used in a CI/CD pipeline: container images, GitLab CI components, templates, and includes. Think of it as an SBOM, but for your pipeline infrastructure instead of your application code.

Plumber generates PBOMs in two formats:

| Format | Flag | Best for |
|--------|------|----------|
| **Plumber PBOM** | `--pbom <file>` | Detailed pipeline-specific inventory with compliance metadata |
| **CycloneDX SBOM** | `--pbom-cyclonedx <file>` | Integration with Gitlab reporting, security tools (Grype, Trivy, Dependency-Track) |

```bash
# Generate both
plumber analyze --pbom pbom.json --pbom-cyclonedx pipeline-sbom.json
```

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

```json
{
  "pbomVersion": "1.0.0",
  "generatedAt": "2026-02-09T15:26:20Z",
  "project": { ... },
  "containerImages": [ ... ],
  "includes": [ ... ],
  "summary": { ... }
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `pbomVersion` | string | PBOM specification version (currently `"1.0.0"`) |
| `generatedAt` | string | ISO 8601 timestamp of generation |
| `project` | object | Information about the analyzed project |
| `containerImages` | array | All container images used in the pipeline |
| `includes` | array | All includes (components, templates, local, remote, project) |
| `summary` | object | Aggregate statistics |

### `project` Object

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Full project path (e.g., `mygroup/myproject`) |
| `id` | number | GitLab project ID. Omitted if unavailable. |
| `gitlabUrl` | string | GitLab instance URL |
| `branch` | string | Branch that was analyzed. Only present when `--branch` is specified. |

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

Each entry represents a CI/CD include dependency. Fields vary by include type: only relevant fields appear in the output.

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Include type: `"component"`, `"template"`, `"local"`, `"remote"`, `"project"` |
| `location` | string | Path or URL of the include |
| `project` | string | Source project path. Only for `project` type includes. |
| `version` | string | Pinned version. Only for versioned includes. |
| `latestVersion` | string | Latest available version, when known. |
| `upToDate` | bool | Whether the include is on the latest version, when known. |
| `componentName` | string | Component name. Only for `component` type. |
| `fromCatalog` | bool | Whether it comes from the GitLab CI/CD Catalog. Only for `component` type. |
| `nested` | bool | Whether this is a nested include (included by another include). Only present when `true`. |
| `overridden` | bool | Whether this include's jobs are overridden with forbidden CI/CD keywords. Only present when `true`. |
| `overriddenJobs` | array | Details of which jobs are overridden and with which keywords. Only present when `overridden` is `true`. |

Each entry in `overriddenJobs[]`:

| Field | Type | Description |
|-------|------|-------------|
| `jobName` | string | Name of the overridden job |
| `overriddenKeys` | string[] | Forbidden CI/CD keywords found in the override (e.g., `script`, `image`, `rules`) |

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

### `summary` Object

All fields are always present (default to `0`).

| Field | Type | Description |
|-------|------|-------------|
| `totalImages` | number | Total container images found |
| `uniqueRegistries` | number | Number of distinct container registries |
| `totalIncludes` | number | Total includes of all types |
| `components` | number | GitLab CI/CD component includes |
| `projectIncludes` | number | Cross-project file includes |
| `localIncludes` | number | Local file includes |
| `remoteIncludes` | number | Remote URL includes |
| `templates` | number | GitLab template includes |

---

## Format 2: CycloneDX SBOM (`--pbom-cyclonedx`)

The CycloneDX output follows the [CycloneDX 1.5 specification](https://cyclonedx.org/docs/1.5/json/) for compatibility with standard security tools.

### Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": { ... },
  "components": [ ... ]
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `bomFormat` | string | Always `"CycloneDX"` |
| `specVersion` | string | CycloneDX spec version (`"1.5"`) |
| `serialNumber` | string | Unique BOM identifier (URN UUID) |
| `version` | number | BOM version (always `1`) |
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

**PURL format for includes:**

```
pkg:gitlab/org/component@version          (components)
pkg:gitlab/project/path/file@version      (project includes)
pkg:generic/sanitized-location@version    (other types)
```

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
| `plumber:nested` | includes | `"true"` if nested include |
| `plumber:overridden` | includes | `"true"` if the include's jobs are overridden with forbidden keywords |
| `plumber:overridden-job` | includes | `"jobName:key1,key2"` — one property per overridden job with its forbidden keys |
| `plumber:gitlab-url` | metadata | GitLab instance URL |
| `plumber:project-id` | metadata | GitLab project ID |

---

## GitLab CI Integration

When using the Plumber component in GitLab CI, the CycloneDX output is automatically uploaded as a [GitLab CycloneDX report](https://docs.gitlab.com/ci/yaml/artifacts_reports/#artifactsreportscyclonedx). GitLab natively understands this format and will display the dependency list in the pipeline's **Licenses** tab (GitLab Ultimate) or as a downloadable artifact (all tiers).

```yaml
include:
  - component: gitlab.com/getplumber/plumber/plumber@v0.1.27
```

Both `plumber-pbom.json` (native PBOM) and `plumber-cyclonedx-sbom.json` (CycloneDX) are generated and stored as pipeline artifacts by default.

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
