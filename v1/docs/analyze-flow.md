# The `analyze` flow

How the rewritten `plumber analyze` runs, stage by stage. It is the target of rewrite steps 8 to 12
in [project-structure.md](project-structure.md#rewrite-order), and its participants are the
packages of the [target layout](project-structure.md#target-layout). Today's CLI does several of
these stages differently; the last two sections list what stays and what changes.

A run has five stages before evaluation:

1. Preflight: check that the run can do what it is asked to do, such as a token that is set and
   has the rights the options need.
2. Source: a local run reads the clone on disk; a remote run clones the project in memory.
3. Static analysis of the workflows or `.gitlab-ci.yml`. This is the default and needs nothing
   else.
4. Resolve, with `--resolve-depth=N`: fetch the imported material (actions, reusable workflows,
   includes, components) down to N levels.
5. Sanity, with `--sanity`: read the project settings, such as branch protection and rulesets.

There is no provider-neutral pipeline model. Each provider parses its own document, typed against
its official schema, and its own policies (`policies/github`, `policies/gitlab`) evaluate it with
shared Rego functions from `policies/lib`. Findings, the score and the attack paths are shared.

## Overview

```mermaid
sequenceDiagram
    autonumber
    actor U as User or CI
    participant M as main
    participant A as cli/analyze
    participant C as pkg/config
    participant PF as preflight
    participant P as provider/github or gitlab
    participant K as control
    participant S as score
    participant O as output
    participant PB as publish

    U->>M: plumber analyze [target] [flags]
    M->>A: run root command
    A->>A: read flags, then PLUMBER_ANALYZE_* env
    A->>C: Load(.plumber.yaml)
    C-->>A: config or validation error
    A->>PF: Check(target, options, config)
    PF-->>A: ok or what is missing
    A->>P: Source(target, ref)
    P-->>A: repository tree
    A->>P: Parse()
    P-->>A: provider document
    opt resolve-depth above 0
        A->>P: Resolve(document, depth)
    end
    opt sanity
        A->>P: Settings(project)
    end
    A->>K: Evaluate(document, selected controls)
    K-->>A: findings
    A->>S: Score(findings, profile)
    S-->>A: score and attack paths
    alt standalone
        A->>O: Write(report, formats)
        A->>PB: Publish(score push, MR comment, badge)
    else platform mode
        A->>PB: Push(report) and read the verdict
        A->>O: Write(report, formats)
    end
    A->>A: gate
    A-->>M: nil or an error with its exit code
    M-->>U: exit 0, 1, 2 or 3
```

## Inputs, configuration and preflight

Flags win over `PLUMBER_ANALYZE_*` variables, which `cli` binds through viper. A local run reads
its remote and `HEAD` with go-git. `pkg/config` loads `.plumber.yaml` in the four stages of
[Configuration](project-structure.md#configuration). Preflight checks only what the chosen options
need, with cheap API calls, and says what is missing. A local static run needs no token and no
network.

```mermaid
sequenceDiagram
    autonumber
    participant A as cli/analyze
    participant G as gitrepo
    participant C as pkg/config
    participant PF as preflight
    participant API as provider API

    A->>A: flags, then env, then target parsing
    alt invalid or conflicting inputs
        A-->>A: usage error, exit 2
    end
    opt no target given
        A->>G: PlainOpen(working directory)
        G-->>A: remote URL, branch, HEAD
    end
    A->>A: provider and project from target or remote
    A->>C: Load(path)
    C->>C: validate YAML against plumber.schema.json
    C->>C: layer defaults, extends, file, env, flags with viper
    C->>C: UnmarshalExact into Go types
    C->>C: semantic checks
    C-->>A: config, warnings
    A->>PF: Check(target, options, config)
    alt remote target
        PF->>API: read the repository with the token
        API-->>PF: ok, 401 or 404
    end
    opt sanity
        PF->>API: probe the settings rights
        API-->>PF: ok or 403
    end
    opt platform mode
        PF->>PF: OIDC id-token present
    end
    PF-->>A: ok, or an error naming the missing token or right, exit 2
```

On GitHub, reading settings needs Administration read on the repository. On GitLab, it needs the
`read_api` scope and the Maintainer role, and preflight can read the token's scopes from
`personal_access_tokens/self`.

## Source and static analysis

A remote project is cloned at the ref (a branch, a tag or a commit) with depth 1, into memory, as
[Repository access](project-structure.md#repository-access) describes. A local project is read from
disk. The provider reads its CI files from the tree, validates them against the official schema
(SchemaStore's `github-workflow.json`, GitLab's `ci.json`) and expands them. Each node keeps its
file and line.

```mermaid
sequenceDiagram
    autonumber
    participant A as cli/analyze
    participant P as provider/github or gitlab
    participant G as gitrepo
    participant H as git host

    A->>P: Source(target, ref)
    alt remote
        P->>G: Clone(url, ref, token)
        G->>H: fetch ref, depth 1
        H-->>G: pack
        G-->>P: tree in memory
    else local
        P->>G: Open(path)
        G-->>P: tree on disk
    end
    A->>P: Parse()
    alt GitHub
        P->>G: read .github/workflows/*
        P->>P: validate each workflow against github-workflow.json
    else GitLab
        P->>G: read .gitlab-ci.yml and local includes
        P->>P: validate against ci.json
        P->>P: expand extends, default, !reference, anchors
    end
    P->>P: record imports for the resolve stage
    P-->>A: provider document with source locations
```

## Resolve

`--resolve-depth=N` fetches what the document imports, level by level. Each repository and ref is
cloned once per run. An import left beyond depth N is recorded as unresolved, so a policy can tell
"not fetched" from "absent". The default depth is 0.

```mermaid
sequenceDiagram
    autonumber
    participant A as cli/analyze
    participant P as provider/github or gitlab
    participant G as gitrepo
    participant H as git host

    A->>P: Resolve(document, N)
    loop level 1 to N
        P->>P: imports of this level
        loop each repo@ref not seen yet
            P->>G: Clone(repo, ref)
            G->>H: fetch ref, depth 1
            H-->>G: pack
            G-->>P: tree, cached for the run
            P->>P: parse action.yml, workflow, include or component
            P->>P: attach it with its origin and level
        end
        P->>P: stop on a cycle
    end
    P->>P: mark imports below level N as unresolved
    P-->>A: document with resolved imports
```

## Sanity

`--sanity` reads the settings that git doesn't carry and attaches them to the document as its
`settings` section. Off by default.

```mermaid
sequenceDiagram
    autonumber
    participant A as cli/analyze
    participant P as provider/github or gitlab
    participant API as provider API

    A->>P: Settings(project)
    alt GitHub
        P->>API: branch protection of the protected branches
        P->>API: rulesets
        P->>API: repository and workflow permission settings
    else GitLab
        P->>API: protected branches and tags
        P->>API: merge request approval rules and settings
        P->>API: project settings
        P->>API: CI/CD variables
        P->>API: security policy project
    end
    API-->>P: settings
    alt a call fails
        P->>P: mark that setting unknown, the run is degraded
    end
    P-->>A: document with settings
```

## Evaluation, score, outputs and exit code

`control` selects the controls from the config and the `--controls`, `--skip-controls` and
`--no-controls` flags, then evaluates the provider's policies on the document. A control that
needs resolved imports or settings reports "not run" when its stage was off, never "passed".

```mermaid
sequenceDiagram
    autonumber
    participant M as main
    participant A as cli/analyze
    participant K as control
    participant F as finding
    participant S as score
    participant O as output
    participant PB as publish
    participant X as score service or platform

    A->>K: Evaluate(document, config, filters)
    K->>K: select controls
    K->>K: OPA on policies/provider with policies/lib
    K-->>A: raw findings, controls not run
    A->>F: Finalize(findings)
    F->>F: links, fingerprints, dismissals
    F-->>A: findings
    A->>S: Score(findings, profile)
    S-->>A: letter, points, attack paths
    A->>O: Write(report)
    O->>O: text, json, sarif, csv, ocsf, glsast, pbom, cyclonedx
    opt score push, platform push, MR comment or badge
        A->>PB: Publish(report)
        PB->>X: push with the OIDC id-token or the provider token
        X-->>PB: ok or verdict
    end
    A->>A: gate
    Note over A: degraded data, exit 3<br/>blocking platform verdict, exit 1<br/>--fail-warnings with warnings, exit 3<br/>score gate fails, exit 1<br/>platform token error, exit 2<br/>otherwise exit 0
    A-->>M: error with its exit code, or nil
```

## Behaviors kept from today's CLI

Each analyze step checks these against the old code:

- The order of the exit gate: degraded 3, blocking platform verdict 1, `--fail-warnings` 3, score
  gate 1, platform token error 2, otherwise 0. Other errors exit 2 (`cmd/root.go:60`,
  `finalizeRun` in `cmd/analyze_shared.go`).
- A flag wins over its `PLUMBER_ANALYZE_*` variable (`envKeys` in `cmd/analyze_gitlab.go:631`).
- Platform mode pushes before it writes the outputs; a standalone run writes first (`continueRun`
  in `cmd/analyze_shared.go`).
- A degraded run still writes every output, stamped as degraded.
- `--threshold` alone uses the old percentage gate and switches the score gate off.

## Behaviors that change

- Static by default: imports and settings are read only with `--resolve-depth` and `--sanity`.
  Today `analyze` resolves remote material and reads settings on every run.
  [feature-inventory.md](feature-inventory.md) records the decision.
- Preflight fails at the start, with exit 2, when a token or a right is missing. Today the run
  continues and reports the settings as unknown.
- No shared pipeline model: today's `internal/ir` and the 75 policies on `input.pipeline` give way
  to one document and one policy set per provider.
