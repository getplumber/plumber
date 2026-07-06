# Detecting malicious code & dubious practices in GitHub Actions

Research reference for Plumber's GitHub Actions control catalog. It crosses a
**threat taxonomy** (what to look for) with **detection methods** (how to find
it), states **what static analysis can and cannot reach**, and maps the
landscape of existing tools and their gaps.

Grounded in real 2024–2026 incidents, CVEs, OWASP CICD-SEC and SLSA. Snapshot
date: 2026-07-06. Rule counts and "who covers what" drift — treat them as
approximate.

---

## 0. The core lesson

The highest-impact 2025–2026 incidents all combined the same three ingredients:
**mutable-ref re-pointing + fetch-and-execute of remote code + a
privileged-trigger misconfiguration.** A static scanner is strong on the first
and third and on injection sinks; it is structurally blind to the second at
runtime. So the catalog must:

1. **Never let a clean result assert "safe"** — only "no known pattern seen".
2. **Treat obfuscation-then-exec as the strongest signal** (nothing legitimate
   hides what it runs) rather than chasing every encoding.
3. **Emit "could-not-verify"** (a distinct, non-passing state) when the pinned
   action source cannot be resolved to immutable execution — never a silent
   green that changes with the CI environment.
4. Position itself as **one complementary layer**: a Jan-2026 study of nine
   scanners found *no single tool covers all ten weakness categories*
   (arXiv 2601.14455v2).

---

## 1. The ten-weakness backbone (arXiv 2601.14455v2)

The academic taxonomy to map every control against:

| # | Category | Static? |
|---|----------|---------|
| 1 | Unpinned Dependency | ✅ |
| 2 | Excessive Permission | ✅ |
| 3 | Injection (untrusted → sink) | ✅ (taint > pattern) |
| 4 | Secrets Exposure | ⚠️ partial (runtime leaks invisible) |
| 5 | Privileged Trigger | ✅ |
| 6 | Artifact Integrity / Provenance | ✅ config, ❌ actual attestation |
| 7 | Known Vulnerable Component | ✅ (advisory DB) |
| 8 | Control Flow | ⚠️ |
| 9 | Runner Compatibility / self-hosted | ✅ (explicit labels only) |
| 10 | Hardening Gap | ✅ |

---

## 2. Threat / dubious-practice catalog

### A. Supply chain of the actions themselves
- **Unpinned action** (mutable tag/branch). *Static YAML.* The `tj-actions/
  changed-files` compromise (**CVE-2025-30066**) retroactively re-pointed **all**
  version tags to one malicious commit, so even tag-pinned users ran attacker
  code that did `curl … memdump.py | sudo python3` and double-base64'd secrets
  into world-readable logs. → **SHA pinning, not tag pinning, is the mitigation.**
- **Action fetches + executes MUTABLE remote code at runtime.** *Static source
  fetch + obfuscation detection.* A SHA-pinned action that pulls a script from a
  moving ref (e.g. `anchore/scan-action` → `raw.githubusercontent.com/anchore/
  grype/main/install.sh`). **Not covered well by any surveyed tool** — the
  whitespace Plumber targets. Evasions: host swap (`github.com/<o>/<r>/raw/…`,
  gist), download-then-run vs pipe-to-shell, base64/hex/concat + `eval`/`atob`,
  non-standard branch names.
- **Transitive / dependency-of-dependency compromise.** The tj-actions
  compromise was *potentially enabled by* `reviewdog/action-setup@v1`
  (**CVE-2025-30154**). Surveyed static tools examine only the **first level** of
  action reuse — deeper reuse is an open gap.
- **Impostor commit** — pinned SHA that does not belong to the named repo (GitHub
  does not validate the SHA↔repo binding). *API ref resolution.*
- **Typosquatting** of a known action name. *Edit distance + reputation.*
- **Archived / abandoned action repo.** *API.*
- **Action with a known CVE/advisory** (GitHub Advisory DB, `actions` ecosystem).
  *API.*
- **Ref confusion** — ref resolving to both a tag and a branch. *API.*
- **Comment-vs-SHA mismatch** (`@<sha> # v4` where the SHA ≠ v4). *API.*
- **Unauthorized source / low reputation** (random owner, few stars, young repo).
  *API + allowlist.*
- **Docker-image action** (`runs.using: docker`) on a mutable image, or a
  `Dockerfile` with `RUN curl … | sh`. *Static source (blind spot today).*
- **Living Off The Pipeline (LOTP)** — RCE-by-design dev tools (`npm ci` scripts,
  `go generate`, `make`, `pre-commit`) invoked on untrusted code. *Taint.*
- **Reusable-workflow call unpinned / `secrets: inherit`.** *Static YAML.*

### B. Obfuscation & generic malware signals (in fetched action source)
Treat these as **high/critical in their own right** — a legitimate action has no
reason to hide:
- `base64 -d | sh`, `openssl enc -d | sh`, `xxd -r`, `eval "$(… | base64 -d)"`.
- `eval(atob(…))`, `new Function(atob(x))`, `exec(Buffer.from(x,'base64'))`.
- Download-then-run (`curl -o /tmp/x; sh /tmp/x`), host swaps.
- High-entropy / large encoded blobs; suspicious minification of a normally
  readable action; `dist/` that does not match source (non-reproducible build).
- Env/secret harvesting (`printenv | curl`, `.git/config` read), egress to
  non-GitHub hosts, cryptominer signatures, anti-analysis / time-bombs.

### C. Pipeline injection & Poisoned Pipeline Execution (OWASP CICD-SEC-4)
- **Template/script injection** — `${{ github.event.* }}` (and other untrusted
  contexts) interpolated into `run:` are substituted **as code before** the shell
  runs. GitHub's own high-risk fields end in: `body`, `default_branch`, `email`,
  `head_ref`, `label`, `message`, `name`, `page_name`, `ref`, `title`. Payloads
  use quote-breakout (`a"; ls …`) or backticks in PR/issue titles. **The
  highest-value static rule surface** — bind through `env:` then reference `$VAR`.
- **Pwn requests** — `pull_request_target` / `workflow_run` run with a read/write
  repo token *in memory, available to any running program even without
  referencing secrets*; combined with a checkout of untrusted PR head → repo
  compromise. Exploited March 2026 against `aquasecurity/trivy-action` to
  backdoor **LiteLLM** on PyPI. *Static: trigger + checkout-ref pattern.*
- **`$GITHUB_ENV` / `$GITHUB_PATH` injection** from untrusted content. *Taint.*
- **`allow-unsafe-pr-checkout: true`** under a privileged trigger. *Static.*
- **Insecure commands** (`ACTIONS_ALLOW_UNSECURE_COMMANDS`). *Static.*
- **Unsafe context dump** (`toJSON(github)` into a log). *Static.*
- **Spoofable actor / unsound conditions** (`github.actor`, bot checks,
  unanchored `contains()`). *Static.*
- **Unverified script execution** (`curl … | bash` in the user's own `run:`).
  *Static.*

### D. Secret / token exfiltration
- **artipacked** — `actions/checkout` without `persist-credentials: false`
  leaves the `GITHUB_TOKEN` in `.git/config`; exploitable when `.git` is uploaded
  as an artifact or a later untrusted step runs.
- Secrets hard-coded in YAML; secrets `echo`'d into logs; **debug-trace** dumps
  (`ACTIONS_STEP_DEBUG`); secrets baked into public artifacts.
- **Over-broad / undeclared `GITHUB_TOKEN` permissions**, `write-all`.
- **`secrets: inherit`** to reusable workflows; `toJSON(secrets)` export;
  dynamic secret indexing `secrets[expr]`.
- Long-lived PAT / cloud creds reachable by a low-privilege (fork) actor.
- **Missing OIDC trusted publishing** (a PAT where OIDC would do).
- App token not revoked at job end.

### E. Runners & execution
- **Self-hosted runner on a public repo** reachable by fork PRs → attacker code
  on your infra. *Static (explicit labels).*
- Docker-in-Docker / mounted Docker socket; deploy job with no `environment`
  gate; weakened security jobs (`allow_failure`, `when: manual` on SAST).

### F. Integrity & provenance
- Unsigned/unattested published artifacts (Sigstore/cosign); **no SLSA
  provenance**; install without checksum verification; Docker base image not
  pinned by digest; container tag mutable (`latest`); **cache poisoning** (a
  low-privilege job seeds a cache a privileged job restores).
- Note: **artifact attestations prove build origin, not that the code is safe** —
  provenance ≠ safety.

### G. Repository posture
- Missing/weak branch protection; no `SECURITY.md`; no SAST; no dependency
  updates (Dependabot/Renovate); **no quarantine/cooldown** on dependency updates
  (`minimumReleaseAge`); no `concurrency`.

---

## 3. Detection methods — strengths & limits

| Method | Catches | Limit |
|--------|---------|-------|
| **Static YAML pattern** | triggers, permissions, `run:`, `uses:` shapes | textual evasion; a pass asserts little |
| **Taint / dataflow** | injection (untrusted source → sink) | best-in-class for injection: the research ARGUS system (USENIX Security '23) found injections **>7×** more than pattern scanners; GitHub CodeQL taint for Actions GA Apr 2025. Pattern rules are a *floor* |
| **Action-source fetch + scan** | mutable-remote-exec, obfuscation, in-action malware | blind spots: subpath/composite, Docker-image actions, GHES/private, API rate limits, **non-determinism across CI environments** |
| **API / metadata enrichment** | impostor commit, archived repo, CVE, stars, ref confusion, comment↔SHA | rate limits, offline, GHES |
| **Obfuscation / entropy** | hidden payloads | encoding space is unbounded → flag *the act of hiding*, don't decode everything |
| **Provenance / integrity** (SHA pin, checksum, cosign, SLSA, Scorecard) | unpinned, unattested, unverified installs | **SHA pin ≠ immutable execution**; adoption partial |
| **Runtime / behavioral** (egress + file + process baseline, eBPF, honeytokens) | what static cannot: runtime fetch-exec, execution-time secret leaks | needs infra; not shift-left; egress detection itself bypassable (e.g. `sendto`/`sendmsg`) |
| **Reputation / diffing / anomaly** | dubious accounts, tampered `dist/` | noise |

**Runtime is the counterpart to the static blind spots.** Behavioral agents that
baseline per-job egress detected tj-actions (CVE-2025-30066), the axios npm RAT
(2026), and the NX "s1ngularity" compromise (2025) *at runtime* — cases a static
scanner cannot observe.

---

## 4. The fundamental limit of static detection (and what to do)

`fetch-and-run mutable remote code` is an **unbounded** expression space: host
swaps, download-then-run, arbitrary encodings, URLs assembled from env/secrets.
No fixed allowlist of hosts/refs/extensions closes it. Two documented static
blind spots (arXiv 2601.14455v2): (1) **no runtime observation** → execution-time
leaks and runtime fetch-exec are invisible; (2) **first-level reuse only** →
transitive risk missed.

Design principles that follow:
1. A **clean result = "no known in-the-open pattern seen"**, never "safe".
2. **In-the-open fetch-exec = high** (a heads-up); **obfuscation-then-exec =
   critical**. This tracks *intent to hide*, so it does not punish the honest
   author who writes `curl … | sh` in plain sight while the obfuscator scores
   well — the inverse of a naive severity model.
3. A **checksum-verified** fetch of a mutable-ref script is materially safer than
   an unverified one → use "mutable ref + no checksum" as the discriminating
   signal to separate legitimate installers from noise.
4. Emit **"could-not-verify"** (tri-state, never a pass) when the source cannot
   be fetched (offline/GHES/private/rate-limited/subpath/Docker-image).
5. **Complement, don't replace, runtime egress monitoring** for the residual.

---

## 5. Tooling landscape & gaps

- **OPA/Rego static supply-chain scanner (BoostSecurity Poutine)** — closest
  architectural analog to Plumber's engine. Rules for unpinnable actions,
  injection / arbitrary code execution from untrusted changes, self-hosted
  runner exposure on PRs, unverified-creator actions, untrusted-checkout-exec,
  unverified-script-exec. **Lacks a mutable-remote-exec rule.**
- **The reference open-source Actions auditor** — broadest static coverage of the
  ten categories; strong on the `dangerous-triggers` and `template-injection`
  classes. (Named check identifiers are usable; the tool name is intentionally
  omitted here.)
- **`octoscan`** (Synacktiv) — deep static, requires fetching action definitions
  via the GitHub API.
- **ARGUS / CodeQL** — taint/dataflow, the state of the art for injection.
- **OpenSSF Scorecard** — repo-level signals (pinning, permissions, dangerous
  workflow patterns).
- **Harden-Runner (StepSecurity)** — the runtime counterpart (egress/file/process
  baseline).
- **`actionlint`, Semgrep, Snyk/Trivy, GitHub secret/dependency scanning** —
  partial, complementary layers.

**Gaps no tool covers well:** (a) an action that fetches **mutable remote code**
at runtime; (b) **obfuscated** fetch-and-exec; (c) **transitive** (2nd-level+)
action compromise. (a) and (b) are Plumber's differentiation.

---

## 6. Mapping to Plumber controls

| Threat | Plumber | Status |
|--------|---------|--------|
| Unpinned action | `actionsMustBePinnedByCommitSha` (ISSUE-701) | shipped |
| Mutable remote exec (in the open) | `actionsMustNotExecuteMutableRemoteCode` (ISSUE-714) | in PR |
| Obfuscated remote exec | same control (ISSUE-715, critical) | in PR |
| Could-not-verify | same control (info) | planned |
| Impostor commit | ISSUE-707 | shipped |
| Archived repo | ISSUE-702 | shipped |
| Known CVE | ISSUE-703 | shipped |
| Ref confusion | ISSUE-402 | shipped |
| Unauthorized source | ISSUE-713 | shipped |
| Template injection | ISSUE-207 (narrow, free-text fields) | shipped |
| Injection via vars/inputs | ISSUE-215 (+ `github.event.inputs`) | shipped / extending |
| Pwn request | ISSUE-802 / ISSUE-804 | shipped |
| artipacked | ISSUE-307 | shipping |
| Debug trace | ISSUE-203 | shipped |
| Unverified script exec | ISSUE-411 | shipped |
| Dependency-update cooldown | (issue) | proposed |
| **Docker-image action fetch-exec** | — | gap |
| **Transitive action compromise** | — | gap (needs graph + API) |
| **Runtime exfil / egress** | — | out of scope (runtime tool territory) |

---

## Sources

Primary incidents & advisories:
- CISA — tj-actions/changed-files (CVE-2025-30066) & reviewdog (CVE-2025-30154):
  https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
- GitHub Advisory GHSA-mrrh-fwg8-r2c3: https://github.com/advisories/ghsa-mrrh-fwg8-r2c3

Concepts & mechanisms:
- GitHub Security Lab — Preventing pwn requests: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
- GitHub docs — Script injections: https://docs.github.com/en/actions/concepts/security/script-injections
- GitHub Security blog — Catching workflow injections: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/
- SHA-pinning is not immutable execution: https://www.vaines.org/posts/2026-03-24-the-comforting-lie-of-sha-pinning/
- GitHub Actions SHA-pinning policy: https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/

Detection methods & tooling:
- Nine-scanner systematic study (arXiv 2601.14455v2): https://arxiv.org/html/2601.14455v2
- ARGUS — staged static taint analysis (USENIX Security '23): https://par.nsf.gov/biblio/10516034-argus-framework-staged-static-taint-analysis-github-workflows-actions
- Harden-Runner: https://github.com/step-security/harden-runner
- Poutine: https://github.com/boostsecurityio/poutine
- octoscan: https://github.com/synacktiv/octoscan
- Action-scanner comparison & API-fetch constraint: https://datosh.github.io/post/github_action_scanner/
- Artifact attestations / SLSA scope: https://tenki.cloud/blog/github-actions-artifact-attestations-slsa
