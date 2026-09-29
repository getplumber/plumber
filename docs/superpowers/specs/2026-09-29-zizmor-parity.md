# zizmor parity for the GitHub analysis

> The spec behind `docs/superpowers/plans/2026-09-29-zizmor-parity.md`. It records what the
> comparison found, which zizmor audit maps to which Plumber control, and the decisions the
> plan implements. Read this first, then the plan.

## Where the numbers come from

Both tools were run on `austenstone/actions-playground` at commit `a84f5c0` (110 workflows,
9 local actions) on 2026-09-29 with GitHub API access:

| | zizmor 1.30.1 | plumber 0.5.12 |
|---|---|---|
| Findings, default mode | 1677 over 100 files | 2296 over 96 files, 13 issue codes |
| Findings, maximum mode | 2296 (auditor persona, 111 files) | 2296 (nothing more can be enabled) |
| GitHub controls shipped | 41 audits | 24 controls run; 35 more sit in `benchedControls` |
| Wall time with API access | 24 s (1.5 s offline) | 190 s |
| `.github/actions/**/action.yml` audited | yes | no |

Where the two tools implement the same check they agree almost line for line (action pinning:
1006 identical locations; permissions: 143; checkout credentials, CVEs, ref confusion, inherited
secrets, secrets context dump: identical). The gaps are elsewhere and this spec closes them.

## Design decisions

1. **One control per zizmor audit, same severity tiers.** Every zizmor audit gets exactly one
   Plumber control (an existing one, a promoted benched one, or a new one). zizmor's
   `Severity x Confidence` becomes Plumber's severity plus a `confidence` field on the finding
   (`high` | `medium` | `low`), so consumers can filter the way zizmor personas do.
2. **Personas become defaults.** zizmor's regular persona is Plumber's `defaultConfig`. Audits
   that zizmor only enables under `--persona auditor` or `--pedantic` ship `enabled: false` by
   default and are listed in the default config with a one-line comment saying so.
3. **Plumber's conservative rules keep their default but gain the zizmor reading as a knob.**
   Dangerous triggers stay "exploitable only" by default; `flagTriggerWithoutCheckout: true`
   gives the zizmor behaviour. Cache poisoning stays release-scoped by default;
   `flagPublishingWorkflows: true` widens it to zizmor's publishing heuristics. Action pinning
   keeps `trustedOwners: [actions, github]`; an empty list gives the zizmor behaviour. These
   knobs are documented next to each control so a user switching from zizmor can reproduce
   its output with one config file.
4. **Inputs parity.** Everything zizmor audits as a "Workflow, Action" input becomes an input
   here: local action definitions (`.github/actions/**/action.yml`, `action.yaml`) and any
   `uses: ./path` target are parsed into the IR as jobs of kind `action`, so every
   workflow-content rule sees them without per-rule changes. `services:` images and
   `uses: docker://` step images join the inventory (PBOM, image rules).
5. **Template injection becomes a context classifier, not a regex list.** The rule keeps its
   safe sinks (env binding, quoted heredoc) and replaces the pattern list with zizmor's
   context capability table (2520 arbitrary, 195 structured, 1367 fixed contexts, embedded as
   generated Go data) plus the in-code heuristics for `inputs.*` (typed by the
   `workflow_dispatch` declaration), `env.*` (resolved to its definition), `matrix.*` (static
   or not), `needs.*.outputs.*` and `steps.*.outputs.*` (arbitrary unless provably static).
   One finding per expression, not per job.
6. **The catalog stops promising benched controls.** `plumber catalog` marks each control
   `status: shipping | benched` and `plumber config validate` answers "known but benched" for a
   benched name instead of "unknown control". After the plan, the benched set for GitHub is
   empty except the cross-provider GitLab-only controls.
7. **No new binary, no new network call class.** Every new audit is YAML parsing, on-disk
   reads, or the GitHub API calls the collector already makes (typosquat and unpinned-tools
   are pure tables).

## Audit by audit: zizmor to Plumber

Status on v0.5.12: **ships** (in the 24), **benched** (Rego, fixtures, docs and identity exist;
config, catalog, JSON, terminal, default-config and wizard wires do not), **partial** (ships but
narrower than zizmor), **missing** (nothing in the tree). "Persona" is zizmor's: regular unless
said otherwise.

| # | zizmor audit | Persona | Plumber control (code) | v0.5.12 | Plan task |
|---|---|---|---|---|---|
| 1 | adhoc-packages | regular | workflowMustPinPackageInstalls (214) | benched | W2 |
| 2 | anonymous-definition | auditor | workflowsMustHaveExplicitName (422) | benched | W2 |
| 3 | archived-uses | regular | actionsMustNotBeArchived (702) | ships | none |
| 4 | artipacked | regular | checkoutMustNotPersistCredentials (307/310) | ships | none |
| 5 | bot-conditions | regular | workflowMustNotTrustSpoofableActorChecks (210) | benched | W2 |
| 6 | cache-poisoning | regular | releaseWorkflowsMustNotRestoreUntrustedCache (705) | partial | W4 |
| 7 | concurrency-limits | auditor | workflowsMustDeclareConcurrency (418) | benched | W2 |
| 8 | dangerous-triggers | regular | workflowMustNotUseDangerousTriggers (802) + 804 | partial | W4 |
| 9 | dependabot-cooldown | regular | dependabotEcosystemsMustHaveCooldown (902) | benched | W2 |
| 10 | dependabot-execution | regular | dependabotMustNotAllowInsecureExternalCodeExecution (901) | benched | W2 |
| 11 | excessive-permissions | regular | workflowsMustDeclarePermissions (801) + writeAll (803) | partial | W3 (805) |
| 12 | forbidden-uses | opt-in | githubActionMustComeFromAuthorizedSources (713) | partial | W4 (denylist) |
| 13 | github-app | regular | githubAppTokensMustBeRevokedOnExit (306) | benched | W2 |
| 14 | github-env | regular | workflowMustNotWriteUntrustedContentToGitHubEnv (209) | ships, workflows only | W1 (actions input) |
| 15 | hardcoded-container-credentials | regular | containerCredentialsMustComeFromSecrets (704) | benched | W2 |
| 16 | impostor-commit | regular | actionRefsMustExistUpstream (707) | ships | none |
| 17 | insecure-commands | regular | workflowMustNotReEnableInsecureCommands (208) | benched | W2 |
| 18 | insecure-url-scheme | regular, pre-commit files | none | missing | W3 (906) |
| 19 | known-vulnerable-actions | regular | actionsMustNotCarryKnownCVEs (703) | ships | none |
| 20 | misfeature | regular | workflowMustNotUseKnownMisfeatures (419) | benched | W2 |
| 21 | obfuscation | regular | workflowMustNotContainObfuscation (420) | benched | W2 |
| 22 | overprovisioned-secrets | regular | workflowMustNotExportEntireSecretsContext (309) | ships | none |
| 23 | ref-confusion | regular | externalRefsMustNotCollide (402) | ships | none |
| 24 | ref-version-mismatch | auditor | actionPinCommentsMustMatchSha (708) | benched | W2 |
| 25 | secrets-inherit | regular | reusableWorkflowsMustNotInheritSecrets (302) | ships | none |
| 26 | secrets-outside-env | auditor | deployJobsMustUseEnvironmentGate (305) | benched | W2 |
| 27 | self-hosted-runner | pedantic | none | missing | W3 (424) |
| 28 | self-repository | regular | none | missing | W3 (423) |
| 29 | stale-action-refs | auditor | actionPinsMustNotBeStale (709) | benched | W2 |
| 30 | superfluous-actions | auditor | actionsMustNotDuplicateRunnerBuiltins (711) | benched | W2 |
| 31 | template-injection | regular | workflowMustNotInjectUserInputInScripts (207) | partial: 4 vs 52 high-confidence | W1 |
| 32 | typosquat-uses | regular | none | missing | W3 (718) |
| 33 | undocumented-permissions | auditor | none (801 is "missing", not "uncommented") | missing | W3 (806) |
| 34 | unpinned-images | regular | containerImageMustNotUseForbiddenTags (102/103) | partial: job containers only | W1 (services, docker://) |
| 35 | unpinned-tools | regular | none | missing | W3 (719) |
| 36 | unpinned-uses | regular | actionsMustBePinnedByCommitSha (701) | ships | W4 (document the knob) |
| 37 | unredacted-secrets | regular | workflowMustNotUnredactSecretsViaFromJSON (303) | benched | W2 |
| 38 | unsound-condition | regular | workflowConditionsMustBeSound (211) | benched | W2 |
| 39 | unsound-contains | regular | workflowContainsCallsMustBeSound (212) | benched | W2 |
| 40 | unsound-ternary | regular | none | missing | W3 (216) |
| 41 | use-trusted-publishing | regular | publishWorkflowsMustUseOidcTrustedPublishing (421) | benched | W2 |

Benched GitHub controls with no zizmor counterpart (213, 215, 308, 706, 712, 903, 904, 905 and
the seven cross-provider GitLab-only ones) are out of this plan's scope; they stay benched.

## What the comparison showed, per gap

- **Template injection.** zizmor's 52 high-confidence findings sit in run blocks expanding
  `inputs.version` (26), `inputs.environment` (16), `github.actor` (15), `github.ref_name` (10),
  `github.event.head_commit.message` (2) and similar. Plumber's regex list covers titles,
  bodies, head refs, branch names, commit messages and author names only, and reports one
  finding per job. Part of zizmor's total is noise Plumber excludes on purpose
  (`github.event_name`, `github.sha`, `github.repository`, `github.run_id` are `fixed` in
  zizmor's own table and only appear at Low confidence).
- **Service containers.** `service-container.yml` declares `services: nginx: image: nginx`;
  zizmor flags the untagged image, Plumber never sees it. The GitHub collector fills
  `job.Image` from `container:` and leaves `job.Services` empty; the GitLab collector fills
  both. The image rules read `job.image` only, on both providers.
- **`uses: docker://ghcr.io/wolfi-dev/sdk:latest`.** A step image, not an action; zizmor
  flags the mutable tag, Plumber skips `docker://` uses entirely except in the mutable
  remote-code control.
- **Local actions.** zizmor's regular run touched one `action.yml` (a `GITHUB_ENV` write in a
  Python step); its auditor run touched eleven. Plumber's collector reads `.github/workflows`
  only; `action_source.go` fetches remote `action.yml` files for one control but never
  parses local ones as inputs.
- **Personas.** Nine zizmor audits fire only under auditor or pedantic. Plumber has no
  persona; the default config is the persona.
- **Catalog honesty.** `plumber catalog` lists 59 GitHub controls, the binary runs 24, and a
  config naming one of the other 35 is refused as unknown.

## Out of scope

- zizmor's auto-fixes (`--fix`). Plumber's remediation stays in the platform.
- The 190 s wall time. It is the per-action upstream lookup loop, not coverage; a cache and
  a bounded worker pool are a separate change.
- GitLab parity for the new controls where the concept does not exist on GitLab (typosquat,
  self-repository, unpinned tools); the rules declare `providers: [github]`.
