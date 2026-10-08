# The Plumber Score

The Plumber Score is a letter from **A** to **E**, read from **points** between 0 and 100. By default Plumber computes the **contextual score**: it looks for **attack paths** in your pipeline (a way for someone outside your team to run code in a job and reach what that job holds or changes) and charges each path for what it reaches. Findings that are not part of any path still cost something, but much less, and never enough on their own to give an E.

The previous score, which priced every issue code by its severity, is still available: see [The previous score](#the-previous-score-scoring-v3) at the end.

---

## What each letter means

| Letter | Final points | What it means |
|:------:|--------------|---------------|
| **A** | 90 to 100 | Excellent: no significant exposure found |
| **B** | 71 to 89 | Good: minor exposure |
| **C** | 51 to 70 | Moderate: exposure worth fixing |
| **D** | 31 to 50 | Poor: significant accumulated exposure |
| **E** | 0 to 30 | Critical: a Critical attack path remains, or (with none) heavy accumulated losses |

A letter from A to D does not say how many paths there are, or of which kind: a report can land on any of them through individual findings alone. An **E needs at least one Critical**: a Critical attack path keeps the score at 30 points or below, and only Critical items, paths or individual findings, can take the score lower than 31. The limits described below make the same guarantee for the other letters: with no Critical anywhere the letter is D or better (31 points), with no High either C or better (51), with nothing above Low B or better (71).

---

## How the points are computed

Every run starts at 100 points and loses points for two kinds of items: the attack paths, and the individual findings.

| Step | Rule |
|---|---|
| **Attack paths** | Each path costs a flat price by its tier: **Critical 30**, **High 15**, **Medium 6**, **Low 3**. |
| **Individual findings** | Each finding no path uses costs a price by its own severity: **Critical 20**, **High 10**, **Medium 5**, **Low 2**. All individual findings together count for at most **30**, the worst first: the Critical ones, then the High, the Medium and the Low, until the 30 are spent; what does not fit is not counted. |
| **Critical items** | Critical paths and the Critical individual findings counted within their 30 are never limited. |
| **Every other item** | Paths and individual findings alike enter **one nested limit** by severity: the low items count for at most **29**, the medium and low items together for at most **49**, the high, medium and low items together for at most **69**. |
| **Raw points** | 100 minus `Critical + min(69, High + min(49, Medium + min(29, Low)))`, where High, Medium and Low are the summed prices of every non-Critical item of that severity, paths and individual findings together. This figure can go below zero (`rawPointsUnclamped`); the score reads it floored at zero (`rawPoints`). |
| **Critical path** | If at least one attack path is Critical, the final points are **30 at most** (letter E). A Critical individual finding costs its price and forces nothing. |
| **No finding** | 100 points, A. |

The letter is read from the **final points** only (`finalPoints`). There is no floor: the nested limit already keeps a run with no Critical item at 31 points or more, with no High at 51 or more, with no Medium at 71 or more. Moving one item down a tier never lowers the score. Findings that are dismissed cost nothing. Several occurrences of one finding (the same issue, as the platform groups them: see [FINGERPRINT.md](FINGERPRINT.md)) count once.

---

## Attack paths

A path reads **entry, job, reach**:

- **Entry**: a finding that lets someone outside your team put code or input into a job. A dependency that can change without a commit in your repository (an action, a reusable workflow, a container image, an include, a script fetched from the network), an expression an attacker controls that ends up in a script (a pull request title, a merge request description), a privileged trigger that runs fork code, a cache that a run that is not trusted can write and that a release or publish job restores (its key is not scoped to the released ref; when Plumber cannot tell whether the cache is on for the run that publishes, the path is unverified; the cache is an entry only when another path of the pipeline enters a job whose run can save the repository's caches, a job on a privileged trigger such as `pull_request_target`, a push, a schedule, a release or a manual run, other than a fork pull request run, whatever caches it declares (code running there can save any key through the cache API), and the path block names that job when there is one; otherwise the cache finding is an individual finding), or an unprotected default branch that runs a job on every push. An action owner or an image registry outside the authorized sources is not an entry on its own: when the reference can change, the finding that it is not pinned starts the path and the source finding is listed with it, charged through the path; when the reference is pinned by a full commit SHA or a digest, the source finding is an individual finding. A workflow or an action inside the repository itself (`./.github/workflows/build.yml`) is not a dependency: it changes only with a commit in the repository, so a finding on it starts no path. The path enters the job that finding names; an include finding enters every job the include shapes.
- **Walk**: from that job to the jobs it feeds directly (through `needs`, an artifact or a shared cache), one step. An entry that holds only in a fork pull request run (the run itself, or an expression its author sets) is not walked through a cache alone: such a run saves only in its pull request's scope.
- **Reach**: what the walked jobs hold (secrets, by name only, and write tokens) and what they change (they publish, deploy, write to the repository, sign or release). The runner a job runs on is not read: every runner counts as one that is not self-hosted. A job that reads the whole secrets context (`toJson(secrets)`) or calls a reusable workflow with `secrets: inherit` holds every secret of the repository: that is proven by the way it reads them, names or not. A job token that the workflow or the job declares with `contents`, `packages` or `deployments` write is both: any code in the job can write to the repository, publish packages or create deployments with it (`write-all` can do all three). A token with no `permissions` block is the repository default, whose real scopes Plumber cannot read: it counts as held, never as something the job changes. Its other write scopes (`pull-requests`, `issues`, `id-token`, `security-events`, `actions` and the like) are held, nothing more. What a step of the job does and what its token allows count once per kind.

One entry makes **one** path, however many jobs it enters: one thing to fix, one path, charged once. Two findings on one entry (for example a forbidden tag and a missing digest on the same image) make one path too, and so does an unprotected branch that every workflow runs on, or an action used in several jobs. Each job the entry enters is a branch of the path, with its own walk and its own reach: code an attacker runs in one job never gets what another job holds. A branch's tier is read from everything its walked jobs hold and change; the path takes the tier of its strongest branch, with that branch's moves and reach, and is proven as soon as one branch is. The JSON lists every branch under `branches` (its job, the jobs it walks, its reach, tier, state and modifiers, and under `feedsVia` the kinds of edge, `artifact`, `cache` or `output`, from its job to each job it feeds), and the path's `jobs` are the entry jobs, strongest first, then the jobs they feed.

### Tier: what the path reaches

| Tier | The path reaches |
|---|---|
| **Critical** | secrets or a write token, **and** something the job changes (a publish, a deploy, a release, a write to the repository); a declared token that can write `contents`, `packages` or `deployments` is both. An entry anyone opening a pull request controls (a fork pull request, a checkout of the pull request head or of another workflow's run in a privileged workflow, an expression an attacker sets on a pull request trigger) needs a secret or any write token alone, the OIDC token included |
| **High** | secrets or a write token, or something the job changes, but not both; or code execution alone, in a job that holds nothing: the runner can be abused, its cache or artifacts poisoned. A contributor's entry is High with code execution alone |
| **Medium** | only a High path one of the moves below lowered (a private repository, something Plumber could not decide), or a dependency path held there because its reference is only not pinned |
| **Low** | the entry exists, but no code of the attacker runs |

Plumber also applies what the CI platform itself guarantees: a GitHub pull request from a fork gets no secrets and a read-only token (unless the workflow also runs on a privileged trigger such as `pull_request_target`), and a GitLab merge request from a fork never sees protected variables.

### What moves a tier

Each of these moves a path by one tier, never below Low nor above Critical:

- **Private repository**: an entry that needs a contributor (a fork pull request, an untrusted expression, a privileged trigger) goes down one when the repository is proven private. A dependency that can change on its own, and a cache any run on the repository can write, are unchanged.
- **Something Plumber could not decide**: when a fact on the path cannot be settled (an unknown permission default, a trigger filter or a branch protection Plumber cannot read, an entry that could not be checked, a reference computed at run time such as an image named by an expression or by a variable), the path goes down one and is marked **unverified**. This applies only when the path's tier rests on that fact: secrets Plumber could not list do not lower a path whose job holds a declared write token, a listed secret or every secret of the repository, which already give it the same tier; the path then says the secrets could not be listed and stays proven. Likewise, something the job changes that Plumber could not confirm does not lower a path that changes something else for certain. When the tier does rest on such a fact, the path is priced as if the fact held, then goes down one, so it never falls below what its proven reach gives. Code execution alone is High, so secrets Plumber could not list, or a repository-default token whose write is assumed, never lower a path that runs code: it stays High and proven, and says what could not be checked. A missing protection that raises such a path only because of secrets Plumber could not list rests on them too: the path is priced one up, goes down one, and is marked unverified.
- **A missing protection**: a protection raises a path only when the path can do damage it would have stopped, that is when the path reaches a secret, a write token or an impact; a path that reaches code execution without secrets, write token or impact is never raised, and neither is one whose only privilege is the repository's default token, whose write is assumed. Within that, an unprotected branch takes a path up one when the path really writes to the repository (a `contents` write a job declares, or a proven push, publish or deploy), and a missing protection on a job (an environment without approval, for example) takes up every path through that job. A protection that amplifies a path is charged through that path only. A hard-coded registry password and Dependabot's insecure code execution never amplify a path: their risk needs none, so they are always individual findings.
- **Push to an unprotected branch**: such a path is at most **High**. Pushing needs an account with write access, so this entry alone never makes a Critical path.
- **A dependency that can change**: such a path is capped, after every other move. Changing what runs takes a compromise of the action, reusable workflow, image, include or script first, so a dependency alone never makes a Critical path, unless a finding on the path says it is already bad: a published security advisory on the pinned version, a pinned commit that does not belong to the action's repository, or an action that hides a remote fetch and execution. How far it goes depends on what the findings on the path say about the dependency:
  - a reference that is only not pinned (an action not pinned by a commit SHA, an image on a forbidden tag or without a digest, a reference that names both a tag and a branch, an include or component on a forbidden version) is at most **Medium**: the dependency comes from a source you chose, and someone has to compromise it first;
  - the same reference from a source outside the authorized list (an action or reusable workflow owner, an image registry) is at most **High**: nobody vetted that source, so a compromise is more likely;
  - a dependency that is not a reference to pin (a script fetched and run, an action that fetches remote code or whose source could not be fetched) is at most **High**.

  The block reads what the path is, not how its points were computed, so no branch says the cap held it; with `--score-point` a `Note` line under the block says why the path stops at its tier (see below), and the JSON lists `dependency_cap` in its modifiers, followed by `source_cap` when an unauthorized source is what holds it at High rather than Medium. An entry a contributor controls (a fork pull request, an expression an attacker controls, a privileged trigger) is not capped.
- **A cache that a run that is not trusted can write**: such a path holds at the strongest cap among the paths that enter the jobs that can write the cache, since poisoning it takes getting into one of them first: Medium when only references that are only not pinned enter them, High when one of them is entered by a dependency from an unauthorized source, a script, or a push to an unprotected branch, no cap when a contributor or a dependency known bad enters one. A writer is a job entered by another path that runs (a job under a constant false `if:` never does) and saves in the default branch's cache scope (a push to it, a schedule, a dispatch, a privileged trigger), since a save in a pull request's, a tag's or another branch's scope reaches runs of that same ref only. The restoring job itself is never a writer of its own cache; a cache with no other writer starts no path, and its finding is an individual finding. The JSON lists `cache_writer_cap` in its modifiers when this lowered the path, after the cap it took from the writers (`dependency_cap`, `source_cap`, `push_entry_cap`).

A Critical path therefore means one of three things: someone outside your team can reach it, directly or through a cache they can write, or a dependency in it is known bad.

A job that never runs (one under a constant false condition) starts no path, is walked by none and writes no cache.

---

## Individual findings

Every live finding that no path uses is an **individual finding**, whatever kind of issue it is: a protection with no path to amplify, a hard-coded password, a permission or credential on a job no path reaches, a hygiene issue. It costs its own severity's price, all of them together count for at most 30 points, the worst first, and outside Critical they share the nested limit with the paths.

A finding that a path uses costs nothing more on its own: the entry findings of a path, a protection that amplifies it, and a credential or permission held by a job the path walks are all charged through the path.

### Severity shown per finding

Each finding shows the severity it is charged at. A finding that is the entry of a path shows the tier of the strongest path it starts; a credential or permission held by a job a path walks shows that path's tier; every other finding shows its own severity, the price it pays, with two readings of its own: a missing branch protection is Critical on the default branch and High on any other, and an action or reusable workflow from an owner outside the authorized list is High, Medium when it is pinned by a full commit SHA. Every output also keeps the finding's own severity next to it as `baseSeverity` (JSON, SARIF, GitLab SAST, CSV, OCSF, the platform push).

---

## Two examples

**`github.com/getplumber-examples/plumber-example-demo`: 34 points, D.**

The `plumber` workflow runs on every push to `main` with an `id-token` and a `security-events` write token, and `main` is not protected. The `ci/build` job runs on pull requests with a read token and no secret, and it puts the pull request title in a shell, runs `node:latest`, pipes a script from the network into `bash`, and uses a pinned `tj-actions/changed-files` that carries a published advisory.

- One **High** path: a push to the unprotected `main` runs the `plumber` job and its write token. The checkout credentials that job keeps are part of the same path and cost nothing more.
- Three **High** paths into `ci/build`, a job holding nothing: the title in the shell, the fetched script, and `tj-actions/changed-files` (two findings, one path). Running someone else's code in the pipeline is High even with no secret in reach.
- One **Medium** path: `node:latest` (two findings, one path) is only not pinned, so it is held at Medium.
- No individual finding.
- 4 x 15 + 6 = 66, under the 69 that high, medium and low items count for at most. **100 - 66 = 34, D.** Fixing the title in the shell gives back its 15: 49, still D.

The nested limit at work, by hand:

| Run | Sum | Counted | Points |
|---|---|---|---|
| 5 High paths | 75 | 69 | 31, D |
| 10 Medium paths | 60 | 49 | 51, C |
| 2 High and 12 Low paths | 30 + 36 | 30 + 29 = 59 | 41, D |
| 1 Critical and 1 High path | 30 + 15 | 45 | 55, held at 30: E |
| 1 Critical and 10 High individual findings | 20 + 100 | 20 + 10 (the 30 of the individual findings) | 70, C: no Critical path, nothing forced |

**A private GitLab project with a single job: 75 points, B.**

One job runs on `docker.io/alpine:latest`. The project's settings variables were not read in this run, so Plumber cannot list the job's secrets.

- One **High** path: a new `alpine:latest` image runs in the job. 15 points.
- One individual finding: a branch that should be protected is not (the default branch is protected, so no push path starts there), High on a branch other than the default one, 10 points.
- **100 - 15 - 10 = 75, B.** The individual finding is not a path, so nothing forces the score down. The best fix is protecting that branch: 85, B.

---

## What Plumber looks at

Before scoring, Plumber reads, from the same pipeline it analyzes, what each job holds and what it can change. These facts never change a control's result; they only decide what a finding is worth. Each one keeps the evidence that proved it (file, line, the text).

- **The repository**: its visibility (`public`, `private` or `unknown`; unknown is scored as public), its default branch and whether that branch is protected.
- **The triggers of each job**: whether a pull request or merge request from a fork reaches it, whether it also runs on a privileged trigger (`pull_request_target`, `workflow_run`, `issue_comment` and the like, which run with the repository's own secrets), and whether it runs on a push to the default branch while that branch is not known to be protected.
- **What each job holds**: the secrets it references (names only, never a value), its effective write permissions, persisted checkout credentials, its environment.
- **What each job changes**: a publish, a deploy, a write to the repository, a signing or release step, a cache or artifact another job uses. A job's environment is a protection, never a change by itself: the block says the job runs in it, and that it requires a review before the job runs when it does.
- **The includes**: which jobs each include shapes, so a finding on an include starts a path on each of them.

When these facts cannot be evaluated at all, the run uses the previous score and prints the warning `contextual score unavailable, scoring-v3 used`.

---

## What the report shows

The terminal is read from the bottom: the score is the last thing it prints, and the details are above it.

- **The individual findings in detail**: under an `Individual findings (n)` heading, the findings no path uses, one block per issue code, shaped like an attack path block: the severity (the code's own, for a finding no path uses), the code, its title and how many findings (`(35 findings)`, nothing for one); one branch per finding, saying where it runs (``job `analyze_pr` from workflow `analyze-pr.yml` ``, the message's own words for a finding with no job, a branch protection finding for instance) and what it found, with `↳ at` and where it is under it (the forge URL when the run has one, else `file:line`); then what it means (`So`, once when every finding of the code means the same, else under each branch as `so ...`), the fix (`Fix`) and the documentation (`↳ docs:`). The blocks print the least severe first, the worst last, closest to the attack paths, by code within a severity, a lighter rule (`┄`) between two. With colour on, the labels are bold and the documentation line is dim. With no individual finding this section is left out. The checkouts of `facebook/react-native` that keep their credentials:

  ```
   LOW   ISSUE-307  Checkout persists credentials in .git/config (latent) (35 findings)
         │
         ├──▶ job `analyze_pr` from workflow `analyze-pr.yml`: runs "actions/checkout@v6" without
         │    `persist-credentials: false`
         │    ↳ at https://github.com/facebook/react-native/blob/main/.github/workflows/analyze-pr.yml#L17
         ├──▶ ...
         └──▶ job `validate-dotslash-artifacts` from workflow `validate-dotslash-artifacts.yml`: runs
              "actions/checkout@v6" without `persist-credentials: false`
              ↳ at https://github.com/facebook/react-native/blob/main/.github/workflows/validate-dotslash-artifacts.yml#L33

         So     GITHUB_TOKEN lingers in .git/config (latent; becomes a leak if a later step packs .git
                into an artifact or runs fork-controlled code)
         Fix    set persist-credentials: false on the checkout
         ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-307
  ```
- **The attack paths in detail**: under an `Attack paths (n)` heading, one block per path, the least severe first, so the worst one, attack path 1, sits right above the score (the paths are numbered by tier, then within a tier by what they reach: every secret, then listed secrets, then a write token, then code execution alone; the best fix breaks a tie between two paths the same way), a lighter rule (`┄`) between two blocks, the last block closing the section. Each block is a small graph: the tier, `Attack path` and the path number (and `(unverified)` when Plumber could not verify the path), alone on the first line; the `Entry` line; one branch per job the entry enters, saying where the job runs and, after an arrow, what an attacker there reaches; then what it means (`So`), what Plumber could not check (`Note`) and the fix (`Fix`), and a last line naming the command that lists its findings (``↳ details: run `plumber explain -a 2` ``). With colour on, the labels are bold and the details line is dim. The push to the unprotected default branch of `plumber-example-demo`, and the poisoned cache of a release workflow:

  ```
   HIGH  Attack path 2
         Entry  main (branch anyone with write access can push to, not protected)
         │
         └──▶ runs in job `plumber` from workflow `plumber.yml`
              └─▶ reaches a token with write access to security events and an OIDC token

         So     as anyone with write access to `main`, an attacker can execute code to write to
                security events and request an OIDC token
         Fix    protect the default branch
         ↳ details: run `plumber explain -a 2`

    ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄

   CRIT  Attack path 1
         Entry  npm-${{ hashFiles('**/package-lock.json') }} (cache an untrusted run can write)
         │
         └──▶ runs in job `publish` from workflow `release.yml`
              └─▶ reaches 1 secret and a token with push, publish and deploy access

         So     as anyone who can write that cache, an attacker can read 1 secret of the repository,
                push in your repository, deploy and ship a malicious release
         Fix    do not restore a cache that untrusted runs can write in a release job
         ↳ details: run `plumber explain -a 1`
  ```

  The `Entry` line names what you can search for in your workflow (the action reference as `owner/repo@ref`, the image, the include, the script URL, the expression, the branch, or the cache: its key for `actions/cache`, else the cache the action keys itself, `Rust build cache, key prefix ${{ matrix.os }}` for `Swatinem/rust-cache` (its `prefix-key`, then its `shared-key`, else its `key`), `npm cache of setup-node` for a setup action's cache of a package manager, `Gradle cache of setup-gradle`, `cache of <action>` for the others), then, in parentheses, what it is, from the code that anchors the path: `mutable external action` for an action not pinned by SHA (`mutable action of your organization` when its owner is the analysed repository's own, which the authorized sources already trust; `of your organization` replaces `external` the same way for a reusable workflow, an image tag and the other natures below), `untrusted and mutable external action` when its owner is also outside the authorized list (the finding that holds the path at High rather than Medium), `external action with a known vulnerability`, `external action pinned to a commit that is not in its repository`, `external action that downloads code at run time from a mutable source` (`... downloads obfuscated code at run time`, `... downloads code at run time Plumber could not check`; `untrusted external action that downloads ...` when its owner is also outside the authorized list), `mutable image tag` (`untrusted and mutable image` from a registry outside the authorized list; on GitHub, where no control checks an image's source, `mutable image tag, source not checked on GitHub`, read as possibly malicious, unless the image is under the repository owner's own namespace, `ghcr.io/<owner>/`, which reads `mutable image tag of your organization`), `mutable external include`, `script downloaded and run at build time`, `user-controlled input injected in a script` (`input an insider controls, injected in a script` when only someone with write access sets it), `user-controlled variable expanded in a script`, `pull request code checked out in a privileged workflow`, `code of another workflow's run checked out`, `cache an untrusted run can write`, `branch anyone with write access can push to, not protected`, or `image computed at run time` (an action or a reusable workflow alike); a reusable workflow reads `reusable workflow` instead of `action`. When several codes anchor one path, the nature, the `So` line's actor, the `Fix` line and the merge request table all follow the same one, the most serious: a dependency known bad (a known vulnerability, then a commit not in the action's repository, then an action hiding a remote fetch), then an action that downloads code at run time, then a reference not pinned from a source outside the authorized list, then a reference only not pinned. When one finding covers several values of a matrix, the line names each (`one of: python:2.7, python:3.6 (mutable image tag)`). The line wraps when it is long, never cut. A commit SHA in an action reference shows as its first 12 characters (the finding's own line and the JSON keep the full reference). Each branch is a job the entry enters, in the order of the path's jobs, the strongest first: ``runs in job `triage` from workflow `labeler.yml` `` on GitHub (the workflow's name when no finding of that workflow names its file), ``runs in job `build` `` on GitLab, then what it reaches after `─▶ reaches`, on the same line when it fits there in fewer lines than under the job, else on the line under the job, opening on a corner under the job's first word (`└─▶ reaches`; `├─▶ reaches` when the job feeds others, so the tree runs on down to them), each line filled as far as the width allows and broken at the last phrase boundary that fits (after a `, `, before an ` and ` or before a parenthesis), never inside a parenthesised phrase and never between the token's verbs (`a token with push, publish and deploy access` and `(assumed: no permissions block)` are one phrase each), its lines under its first word after `reaches`. What a branch reaches reads as a sentence: `every secret of the repository` or `3 secrets` (secret names are never shown there, only how many), `secrets Plumber could not list`, then the token by what it lets code in the job do (`a token with push, publish and deploy access`: contents push, packages publish, deployments deploy; every other write scope after it, none dropped: `a token with push access and write access to issues and pull requests`, `a token with write access to discussions, issues and pull requests`; `(assumed: no permissions block)` on the token of a job with no permissions block, whatever else the branch reaches), `an OIDC token` whenever the token can request one, a step's own impact the token does not give (`a step that publishes`, `a step that deploys`, `a step that releases`), or `code execution on the runner, no secret and no write token`. What the entry job holds comes first; what the branch reaches only through a job it feeds follows, naming that job (with its workflow when it is another one's): ``reaches 2 secrets and, through job `release`, 1 secret and a token with push access``, or ``reaches through job `publish` from workflow `publish.yml`, 1 secret and a step that publishes`` when the entry job holds nothing itself. A job the entry job feeds hangs off it, naming what the entry job hands it: ``└──▶ feeds artifact to job `publish` from workflow `release.yml` `` when the entry job uploads an artifact the other downloads (``through workflow `release-publish.yml` `` when the job it feeds is in another workflow), `feeds cache to` when it saves a cache the other restores, `feeds output to` when the only link is a `needs` dependency (the job outputs it passes on), the kinds joined with `and` when several link the pair (`feeds artifact and cache to`); one per line, under the reach in the column of its corner:

  ```
         └──▶ runs in job `build_npm_package` from workflow `test-all.yml`
              ├─▶ reaches every secret of the repository
              ├──▶ feeds output to job `build_android_templateapp` from workflow `test-all.yml`
              └──▶ feeds output to job `test_ios_spm_newapp` from workflow `test-all.yml`
  ```

   The `So` line says who gets in and what they can do, wrapped like the reach, at its last phrase boundary that fits: for a dependency, by its trust and its mutability, the same two facts the `Entry` line reads (a trusted dependency can only be compromised, an untrusted one can also be malicious, and only one whose code can change can be compromised): `if this action is compromised or malicious` when what runs can change (a reference not pinned, code downloaded at run time, a reference computed at run time) and its source is not authorized (a script always, its URL being outside the trusted list), `if this action is malicious` when its source is not authorized but it is pinned by SHA or digest, `if this action is compromised` when what runs can change but its source is trusted (an include, an action of your organization, an action of a trusted owner that downloads code at run time), `through the known vulnerability of this action` for an action with an advisory, `through the commit this action is pinned to, which is not in its repository` for a commit outside it and `through the code fetch this action hides` for an action that hides a remote fetch (an image, an include, a script, a reusable workflow alike); `as anyone who can open a pull request` (`as anyone who can run the workflow`, `as anyone who can push` and the like for an expression only an insider sets), `as anyone who opens a pull request`, `as anyone who can write that cache` or ``as anyone with write access to `main` ``, then `an attacker can` and what the reach gives: `read every secret of the repository`, `execute code to push in your repository, publish packages and deploy`, `write to pull requests`, `request an OIDC token`, `alter what the job deploys`, `ship a malicious release`, or `execute code on the runner and poison what it caches or uploads`; `may` instead of `can` for what rests on a token whose write is assumed or on an impact that could not be confirmed (`an attacker can read 3 secrets and may push in your repository`). The `Fix` line is one thing to do: `pin the version on the commit SHA`, `use an action from a trusted source and pin the version on the commit SHA`, `move to a version without the advisory`, `pin a commit that exists in the action's repository`, `pin what the action downloads, or vendor it`, `use an action from a trusted source and pin what it downloads, or vendor it`, `pin the image by digest`, `use an image from a trusted registry and pin it by digest`, `pin the include on a commit SHA`, `download the script, check its checksum, then run it`, `pass the input through an environment variable`, `never check out the pull request head in a privileged workflow`, `do not restore a cache that untrusted runs can write in a release job`, `protect the default branch`, or, for a reference computed at run time, ``pin the reference to a literal in place of `${{ inputs.image }}` ``; the best fix of the score block reads the same words. A branch Plumber could not verify says `(unverified)` after its job, and a branch that runs only on some triggers names them (`(on pull_request_target)`); a branch never says which cap held it, that being how the score was computed rather than what the path is. Under `So`, a `Note` line says what Plumber could not check (`Plumber could not list the secrets`, `Plumber could not check what it runs`, `Plumber could not check that the token can write (no permissions block)` whenever the reach holds an assumed token, `Plumber could not check that this job pushes to the repository`, naming what it could not confirm: `publishes`, `deploys`, `pushes to the repository`, `releases`), the environment the entry job runs in (``the job runs in environment `npm-publish` ``, then `the environment requires a review before the job runs` when it does), which jobs can write a cache (never the job restoring it), named the way a branch names its job (``a run of job `preview` from workflow `pr-preview.yml` can write the cache``; with several, the first three grouped by workflow, ``runs of jobs `release-notes` and `security-scan` from workflow `build.yml`, `auto-approve` from workflow `ci.yml` and 5 more can write the cache``), and, with `--score-point` only (in the terminal and in the merge request comment), why a path a cap lowered stops at its tier: `Capped at High: it needs write access first` for a push entry, `Capped at Medium: it needs a dependency compromise first` for a reference that is only not pinned, `Capped at High: the source is not authorized, so a compromise is more likely` for one from a source outside the authorized list, `Capped at High: it needs a dependency compromise first` for any other dependency, and `Capped at Medium: the jobs that can write the cache need a dependency compromise first` (`... need write access first` through a push) for a cache its writers hold. `plumber explain -a N` prints block N with its `Findings` in full: every finding that starts the path, every protection that amplifies it, and every credential and permission it carries, one group per code shaped like an individual finding's block, each finding a branch of its group (see [Reading a path again](#reading-a-path-again)). Each path costs the price of its tier (Critical 30, High 15, Medium 6, Low 3); the totals are in the score block. The merge request comment shows the same graph in a code block under each path's heading (its first line says `path` and the number), its findings listed after it with their documentation links.
- **The final screen**, a `Score` section closing the report: the **Plumber Score** block beside the letter, with the points out of 100 and the bar on one line, the verdict against the gate right under it (`Status: FAILED (gate blocks at 100 pts)`, `Status: PASSED (gate at 100 pts)`, `(gate at grade B)` under `--min-score`, `(no control was evaluated)` when nothing was), then, after a blank line, the worst case, what attack path 1 means in the words of its `So` line, then the path and the subject of its entry (``Worst case: if this image is compromised, an attacker can read the secrets Plumber could not list (attack path 1: docker.io/alpine:latest)``; no line without a path), and the best fix right under it (the path or finding whose fix recovers the most points, with the points and letter it leads to, for example `Best fix: pin the image by digest (image node:latest), +6 pts, 70 / 100 (C)`), what does not fit beside the letter's six lines prints under the text column. With colour on, the `Worst case:` label is red and the `Best fix:` label green, the rest of their lines plain. When no single fix moves the score (a limit or the Critical path cap still holds it), the best fix is the path or finding with the highest price before the limits, alone (`Best fix: protect the default branch (push to main).`); the JSON `bestFix` then gains 0 points. These are the last lines of the run. The attack paths and the individual findings are not repeated there: their counts head their own sections above.
- With `--score-point`, the final screen shows how the figures add up. The score block adds, under the verdict, the subtraction (`100 - 15 (attack paths) - 30 (individual findings)`, each figure what the limits leave of its items), one line for each part of the nested limit that held (`high, medium and low items count for 69 at most`, `medium and low items count for 49 at most`, `low items count for 29 at most`) and one when the individual findings went over their 30 (`individual findings count for 30 at most`), and one more line when a Critical path held the score at 30 or it stopped at 0 (`Capped at 30: a Critical attack path remains.`, `The score does not go below 0.`). Under the best fix, a line says why it recovers what it does when that differs from the price of what the fix removes (`+13 pts: the path's 15, less 2 for a finding that then stands alone`, `+1 pts: the path's 6, of which 1 counts, medium and low items counting for 49 at most`), or why the score does not move yet (`The score stays at 31 while high, medium and low items count for 69 at most.`). Under the score block, one line per code of the individual findings, then one line per tier with its count and the points its paths take off (`high paths          x5   -69`). What each tier takes off is its part of the nested limit read from the lowest tier up: the low items first, up to 29, then the medium items up to what is left of 49, then the high items up to what is left of 69; within one tier the paths and the individual findings share that part by their prices, and each code of the individual findings shares theirs by its own, so the figures always add up to the subtraction. The JSON report carries every one of these figures with or without the flag.
- The final screen and the path blocks fit the terminal width (100 columns when the output is not a terminal, never fewer than 60): the bar is 28 cells, 20 when 28 do not fit beside the score, a long value wraps under its column, and in a path block what a branch reaches wraps under itself.

```
────────────────────
Score
────────────────────

  ██████╗  Plumber Score  75 / 100  █████████████████████░░░░░░░
 ██╔════╝  Status: FAILED (gate blocks at 100 pts)
 ██║
 ██║       Worst case: if this image is compromised, an attacker can read the secrets Plumber could
 ╚██████╗  not list (attack path 1: docker.io/alpine:latest)
  ╚═════╝  Best fix: protect the branch (dev), +10 pts, 85 / 100 (B)
```

The same run with `--score-point`:

```
  ██████╗  Plumber Score  75 / 100  █████████████████████░░░░░░░
 ██╔════╝  Status: FAILED (gate blocks at 100 pts)
 ██║       100 - 15 (attack paths) - 10 (individual findings)
 ██║
 ╚██████╗  Worst case: if this image is compromised, an attacker can read the secrets Plumber could
  ╚═════╝  not list (attack path 1: docker.io/alpine:latest)
           Best fix: protect the branch (dev), +10 pts, 85 / 100 (B)

           ISSUE-501  high     x1   -10
           high paths          x1   -15
```

The merge request comment opens on a summary instead, since a web page is read from the top: the score, the worst case and the best fix (with `--score-point`, also the subtraction, the limit lines, the Critical path cap or zero line and why the best fix recovers what it does), the individual findings, the attack paths as a table (number, tier, entry in the words of the block's `Entry` line, job, with the jobs the entry enters, two at most and the count of the others, and what it reaches), then the controls and the individual findings in detail, then the details of each path (at most 20; with `--score-point`, each with its cap `Note` when a cap lowered it), where a control split with a path says how many more of its findings the path details list.

These appear in the terminal, the merge request comment, the JSON report (`plumberScore.paths`, `plumberScore.pathLosses`, `plumberScore.otherFindings`, `plumberScore.codeLosses` for the individual findings per code, `plumberScore.bestFix`) and the platform push (`score.profile_id`, `final_points`, `results[].score_context`). The JSON report (`plumberScore.situation`) and the platform push (`score_context.situation`) also carry the situation, the facts about the repository and the pipeline (its visibility, the default branch and whether it is protected, the jobs and workflows or pipelines, and how many of them publish or deploy), which the terminal and the merge request comment do not print. The JSON report also says whether a Critical path held the score at 30 (`criticalMalusApplied`). In `pathLosses`, `cappedLoss` is what the tier takes off as the nested limit attributes it and `cap` is the part of the nested limit that holds the tier (69 for High, 49 for Medium, 29 for Low, none for Critical); in `otherFindings` and `codeLosses`, `cappedLoss` is what the individual findings take off once both their 30 and the nested limit held, and `capApplied` says the 30 held. The platform push carries the same `final_points` and `score_context`, with the same shape. `floorApplied` and `floorPoints` are kept for the readers that expect them and are never set: the score has no floor.

The legacy `--score` flag is deprecated and has no effect now that the score is shown by default. It is still accepted so existing invocations do not break.

---

## Reading a path again

Every `plumber analyze` run that produced a report keeps its JSON report (the document `--output` writes) in the user cache directory (`$XDG_CACHE_HOME`, else `~/.cache` on Linux, `~/Library/Caches` on macOS): `plumber/runs/<provider>/<owner>/<repo>.json` for a remote or detected project, `plumber/runs/local/<hash>.json` for a local analysis with no project path (the hash of its working directory), and `plumber/runs/last` naming the most recent one. The files are readable by the user alone, and a run whose cache cannot be written goes on as if nothing happened.

`plumber explain -a N` (`--attack N`) reads the last run and prints its attack path `N`, numbered as the report numbers them, worst first: the block as the report shows it, then, under `Findings`, every finding of the path, one group per code, a blank line before each, in the order of the block's findings (the codes that start the path first), each laid out as an individual finding's block: the contextual severity, the code, its title and how many findings; one branch per finding, saying where it runs and what it found, with `↳ at` and the forge URL when the run has one (else `file:line`) under it; what it means (`So`) once when the findings share it, else under each branch; `Fix` only for a code that does not start the path (a privilege or a protection), the block's own `Fix` fixing its entry; and `↳ docs:` once. `-a all` prints every path, path 1 first. `--project owner/repo` reads that project's last run instead (add `--provider github` or `--provider gitlab` when both have one), and `--run report.json` reads a report written by `--output`, a CI artifact for instance. The JSON report carries what this needs in `pathBlocks`, one entry per path (`id`, then the block's lines and its `findings`, each carrying its findings in full in `details`: `message`, `severity`, `url`, `location`).

```
$ plumber explain -a 2
 HIGH  Attack path 2
       Entry  main (branch anyone with write access can push to, not protected)
       │
       └──▶ runs in job `plumber` from workflow `plumber.yml`
            └─▶ reaches a token with write access to security events and an OIDC token

       So     as anyone with write access to `main`, an attacker can execute code to write to
              security events and request an OIDC token
       Fix    protect the default branch
       Findings

          HIGH  ISSUE-501  Branch protection missing
                │
                └──▶ Branch `main` is not protected.

                ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-501

          HIGH  ISSUE-307  Checkout persists credentials in .git/config (latent)
                │
                └──▶ job `plumber` from workflow `plumber.yml`: runs "actions/checkout@v5" without
                     `persist-credentials: false`
                     ↳ at https://github.com/getplumber-examples/plumber-example-demo/blob/main/.github/workflows/plumber.yml#L17

                So     GITHUB_TOKEN lingers in .git/config (latent; becomes a leak if a later step
                       packs .git into an artifact or runs fork-controlled code)
                Fix    set persist-credentials: false on the checkout
                ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-307
```

---

## Withheld score

When **nothing at all** evaluated, a run or a policy has no basis for a score. Zero findings over an empty or all-`not_evaluable` control set would otherwise compute a perfect 100/A, which reads as a clean pass rather than as nothing having been checked. The score is **withheld** instead: the banner prints "Score withheld: no control was evaluated", the JSON report omits `plumberScore` (top-level) and the policy entry's `score`, and the push omits the policy's `score`. This applies at both levels: a whole run with nothing evaluated, and, in platform mode, an individual policy whose own control set evaluated nothing while other policies in the same run scored normally.

Degraded data collection withholds the score the same way: the JSON report and the run cache `plumber explain -a` reads carry neither `plumberScore` nor `pathBlocks`, and the PBOM carries no score. A withheld score prints no attack paths.

An enabled control none of whose substantive configuration fields is set is not evaluated (`not_evaluable`, reason `config_required`) and contributes no findings. When at least one other control genuinely evaluated, the score is computed over that smaller evaluated set.

---

## Gating CI on the score

The score is also the pass/fail gate for `plumber analyze` (exit code 1 on failure). The gate reads the score you selected: the contextual score by default, the previous score under `--score-profile v3`.

- `--min-points <0-100>`: fail when the final points are below the value. **Default: 100**: any finding that costs points fails the run.
- `--min-score <A-E>`: fail when the letter is below the given one (e.g. `--min-score B` fails on C, D, E). When set without `--min-points`, the letter alone gates.
- Both set: both must pass.

**In platform mode (`--platform`) these flags are inert:** the exit code is the platform's gate verdict, computed per policy from each policy's `enforcement` and `min_points`; a locally supplied threshold prints an "ignored" notice. The JSON report then carries a `policies` array (one score per policy) and, at the top level, the platform's global score. `--controls` and `--skip-controls` are inert the same way: the platform's policy configuration is the only way to exclude a control from a linked run, so both flags print an "ignored" notice and every resolved policy still evaluates its full control set. Until the platform stores the score the CLI pushes, it keeps recomputing the previous score from the pushed findings, so the platform's figure can differ from the CLI's.

A run where **zero controls were evaluated** fails the score gate rather than passing as an empty 100-point pipeline: a `.plumber.yaml` that enables no controls for the scanned provider (e.g. a `github:`-only config on a GitLab project), a filter that skips them all, and, on GitLab, where a missing or unparseable CI configuration leaves no control evaluated, a project with no usable CI. On GitLab this matches the historical default (compliance was 0 in those cases).

**On GitHub, a repository with no workflows (or workflows Plumber cannot parse) passes the default gate** when its enabled controls report no findings: the pre-0.4.0 behavior, deliberately restored so fleet scanners can sweep repositories that have no CI without failing on them. The score is then computed over what could be checked; gate on findings, not on CI presence.

A related but distinct shape: GitHub's control count, unlike GitLab's, does not exclude `not_evaluable` controls, so a repository whose enabled controls are all `config_required` still carries a nonzero control count. Nothing was actually checked either way, so the score is withheld exactly as in the zero-control case above, but the **exit code does not change**: this shape already passed the gate before this rule existed, and a withheld score still passes it now, for the same reason a `.plumber.yaml`-declared empty policy passes. Only the number shown changes, from a perfect A to none.

The legacy `--threshold` flag (percentage of passing controls) is **deprecated**: it still works, with a warning, and cannot be combined with the score gate flags.

The JSON report spells out the active gate next to the verdict: `minPoints` / `minScore` (or `threshold` when the deprecated flag is used) and `passed`.

---

## Where this appears

| Surface | When |
|---------|------|
| Terminal | By default |
| `plumber analyze --output ...` JSON | `plumberScore` object, by default |
| PBOM / CycloneDX | Same fields and CycloneDX properties (see [PBOM.md](PBOM.md)) |
| Merge request comment | The summary, then the controls and the findings in detail, then the path details, by default; under the previous score, a short block, and the points with `--score-point` |
| Score badge | The letter of the score you selected |

---

## The previous score (`scoring-v3`)

Select it with `--score-profile v3` or `PLUMBER_ANALYZE_SCORE_PROFILE=v3`. The output then carries `profileId: "scoring-v3"`, with no attack paths, no situation and no `baseSeverity`; findings keep their own severity. The badge, the merge request comment and the `--min-points` / `--min-score` gates read this score instead. To compare both scores over many repositories, see [Migrating from the previous score](scoring-v4-migration.md).

The previous score prices issue codes, not paths: any Critical issue forces the score into the E band regardless of how few other issues there are.

### Inputs: per-code counts

Plumber walks every open issue on **enabled** (non-skipped) controls and aggregates them by **issue code** (e.g. `ISSUE-401`, `ISSUE-205`). Each code carries a documented **severity** (Critical, High, Medium, Low) which determines its weight and per-code cap.

- `counts.{critical,high,medium,low}`: total findings per severity (banner, merge request comment).
- `codeLosses[]`: per-code rows that drive the score (full breakdown via `--score-point`).

Occurrences of a code that share the same finding identity count once toward that code's tally.

### Step 1: loss per issue code

For each code with count `n > 0`, the **weight** `w` and **per-code cap** `C` come from its severity:

| Severity | Weight `w` | Cap `C` per code |
|----------|:----------:|:-----------------:|
| Critical | 25 | none |
| High     | 15 | 60 |
| Medium   | 6  | 20 |
| Low      | 3  | 10 |

```text
L_uncapped = w x (1 + 0.5 x log2(n))
L          = L_uncapped for Critical, min(L_uncapped, C) otherwise
```

Each new code at the same severity opens a fresh budget up to its own `C`, so the score keeps reflecting the diversity of issues; repeats of one code taper off and are bounded by `C`.

### Step 2: raw points

```text
rawPoints = max(0, 100 - sum of the per-code capped losses)
```

The result also exposes a per-severity rollup (`losses[]`), the sum of per-code capped losses inside each severity. This rollup is informational and can exceed any single per-code cap once multiple codes accumulate.

### Step 3: Critical malus

If at least one Critical issue exists (`counts.critical > 0`), `finalPoints = min(rawPoints, 30)`, `criticalMalusApplied` is `true` and `criticalMalusMax` is `30`. Otherwise `finalPoints = rawPoints`.

### Step 4: letter

The letter is read from final points with the thresholds above (A >= 90, B >= 71, C >= 51, D >= 31, E below), so `finalPoints = 30` maps to E.

### Breakdown

With `--score-point`, a **points breakdown** table prints after the banner with one row per issue code (`Code | Severity | Count | Weight | Cap | Loss`), then base 100, total loss, raw points, malus line (if any), final points, and letter score.

---

## Stability and changes

Every result names the rules that produced it in `profileId`: `scoring-v4` for the contextual score, `scoring-v3` for the previous score. If a price, a limit or a letter threshold changes, the profile id changes with it and this page is updated, so a stored result can always be read against the rules that produced it.
