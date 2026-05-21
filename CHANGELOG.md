## [0.3.3](https://github.com/getplumber/plumber/compare/v0.3.2...v0.3.3) (2026-05-21)

## [0.3.2](https://github.com/getplumber/plumber/compare/v0.3.1...v0.3.2) (2026-05-21)


### 🐛 Bug Fixes

* **config:** Generate correct msg in plumber config generate ([f7cda10](https://github.com/getplumber/plumber/commit/f7cda10664119d058d3baf904ffa7161fcf36f4c))

## [0.3.1](https://github.com/getplumber/plumber/compare/v0.3.0...v0.3.1) (2026-05-21)


### 🐛 Bug Fixes

* **ci:** remove ci testing vlaues ([fb7d2e5](https://github.com/getplumber/plumber/commit/fb7d2e5b7a9a5b50e40a0f285f5154ff1961ac8e))

## [0.3.0](https://github.com/getplumber/plumber/compare/v0.2.22...v0.3.0) (2026-05-20)


### ⚠ BREAKING CHANGES

* **config:** .plumber.yaml schema is now per-provider. Existing
v1 files keep working with a deprecation warning; run
`plumber config migrate` to upgrade on disk.

Update .plumber.yaml from the flat top-level controls: block (legacy v1)
to a per-provider layout where each control lives under gitlab.controls:
or github.controls:. Same control name, different values per platform:
the trusted-registry list on GitLab is registry.gitlab.com/..., on
GitHub it's ghcr.io/<org>/..., and there was no way to express that
before. v2 fixes it.

Schema:
- version: "2.0" = current per-provider schema. version: "1.0" =
  legacy flat schema (auto-converted in memory at load time, with a
  deprecation warning).
- Add ProviderConfig / AuthConfig types; PlumberConfig now carries
  GitLab/GitHub fields and a ControlsFor(provider) helper.
- LoadPlumberConfig detects v1 vs v2 by structural inspection, runs
  convertV1ToV2 for legacy files, rejects unsupported version values,
  and scans the raw YAML for the deprecated engine: key (warning
  only — the field is gone from the struct).
- ValidateKnownKeys handles both v1 (controls.X.subkey) and v2
  (gitlab.controls.X.subkey, github.controls.X.subkey) paths.

Migration tooling:
- Add `plumber config migrate` subcommand. Rewrites a v1 .plumber.yaml
  into v2 on disk, preserving comments via the yaml.v3 node API.
  Default writes <input>.v2; --in-place overwrites with a .bak backup.
  No-op on already-v2 files. Refuses to migrate mixed v1+v2 files
  (top-level controls AND a gitlab.controls already present); the user
  resolves manually.

Caller migration:
- cmd/legacy_json.go, cmd/render_details.go, cmd/init.go,
  control/task.go (evaluatePolicies now takes a provider arg),
  control/task_github.go, control/catalog.go (GitLabControls,
  FilterFindingsByEnabledControls, DisabledControlNames take
  *ControlsConfig directly) — all rewired to read through
  ControlsFor("gitlab"|"github") so each provider sees its own values.
- 14 legacy getter methods on PlumberConfig
  (GetBranchMustBeProtectedConfig, etc.) updated to read from the v2
  location. The branch-protection one was gating the collector —
  without this fix, branch findings silently disappeared on real
  GitLab pipelines.

Side-quest fix that surfaced during validation:
- policies/security_jobs_weakened.rego — _weakening_reason(job) was a
  function with three := bodies that could each return a different
  string for the same job. Real-world pipelines triggering two of them
  at once (e.g. when:manual at job level AND a rules: override) hit
  Rego's eval_conflict_error and the engine returned zero findings.
  Each weakening signal is now its own deny rule; Rego set semantics
  allows multiple findings per job naturally. New regression test
  TestIssue410_MultipleWeakeningsOnOneJob.

Default config:
- .plumber.yaml updated to v2 shape with version: "2.0".

Docs:
- New docs/plumber-yaml-v2-migration.md: 30-second migration, before/
  after, rationale, backward-compat, anchors for shared values, edge
  cases, deprecation timeline, manual cookbook.
- Replace the README "Multi-provider configuration (roadmap)"
  subsection with a real "Multi-provider configuration" section
  showing v2 example, anchor pattern, and a link to the migration
  guide.

### ✨ Features

* **analysis:** Rego/OPA engine with GitHub provider and GitLab parity ([c487121](https://github.com/getplumber/plumber/commit/c48712114e5b2d3a222697c5a3af263c97f80284)), closes [#148](https://github.com/getplumber/plumber/issues/148) [#148](https://github.com/getplumber/plumber/issues/148)
* **config:** per-provider YAML schema (v2.0); plumber config migrate; docs ([bf84cfd](https://github.com/getplumber/plumber/commit/bf84cfd462afce54d469f9f7c9ae3b5597d20e88))
* **controls:** add workflowMustIncludeRequiredActions; fix includes count ([8d262f8](https://github.com/getplumber/plumber/commit/8d262f821d49851e62b7188c3c573c3d5ea6fe59))
* **controls:** ISSUE-203 GitHub hardening — expression env + $GITHUB_ENV script writes (all critical) ([c85c1ab](https://github.com/getplumber/plumber/commit/c85c1abc6dfe8f4df6dbb7dbf41bd4eb50381086))
* **controls:** ship 4 GitHub controls + fix 2 collector caveats ([3b903ef](https://github.com/getplumber/plumber/commit/3b903ef48d8f6ef9cd86159ebbb751bf7fc5dce9))
* **github:** bench-list gating + GitLab-semantic parity + GHES URL ([b5e4293](https://github.com/getplumber/plumber/commit/b5e429340c495b7bd425af35aa2f9719aff504b0))
* **github:** branchMustBeProtected — first project-governance control ([4200bf1](https://github.com/getplumber/plumber/commit/4200bf12ded9359563609ce880a494a33d45f8d9))
* **github:** close the GitHub-side gaps — wizard, artifacts, filters, parity ([2d49870](https://github.com/getplumber/plumber/commit/2d498708e2f641f1ac02b750b6b8edf875bccd54))
* **github:** honest auth UX — preflight banner + postflight skipped markers ([c033cdb](https://github.com/getplumber/plumber/commit/c033cdb0f0ee04a00ef7b379783b894a5b531ac1))
* **github:** per-control parity output + skip API when no consumer ships ([da2d8a7](https://github.com/getplumber/plumber/commit/da2d8a7fe60e0b64e284c900cdcba5a2b758f43c))
* **github:** upstream fetch via --github-url + --project (parity with GitLab) ([5dca4f5](https://github.com/getplumber/plumber/commit/5dca4f550beb429893d0f917cfb983c1a3790076))


### 🐛 Bug Fixes

* **artifact:** Correctly display outputs ([53f5df8](https://github.com/getplumber/plumber/commit/53f5df809b02fb8811aad5c565269292b62d8a1e))
* **artifact:** Flatten rego output from findings to root ([5790964](https://github.com/getplumber/plumber/commit/5790964a497adf9eb680475dcc1331ca9a6c61e9))
* **comments:** Copilot comments ([d928465](https://github.com/getplumber/plumber/commit/d928465eccd3a420e61ca8ee7e35a0fd5051c719))
* **control:** Job variables override should not only detect user-overridden sensitive variables ([a6dd96f](https://github.com/getplumber/plumber/commit/a6dd96f346d10f6b5095c029a5c3c3ae283d826d))
* **ctrls:** Rename issue codes ([b21942c](https://github.com/getplumber/plumber/commit/b21942c7afdd7726e0fa762f29d89e7333a5e9d7))
* **dockerfile:** Fix image and disable automatic creation of cli ([372620e](https://github.com/getplumber/plumber/commit/372620e9e5797554d729fc474deaa820af3faec3))
* **github:** branch-protection accuracy + issue [#158](https://github.com/getplumber/plumber/issues/158) ([1da1d63](https://github.com/getplumber/plumber/commit/1da1d63dbb3b201f96cd4ef4d81cb252fbaf833d))
* **github:** branchMustBeProtected — populate defaultBranch + drop access-level mapping ([1ef4533](https://github.com/getplumber/plumber/commit/1ef4533649e3ac2652cc83a75253845620097d07))
* **github:** Fix sha bugs in github integration ([ae08ae8](https://github.com/getplumber/plumber/commit/ae08ae8af7d7e0ceba203510e5a8ed9056fbec0c))
* **github:** live progress + skip out-of-scope branches in protection fetch ([74e2f66](https://github.com/getplumber/plumber/commit/74e2f66b6d6030f0a8ba37ad26812ffaf3ef5018))
* **issues:** Update links to new issues doc ([e1d01fc](https://github.com/getplumber/plumber/commit/e1d01fc7de86756576cffa333e331ba16cbacd78))
* **test:** Add missing test files) ([1637920](https://github.com/getplumber/plumber/commit/163792078e6622b0544f5e2519dd02d17fb4266d))
* **test:** Fix test to include new workflow control ([c2e5f6a](https://github.com/getplumber/plumber/commit/c2e5f6a8daa93524f52803fa3d33a56534db42ba))

## [0.2.22](https://github.com/getplumber/plumber/compare/v0.2.21...v0.2.22) (2026-05-01)


### ✨ Features

* **scoring:** per-code caps and rebalanced weights (scoring-v3) ([a613467](https://github.com/getplumber/plumber/commit/a613467444fe5f68228fdfcd8cb4cc263c1b6b7e))

## [0.2.21](https://github.com/getplumber/plumber/compare/v0.2.20...v0.2.21) (2026-04-28)


### ✨ Features

* **controls:** Change severities ([c213692](https://github.com/getplumber/plumber/commit/c21369274c39deec3b8d9e501261fc6703aa9033))

## [0.2.20](https://github.com/getplumber/plumber/compare/v0.2.19...v0.2.20) (2026-04-28)


### ✨ Features

* **controls:** ALlow issues 102 and 103 to trigger at the same time ([fdd4616](https://github.com/getplumber/plumber/commit/fdd461672f64e563281dd74e26879517ba002a84))

## [0.2.19](https://github.com/getplumber/plumber/compare/v0.2.18...v0.2.19) (2026-04-24)

## [0.2.18](https://github.com/getplumber/plumber/compare/v0.2.17...v0.2.18) (2026-04-24)

## [0.2.17](https://github.com/getplumber/plumber/compare/v0.2.16...v0.2.17) (2026-04-24)

## [0.2.16](https://github.com/getplumber/plumber/compare/v0.2.15...v0.2.16) (2026-04-24)

## [0.2.15](https://github.com/getplumber/plumber/compare/v0.2.14...v0.2.15) (2026-04-24)

## [0.2.14](https://github.com/getplumber/plumber/compare/v0.2.13...v0.2.14) (2026-04-24)

## [0.2.13](https://github.com/getplumber/plumber/compare/v0.2.12...v0.2.13) (2026-04-24)

## [0.2.12](https://github.com/getplumber/plumber/compare/v0.2.11...v0.2.12) (2026-04-24)

## [0.2.11](https://github.com/getplumber/plumber/compare/v0.2.10...v0.2.11) (2026-04-24)


### 🐛 Bug Fixes

* **conf:** Trust sha pinned versions of plumber ([090f8c7](https://github.com/getplumber/plumber/commit/090f8c71c7266b91534cca79db1eb50747bb6133))

## [0.2.10](https://github.com/getplumber/plumber/compare/v0.2.9...v0.2.10) (2026-04-24)

## [0.2.9](https://github.com/getplumber/plumber/compare/v0.2.8...v0.2.9) (2026-04-23)


### ✨ Features

* **scoring:** Change issues severities and dampen score loss ([8af879a](https://github.com/getplumber/plumber/commit/8af879a71ca3c68e248d76df67bd6c7266d69b75))

## [0.2.8](https://github.com/getplumber/plumber/compare/v0.2.7...v0.2.8) (2026-04-22)


### 🐛 Bug Fixes

* **gitlab:** handle scalar include in GitlabCIConf unmarshalling ([a5888cf](https://github.com/getplumber/plumber/commit/a5888cf1b39c5280c1b04fcc311fda26b917b1b7))
* **tests:** Add more exhaustive tests for unmarshaling error on inclusion ([a3c0bf1](https://github.com/getplumber/plumber/commit/a3c0bf1ff2e47bd7dffabf37aae7e21dd90775b9))

## [0.2.7](https://github.com/getplumber/plumber/compare/v0.2.6...v0.2.7) (2026-04-21)


### 🐛 Bug Fixes

* **mr:** Mr badge must take to doc ([f99986b](https://github.com/getplumber/plumber/commit/f99986b910cc433b52372b91204914b7c37e9ce5))

## [0.2.6](https://github.com/getplumber/plumber/compare/v0.2.5...v0.2.6) (2026-04-21)


### ✨ Features

* **cli:** Bump versions ([4e37488](https://github.com/getplumber/plumber/commit/4e37488ea17f7ee78fcb5abbdce455bf9f190756))

## [0.2.5](https://github.com/getplumber/plumber/compare/v0.2.4...v0.2.5) (2026-04-20)


### ✨ Features

* **scoring:** Update scoring badge url to point to our doc and update scoring doc to including letter descriptions ([58bad14](https://github.com/getplumber/plumber/commit/58bad14d7e655124eb510f3c96493ce2e551475a))

## [0.2.4](https://github.com/getplumber/plumber/compare/v0.2.3...v0.2.4) (2026-04-20)


### ✨ Features

* **release:** Update release to use app + update default trustedUrls ([00f97a2](https://github.com/getplumber/plumber/commit/00f97a2dc1147a3a96da3d6ef0b8c5bf5b25df24))


### 🐛 Bug Fixes

* **ci:** Replace with app id ([5f880b9](https://github.com/getplumber/plumber/commit/5f880b943711e0aadfa40a0a6253e224c3f63271))

## [0.2.3](https://github.com/getplumber/plumber/compare/v0.2.2...v0.2.3) (2026-04-20)

## [0.1.84](https://github.com/getplumber/plumber/compare/v0.1.83...v0.1.84) (2026-04-17)


### ✨ Features

* **score:** Set scoring go v1 and update some severities ([6402fd9](https://github.com/getplumber/plumber/commit/6402fd9002a8c5ed1f1bdeae8eb2b00091e4b1d1))

## [0.1.83](https://github.com/getplumber/plumber/compare/v0.1.82...v0.1.83) (2026-04-17)


### ✨ Features

* **artifact:** new scoring concept: ([ab7d4b6](https://github.com/getplumber/plumber/commit/ab7d4b6b4f262ed50a7d8af3c3907e1387c2eae4))

## [0.1.82](https://github.com/getplumber/plumber/compare/v0.1.81...v0.1.82) (2026-04-13)


### ✨ Features

* **cmd:** Add explain command that explains briefly issues ([88f2b91](https://github.com/getplumber/plumber/commit/88f2b917c5a25c29a9a33f1f9478f83826019cd4))


### 🐛 Bug Fixes

* **ci:** Update alpine image to 3.22 and only fail CI when issues have known fixes - no point otherwise ([f5b9edc](https://github.com/getplumber/plumber/commit/f5b9edcf46169d060db0e8da03ad89fea6a48db2))
* **go:** Update to go 1.26 ([3960953](https://github.com/getplumber/plumber/commit/39609530367dbad02692779d4442f180cb6e707c))

## [0.1.81](https://github.com/getplumber/plumber/compare/v0.1.80...v0.1.81) (2026-04-03)

## [0.1.80](https://github.com/getplumber/plumber/compare/v0.1.79...v0.1.80) (2026-04-03)

## [0.1.79](https://github.com/getplumber/plumber/compare/v0.1.78...v0.1.79) (2026-04-03)

## [0.1.78](https://github.com/getplumber/plumber/compare/v0.1.77...v0.1.78) (2026-04-03)

## [0.1.77](https://github.com/getplumber/plumber/compare/v0.1.76...v0.1.77) (2026-04-02)


### ✨ Features

* **control:** Add control to detect basic DinD and unsecure DinD ([6a03424](https://github.com/getplumber/plumber/commit/6a034247c60348572dc4a039101ae14b6b49ab82))

## [0.1.76](https://github.com/getplumber/plumber/compare/v0.1.75...v0.1.76) (2026-03-31)


### ✨ Features

* **control:** Add control to detect overriden variables pipelineMustNotOverrideJobVariables ([bd095da](https://github.com/getplumber/plumber/commit/bd095daaaee9294fb92f1afa4a76c47e9d24fab6))

## [0.1.75](https://github.com/getplumber/plumber/compare/v0.1.74...v0.1.75) (2026-03-27)

## [0.2.0](https://github.com/getplumber/plumber/compare/v0.1.74...v0.2.0) (2026-03-27)

## [0.2.0](https://github.com/getplumber/plumber/compare/v0.1.74...v0.2.0) (2026-03-27)

## [0.2.0](https://github.com/getplumber/plumber/compare/v0.1.74...v0.2.0) (2026-03-27)

## [0.2.0](https://github.com/getplumber/plumber/compare/v0.1.74...v0.2.0) (2026-03-27)

## [0.1.74](https://github.com/getplumber/plumber/compare/v0.1.73...v0.1.74) (2026-03-27)


### ✨ Features

* **cmd:** Add new flag --ci-config-path to allow overriding .gitlab-ci.yml ([150e230](https://github.com/getplumber/plumber/commit/150e2308f39cab64b54e4dba49b24770053ab4a3))

## [0.1.73](https://github.com/getplumber/plumber/compare/v0.1.72...v0.1.73) (2026-03-23)


### 🐛 Bug Fixes

* **ci:** Enable attestation arrival in artifacts ([8de06af](https://github.com/getplumber/plumber/commit/8de06affa41da3f5b7ced83a192d3bbdbc42d056))

## [0.1.72](https://github.com/getplumber/plumber/compare/v0.1.71...v0.1.72) (2026-03-20)


### 🐛 Bug Fixes

* **pipeline:** Attach attestation to container ([e465aa2](https://github.com/getplumber/plumber/commit/e465aa2de339352e53dd933607dfa7f5f8e00102))

## [0.1.71](https://github.com/getplumber/plumber/compare/v0.1.70...v0.1.71) (2026-03-20)


### 🐛 Bug Fixes

* **readme:** Bump to 0.1.71 ([ae64855](https://github.com/getplumber/plumber/commit/ae64855db19dce1396186357b41f2d067776f42f))

## [0.1.70](https://github.com/getplumber/plumber/compare/v0.1.69...v0.1.70) (2026-03-20)

## [0.1.69](https://github.com/getplumber/plumber/compare/v0.1.68...v0.1.69) (2026-03-18)


### ✨ Features

* **control:** Add control to check unverified inline script exceution ([cbb416b](https://github.com/getplumber/plumber/commit/cbb416b0c4984be268fd1c8accde589af925578f))

## [0.1.68](https://github.com/getplumber/plumber/compare/v0.1.67...v0.1.68) (2026-03-17)


### 🐛 Bug Fixes

* **issues:** Update issues link ([bc42f2f](https://github.com/getplumber/plumber/commit/bc42f2fdd8c0b74e210d254423e57951327aa48a))

## [0.1.67](https://github.com/getplumber/plumber/compare/v0.1.66...v0.1.67) (2026-03-16)


### ✨ Features

* add structured error codes (PLB-XXXX) with documentation links ([692f9d4](https://github.com/getplumber/plumber/commit/692f9d429d779eaa3df27f743314c7b7e247533f)), closes [#92](https://github.com/getplumber/plumber/issues/92)


### 🐛 Bug Fixes

* **issues:** Update issues urls and prefix ([7ced522](https://github.com/getplumber/plumber/commit/7ced52221ba9b7c5be9670ad386d56fc409e099f))

## [0.1.66](https://github.com/getplumber/plumber/compare/v0.1.65...v0.1.66) (2026-03-13)


### 🐛 Bug Fixes

* **analysis:** Fix output that --failing-warnings exits with code 2 ([2a23489](https://github.com/getplumber/plumber/commit/2a2348924758460d6a7c45f02afc83da27fbe27a))

## [0.1.65](https://github.com/getplumber/plumber/compare/v0.1.64...v0.1.65) (2026-03-13)


### ✨ Features

* **cmd:** differentiate exit codes for compliance vs runtime errors (closes [#61](https://github.com/getplumber/plumber/issues/61)) ([b07f2f8](https://github.com/getplumber/plumber/commit/b07f2f8d58e40e4dabdc1dd48beec0019854c2c7))

## [0.1.64](https://github.com/getplumber/plumber/compare/v0.1.63...v0.1.64) (2026-03-13)


### ✨ Features

* **controls:** Add securityJobsMustNotBeWeakened control: ([6dbad42](https://github.com/getplumber/plumber/commit/6dbad42f3ebf4fa49895bb07840a976ced4f4dc3))


### 🐛 Bug Fixes

* **dockerfile:** Update builder image to remove vulns ([7d620c9](https://github.com/getplumber/plumber/commit/7d620c9c04a63310dadc1d55f179b4b035dc5428))

## [0.1.63](https://github.com/getplumber/plumber/compare/v0.1.62...v0.1.63) (2026-03-11)

## [0.1.62](https://github.com/getplumber/plumber/compare/v0.1.61...v0.1.62) (2026-03-11)

## [0.1.61](https://github.com/getplumber/plumber/compare/v0.1.60...v0.1.61) (2026-03-10)


### ✨ Features

* **conf:** Add conf diff ([d48e5e1](https://github.com/getplumber/plumber/commit/d48e5e118d4a57fbd3ed260158a68c0f82bb1e17)), closes [#62](https://github.com/getplumber/plumber/issues/62)


### 🐛 Bug Fixes

* **control:** Add doc and fix edge cases: ([13359f7](https://github.com/getplumber/plumber/commit/13359f7f57c2964e3b3a73ca9243863f83de79a0))

## [0.1.60](https://github.com/getplumber/plumber/compare/v0.1.59...v0.1.60) (2026-03-06)

## [0.1.59](https://github.com/getplumber/plumber/compare/v0.1.58...v0.1.59) (2026-03-06)


### ✨ Features

* **ci:** Add openssf best practices ([c99cc15](https://github.com/getplumber/plumber/commit/c99cc1514ae1fa05e8ea2f5501210a798bba3434))

## [0.1.58](https://github.com/getplumber/plumber/compare/v0.1.57...v0.1.58) (2026-03-06)


### ✨ Features

* **ci:** Add go vuln checks and ask dependabot to update go deps ([3e588c7](https://github.com/getplumber/plumber/commit/3e588c78004fbe63ee6a4f086a2f0112ddaa6f3f))

## [0.1.57](https://github.com/getplumber/plumber/compare/v0.1.56...v0.1.57) (2026-03-05)


### 🐛 Bug Fixes

* **ci:** Improve scorecard score: ([c784ba6](https://github.com/getplumber/plumber/commit/c784ba63af49208639b4ba9678c447ba88ee92d5))
* **ci:** Pin builder image ([d8b88f9](https://github.com/getplumber/plumber/commit/d8b88f9322f7d16d8d1218fa290c1a329d715955))

## [0.1.56](https://github.com/getplumber/plumber/compare/v0.1.55...v0.1.56) (2026-03-05)


### 🐛 Bug Fixes

* **ci:** Ensure slsa3 attestation is uploaded ([29a33c0](https://github.com/getplumber/plumber/commit/29a33c0c2a8a91e03f96a74d23e4738a228dafae))

## [0.1.55](https://github.com/getplumber/plumber/compare/v0.1.54...v0.1.55) (2026-03-05)


### 🐛 Bug Fixes

* **ci:** Bump semantic release and upload artifact versions ([26d81f9](https://github.com/getplumber/plumber/commit/26d81f9d1e2aa1bc061f3da22b4b428c789c358d))

## [0.1.54](https://github.com/getplumber/plumber/compare/v0.1.53...v0.1.54) (2026-03-05)


### 🐛 Bug Fixes

* **ci:** Allow slsa3 stage to write ([fea8113](https://github.com/getplumber/plumber/commit/fea8113e6bac78eae5226d533bd4877601f00f72))
* **ci:** Make salsa upload artifacts before release ([bff7fcb](https://github.com/getplumber/plumber/commit/bff7fcbb8fe1a93d8dcbbe877b6eccc83fcf0792))

## [0.1.53](https://github.com/getplumber/plumber/compare/v0.1.52...v0.1.53) (2026-03-05)


### ✨ Features

* **ci:** add SLSA 3 provenance, OpenSSF Scorecard, and security hardening ([5dad4a3](https://github.com/getplumber/plumber/commit/5dad4a38550416da5bc2f8d59ac9373e9eb00423))


### 🐛 Bug Fixes

* **ci:** Update versions and creds handling: ([cb3477a](https://github.com/getplumber/plumber/commit/cb3477aba3d2a46f1ce70b7b57bfc43abba9b5bc))

## [0.1.52](https://github.com/getplumber/plumber/compare/v0.1.51...v0.1.52) (2026-03-04)


### ✨ Features

* **controls:** Add unsafe variable expansion control for user-filled predefined variables ([0f7ec72](https://github.com/getplumber/plumber/commit/0f7ec723ff0b03ffb1c345fa393eaa8f9e022dd7))

## [0.1.51](https://github.com/getplumber/plumber/compare/v0.1.50...v0.1.51) (2026-03-03)


### ✨ Features

* **controls:** Add debug trace detection control ([5e08b97](https://github.com/getplumber/plumber/commit/5e08b974d17ee2468768f6b8a2917b09eddfe0ff)), closes [#86](https://github.com/getplumber/plumber/issues/86)


### 🐛 Bug Fixes

* **rebase:** Rebase on main and add spinner ([20e8c63](https://github.com/getplumber/plumber/commit/20e8c63c5334875e467244fb55bcb059e978c3b8))

## [0.1.50](https://github.com/getplumber/plumber/compare/v0.1.49...v0.1.50) (2026-03-03)


### ✨ Features

* **cmd:** Add progress spinner during analysis ([80b1bad](https://github.com/getplumber/plumber/commit/80b1bad2a9b556d0e8414e2c90b4199cda5b26c4)), closes [#64](https://github.com/getplumber/plumber/issues/64)

## [0.1.49](https://github.com/getplumber/plumber/compare/v0.1.48...v0.1.49) (2026-03-03)


### ✨ Features

* **ci:** Replace trivvy with grype ([984286f](https://github.com/getplumber/plumber/commit/984286f2ca871792b8a12e34bea7a647cb72450f))

## [0.1.48](https://github.com/getplumber/plumber/compare/v0.1.47...v0.1.48) (2026-03-03)


### ✨ Features

* **ci:** Add dependabot ([3480a77](https://github.com/getplumber/plumber/commit/3480a777b3ef3bcf1dd72269da67aad28c3fcf0b))
* **ci:** Start adding test, lint, scan and pin versions by digest ([ec77e70](https://github.com/getplumber/plumber/commit/ec77e709864ddf621ca5337de3345c5c18627466))


### 🐛 Bug Fixes

* **ci:** Fix CI lint issues ([5288379](https://github.com/getplumber/plumber/commit/528837904a46b7b6334bbfe5f767d200faebdc81))

## [0.1.47](https://github.com/getplumber/plumber/compare/v0.1.46...v0.1.47) (2026-02-25)


### ✨ Features

* **controls:** Add overridden component and templates issue & integration into pbom and cyclonedex ([e970c27](https://github.com/getplumber/plumber/commit/e970c27697c29873057a5f6b6109715ba47d3896))

## [0.1.46](https://github.com/getplumber/plumber/compare/v0.1.45...v0.1.46) (2026-02-25)


### ✨ Features

* **cmd:** Add --fail-warnings on the analyze and config validate commands ([fbc5839](https://github.com/getplumber/plumber/commit/fbc58391ebc1e51d412588ed5748587a6e125227))
* **cmd:** validating config file before analysis ([a1dc4bd](https://github.com/getplumber/plumber/commit/a1dc4bd7c14d4fe230f770849c0b12683fba8323))


### ♻️ Refactoring

* **cmd:** extract config validation logic ([db02f52](https://github.com/getplumber/plumber/commit/db02f524a28a83645631a0c7325bea161f1d86db))

## [0.1.45](https://github.com/getplumber/plumber/compare/v0.1.44...v0.1.45) (2026-02-25)


### ✨ Features

* **cmd:** notify user when a newer version of plumber is available ([deca33f](https://github.com/getplumber/plumber/commit/deca33f74d9c2f1c2468d8ce98a5693df1fa9d9c)), closes [#39](https://github.com/getplumber/plumber/issues/39)
* **version:** async update check with opt-out ([a1ef745](https://github.com/getplumber/plumber/commit/a1ef74553e85c2341e803ea4ec683f6f0c4d6e31))


### 🐛 Bug Fixes

* **release:** Persist creds throughout release cycle ([4483cf0](https://github.com/getplumber/plumber/commit/4483cf0fc8704f0763f95ee8bfc28462be66e157))

## [0.1.45](https://github.com/getplumber/plumber/compare/v0.1.44...v0.1.45) (2026-02-25)


### ✨ Features

* **cmd:** notify user when a newer version of plumber is available ([deca33f](https://github.com/getplumber/plumber/commit/deca33f74d9c2f1c2468d8ce98a5693df1fa9d9c)), closes [#39](https://github.com/getplumber/plumber/issues/39)
* **version:** async update check with opt-out ([a1ef745](https://github.com/getplumber/plumber/commit/a1ef74553e85c2341e803ea4ec683f6f0c4d6e31))

## [0.1.44](https://github.com/getplumber/plumber/compare/v0.1.43...v0.1.44) (2026-02-19)


### ✨ Features

* **analyze:** add --controls and --skip-controls control filtering ([9a9aca0](https://github.com/getplumber/plumber/commit/9a9aca0a50e63eb27a7f7c8f5470ae6922ff425c))


### 🐛 Bug Fixes

* **controls:** Fix bug in controls parsing and swap around some functions and files ([cdf0507](https://github.com/getplumber/plumber/commit/cdf050792ce83b674ce80429f63767d81c90f321))

## [0.1.43](https://github.com/getplumber/plumber/compare/v0.1.42...v0.1.43) (2026-02-18)


### ✨ Features

* **config:** Add ValidateKnownKeys to warn on unknown config keys ([4c33ca3](https://github.com/getplumber/plumber/commit/4c33ca3c980cc57419b7b457bfae09c7543ba8d3)), closes [#58](https://github.com/getplumber/plumber/issues/58) [#58](https://github.com/getplumber/plumber/issues/58)


### 🐛 Bug Fixes

* **config:** Fix compilation issues + make validation recursive to test subkeys ([405abe4](https://github.com/getplumber/plumber/commit/405abe4dc7f78f2bee3e72b7e94f7f9a7568c4d7))

## [0.1.42](https://github.com/getplumber/plumber/compare/v0.1.41...v0.1.42) (2026-02-17)


### ✨ Features

* **analysis:** Add --mr-comment to create mr comments during analysis. Add --badge to create/update Plumber compliance badge when running on default remote branch ([4cba483](https://github.com/getplumber/plumber/commit/4cba4839ce3512ef2da7ff5b9512dca701d2a7f7))

## [0.1.41](https://github.com/getplumber/plumber/compare/v0.1.40...v0.1.41) (2026-02-12)


### ✨ Features

* **local:** Enable lint, validation and analysis of local .gitlab-ci.yml as well as local reoslution of include: local types. ([5a2a3aa](https://github.com/getplumber/plumber/commit/5a2a3aa3b67c8489289bf98f47f9494f386f6458))

## [0.1.40](https://github.com/getplumber/plumber/compare/v0.1.39...v0.1.40) (2026-02-12)


### ✨ Features

* **UX:** Integrate the control pinned by digest inside the immutable one ([87bd450](https://github.com/getplumber/plumber/commit/87bd45074c7d0710f67dfe23e486421eda1baf39))

## [0.1.39](https://github.com/getplumber/plumber/compare/v0.1.38...v0.1.39) (2026-02-12)


### ✨ Features

* **UX:** If a control is misisng from .plumber.yaml simply skip it instead of returning an error ([3eec388](https://github.com/getplumber/plumber/commit/3eec388d75d0e28792c580dc95c79f89663af5e3))

## [0.1.38](https://github.com/getplumber/plumber/compare/v0.1.37...v0.1.38) (2026-02-12)


### ✨ Features

* **controls:** add image digest pinning control ([ea538a9](https://github.com/getplumber/plumber/commit/ea538a954def56d4695b0d766f3bb1aff8ee7bbd))


### 🐛 Bug Fixes

* **control:** Disable sha pin by default and update readme ([1d24837](https://github.com/getplumber/plumber/commit/1d2483747880d2f6f53b87b64064975bffb313e1))

## [0.1.37](https://github.com/getplumber/plumber/compare/v0.1.36...v0.1.37) (2026-02-11)


### ✨ Features

* **artifact:** Add new concept: Pipeline Bill Of Materials (PBOM) and add cyclonedx output format support ([7097605](https://github.com/getplumber/plumber/commit/7097605f85123ea7599e67d7b22e34bfa13e726b))

## [0.1.36](https://github.com/getplumber/plumber/compare/v0.1.35...v0.1.36) (2026-02-11)


### ✨ Features

* **conf:** Add reference to examples in test file for required includes ([a8ec829](https://github.com/getplumber/plumber/commit/a8ec82961ab5152a3b6a1bff938afbc63978b7e6))

## [0.1.35](https://github.com/getplumber/plumber/compare/v0.1.34...v0.1.35) (2026-02-11)


### 🐛 Bug Fixes

* **detection:** support SSH URL and Git protocol formats in remote auto-detection ([8e162aa](https://github.com/getplumber/plumber/commit/8e162aaf7a9f21cedd183edf2a3aa00c6dc91b5d)), closes [#36](https://github.com/getplumber/plumber/issues/36)

## [0.1.34](https://github.com/getplumber/plumber/compare/v0.1.33...v0.1.34) (2026-02-10)


### ✨ Features

* **control:** Support Natural Language in pipeline inclusion for templates and components ([59c4edd](https://github.com/getplumber/plumber/commit/59c4edddb2750296d06d282e7c5efd272e3aa81d))

## [0.1.33](https://github.com/getplumber/plumber/compare/v0.1.32...v0.1.33) (2026-02-10)


### 🐛 Bug Fixes

* **branch:** use correct SHA for ciConfig query when --branch is specified ([1729084](https://github.com/getplumber/plumber/commit/1729084509de141d282e3a3d49c62fe7864e385e))

## [0.1.32](https://github.com/getplumber/plumber/compare/v0.1.31...v0.1.32) (2026-02-04)


### ✨ Features

* **control:** Make component collecetion compatible with gitlab built-in components ([532f071](https://github.com/getplumber/plumber/commit/532f071544c58f8c3af1cbf4771b43a1e296a799))

## [0.1.31](https://github.com/getplumber/plumber/compare/v0.1.30...v0.1.31) (2026-02-04)


### ✨ Features

* **control:** Add 3 new controls ([591a850](https://github.com/getplumber/plumber/commit/591a8509f47c1cc21eb3bf71ad185163368ba033))

## [0.1.30](https://github.com/getplumber/plumber/compare/v0.1.29...v0.1.30) (2026-02-03)


### ✨ Features

* **analysis:** Allow auto-detection for gitlab url and project during analysis + update banner ([e7a20e6](https://github.com/getplumber/plumber/commit/e7a20e6e2b49bdf7cc7805effebc765e73930b2d))

## [0.1.29](https://github.com/getplumber/plumber/compare/v0.1.28...v0.1.29) (2026-02-03)


### ✨ Features

* **conf:** Add conf view and move generate under conf ([8e549e9](https://github.com/getplumber/plumber/commit/8e549e97ab462dbf46d7f5d25dea8fd77989c796))

## [0.1.28](https://github.com/getplumber/plumber/compare/v0.1.27...v0.1.28) (2026-02-02)


### ✨ Features

* **update:** Empty commit ([b7bd04f](https://github.com/getplumber/plumber/commit/b7bd04fa8ab8430c15afd625ea27ce3ae2030e8e))

## [0.1.27](https://github.com/getplumber/plumber/compare/v0.1.26...v0.1.27) (2026-01-30)


### ✨ Features

* **ci:** Run on ubuntu 24.04 instead of latest ([b5473d2](https://github.com/getplumber/plumber/commit/b5473d2d527dc6672f332670d729f2eb4701944f))

## [0.1.26](https://github.com/getplumber/plumber/compare/v0.1.25...v0.1.26) (2026-01-30)


### ✨ Features

* **brew:** Test release 0.1.26 ([1848d52](https://github.com/getplumber/plumber/commit/1848d5248fd9c38cc54d8da11b24ef9694afb48d))

## [0.1.25](https://github.com/getplumber/plumber/compare/v0.1.24...v0.1.25) (2026-01-30)


### 🐛 Bug Fixes

* **brew:** Typo in release ([6c80575](https://github.com/getplumber/plumber/commit/6c80575c26f7294e8fa3a1553d10aa3f88864adb))
* **brew:** Typo in release ([4d7b905](https://github.com/getplumber/plumber/commit/4d7b905d84e47f25cda4c7b770b0f8660f453f7e))

## [0.1.24](https://github.com/getplumber/plumber/compare/v0.1.23...v0.1.24) (2026-01-30)


### ✨ Features

* **brew:** Enable automatic updating of brew tap formula repo upon new release ([ead9860](https://github.com/getplumber/plumber/commit/ead98601a2e355403975b087a5f0da1b3653fb76))

## [0.1.23](https://github.com/getplumber/plumber/compare/v0.1.22...v0.1.23) (2026-01-30)


### ✨ Features

* **conf:** Correct dockerfile and release file ([34263ec](https://github.com/getplumber/plumber/commit/34263ec71a90183a65e9b1511e90f34ce6d2e1a2))

## [0.1.22](https://github.com/getplumber/plumber/compare/v0.1.21...v0.1.22) (2026-01-30)


### ✨ Features

* **conf:** Allow conf generation with command ([7390e76](https://github.com/getplumber/plumber/commit/7390e763055c23a44506ba43db2331fb09a0b0e7))

## [0.1.21](https://github.com/getplumber/plumber/compare/v0.1.20...v0.1.21) (2026-01-29)


### ✨ Features

* **analyze:** Make conf and threshold optional ([bf6a4df](https://github.com/getplumber/plumber/commit/bf6a4dfc3c306d0bb9bd3cd8e7e6a20bcaf9522a))

## [0.1.20](https://github.com/getplumber/plumber/compare/v0.1.19...v0.1.20) (2026-01-28)


### ✨ Features

* **license:** Update license in readme to MPL-2.0 ([4cbab86](https://github.com/getplumber/plumber/commit/4cbab86370f2ee3c5d010d5888e17e1d6fa9d445))

## [0.1.19](https://github.com/getplumber/plumber/compare/v0.1.18...v0.1.19) (2026-01-23)


### 🐛 Bug Fixes

* **bug:** Cleanup some dead code ([fa7e1ae](https://github.com/getplumber/plumber/commit/fa7e1ae3f445ed2047c5ab4ef0a4a66f0bc8ad93))

## [0.1.18](https://github.com/getplumber/plumber/compare/v0.1.17...v0.1.18) (2026-01-23)


### ✨ Features

* **conf:** Introduce priority and automatic detection of conf files ([91ef31b](https://github.com/getplumber/plumber/commit/91ef31b3a43b1fa150a8fba1c2c880a2220b80ef))

## [0.1.17](https://github.com/getplumber/plumber/compare/v0.1.16...v0.1.17) (2026-01-23)


### ✨ Features

* **analysis:** Revert CI_JOB_TOKEN ([6c12fb5](https://github.com/getplumber/plumber/commit/6c12fb59ad73147ca96c3e58ce570eab751706eb))

## [0.1.16](https://github.com/getplumber/plumber/compare/v0.1.15...v0.1.16) (2026-01-23)


### 🐛 Bug Fixes

* **analysis:** If no controls ran (e.g., data collection failed), compliance is 0% - we can't verify anything ([7ec0e72](https://github.com/getplumber/plumber/commit/7ec0e72ca459539c4a8e4d4fdbc04faf01ddfae8))

## [0.1.15](https://github.com/getplumber/plumber/compare/v0.1.14...v0.1.15) (2026-01-23)


### ✨ Features

* **component:** Allow verbosity in component ([b59015a](https://github.com/getplumber/plumber/commit/b59015a9bd64213ca0b3cf21ea02b16e833eee13))

## [0.1.14](https://github.com/getplumber/plumber/compare/v0.1.13...v0.1.14) (2026-01-23)


### ✨ Features

* **controls:** Rename control outputs and config to make them more human-readable & Start using CI_JOB_TOKEN if in the CI ([6669707](https://github.com/getplumber/plumber/commit/66697073a13a337230f88a5ba1213def645f474d))

## [0.1.13](https://github.com/getplumber/plumber/compare/v0.1.12...v0.1.13) (2026-01-22)


### ✨ Features

* **log:** Improve logging experience ([426bcf8](https://github.com/getplumber/plumber/commit/426bcf817bc62c382b5487443832b49372cbe890))

## [0.1.12](https://github.com/getplumber/plumber/compare/v0.1.11...v0.1.12) (2026-01-22)


### ✨ Features

* **UX:** Define default output file, add output json example ([3dbfa1c](https://github.com/getplumber/plumber/commit/3dbfa1c9172b561e35ce52d834e794bc2fb08091))

## [0.1.11](https://github.com/getplumber/plumber/compare/v0.1.10...v0.1.11) (2026-01-22)


### ✨ Features

* **naming:** Rename components to plumber, no need for the analyze suffix ([53a0816](https://github.com/getplumber/plumber/commit/53a08165e7d879099606505c98cce7abc45715eb))

## [0.1.10](https://github.com/getplumber/plumber/compare/v0.1.9...v0.1.10) (2026-01-22)


### ✨ Features

* **output:** Improve readability of printed results ([97d708f](https://github.com/getplumber/plumber/commit/97d708f75d5b76fba6bb3724543837eb371f5c04))

## [0.1.9](https://github.com/getplumber/plumber/compare/v0.1.8...v0.1.9) (2026-01-21)


### 🐛 Bug Fixes

* **build:** Move release creation to after asset upload ([bc96e39](https://github.com/getplumber/plumber/commit/bc96e39f0a4fc56185b62199a1f0da8e6a503367))

## [0.1.8](https://github.com/getplumber/plumber/compare/v0.1.7...v0.1.8) (2026-01-21)


### ✨ Features

* **build:** Add platforms binary releases ([01d9bfa](https://github.com/getplumber/plumber/commit/01d9bfa79b80cf9d2c7ea6d1984e2acc7a4db9bb))

## [0.1.7](https://github.com/getplumber/plumber/compare/v0.1.6...v0.1.7) (2026-01-19)


### 🐛 Bug Fixes

* **analysis:** Fix bug where analyzed branch was being mistaken for branches to protect ([afdd5f8](https://github.com/getplumber/plumber/commit/afdd5f8424a3a05120e50feb3dd99909bd5dba6a))

## [0.1.6](https://github.com/getplumber/plumber/compare/v0.1.5...v0.1.6) (2026-01-19)


### 🐛 Bug Fixes

* **comment:** Add timeout comment to client ([15df3f0](https://github.com/getplumber/plumber/commit/15df3f002dea5c9ba5a6a95b9943eafa1dc0230d))

## [0.1.5](https://github.com/getplumber/plumber/compare/v0.1.4...v0.1.5) (2026-01-19)


### 🐛 Bug Fixes

* **component:** Add full docker path to plumber as trusted ([d7732c8](https://github.com/getplumber/plumber/commit/d7732c8d1fefd7f12730e60e963a703d2a120a64))

## [0.1.4](https://github.com/getplumber/plumber/compare/v0.1.3...v0.1.4) (2026-01-19)


### 🐛 Bug Fixes

* **doc:** Add plumber to trusted images ([2a80e1a](https://github.com/getplumber/plumber/commit/2a80e1a831d42b31d75a5af5407a2a2e7582473a))

## [0.1.3](https://github.com/getplumber/plumber/compare/v0.1.2...v0.1.3) (2026-01-19)


### 🐛 Bug Fixes

* **variables:** Fix self referential variable ([d5aa9a9](https://github.com/getplumber/plumber/commit/d5aa9a93891b61c7a70a63f533d676084820a03a))

## [0.1.2](https://github.com/getplumber/plumber/compare/v0.1.1...v0.1.2) (2026-01-19)


### ✨ Features

* **build:** Move to alpine to make command customizable in CI ([763bcf3](https://github.com/getplumber/plumber/commit/763bcf3eadd21fdf53503033b00ced44b1a6b862))
* **release:** Downgrade feat to patch ([eb30e81](https://github.com/getplumber/plumber/commit/eb30e8183466068954edbd4e700986e02bfd72af))

## [0.2.0](https://github.com/getplumber/plumber/compare/v0.1.1...v0.2.0) (2026-01-19)


### ✨ Features

* **build:** Move to alpine to make command customizable in CI ([763bcf3](https://github.com/getplumber/plumber/commit/763bcf3eadd21fdf53503033b00ced44b1a6b862))

## [0.1.1](https://github.com/getplumber/plumber/compare/v0.1.0...v0.1.1) (2026-01-19)


### 🐛 Bug Fixes

* **release:** empty commit to trigger release and push ([e8bd954](https://github.com/getplumber/plumber/commit/e8bd954354e6c11ceef9fc53c89d634196a0e7af))

## [0.0.1](https://github.com/getplumber/plumber/compare/v0.0.0...v0.0.1) (2026-01-19)


### 🐛 Bug Fixes

* **license:** Update to use Elv2 license ([01656d0](https://github.com/getplumber/plumber/commit/01656d0664524323264bd5cbd7d1cb3419e1f7ce))
* **naming:** Fix further naming convention with plumber ([3389f25](https://github.com/getplumber/plumber/commit/3389f2581be70a079990490e0880b3f15160c972))
* **naming:** Rename to plumber and disable majors ([f442113](https://github.com/getplumber/plumber/commit/f442113514cebd654431a80e2d30b2ea1289dbfa))
