## [0.4.52](https://github.com/getplumber/plumber/compare/v0.4.51...v0.4.52) (2026-09-03)


### ✨ Features

* **artifacts:** emit the analyzed commit ref in every artifact and the analyzed CI file in the JSON report ([#443](https://github.com/getplumber/plumber/issues/443)) ([15e5bd6](https://github.com/getplumber/plumber/commit/15e5bd69a5605aec893d65139bfe247a7dbdfbba))


### 👷 CI/CD

* **release:** pin v0.4.51 refs [skip ci] ([d71e846](https://github.com/getplumber/plumber/commit/d71e846c3c466dd81320057bed01aeb1a726ca85))

## [0.4.51](https://github.com/getplumber/plumber/compare/v0.4.50...v0.4.51) (2026-09-01)


### ✨ Features

* **catalog:** export human-readable control names and categories ([#440](https://github.com/getplumber/plumber/issues/440)) ([c50e9c7](https://github.com/getplumber/plumber/commit/c50e9c7d22cbe69b20cc9116a63436e422d68bca))


### ✅ Tests

* **platform:** assert display metadata on the decoded push body for all three finding branches ([2dbf0c5](https://github.com/getplumber/plumber/commit/2dbf0c51f59bd67b247ea6d5fc3c50fcd7a309ad))
* **platform:** pin the review-flagged guards from the platform-mode audit ([8261477](https://github.com/getplumber/plumber/commit/8261477b5517446daae54bff6f879dce69b8d086)), closes [#431](https://github.com/getplumber/plumber/issues/431)


### 👷 CI/CD

* **release:** pin v0.4.50 refs [skip ci] ([39b2b67](https://github.com/getplumber/plumber/commit/39b2b67cf1cc5ee5dff464b5e0d7682514cb5b1b))

## [0.4.50](https://github.com/getplumber/plumber/compare/v0.4.49...v0.4.50) (2026-08-31)


### ✨ Features

* **platform:** export include job attribution and consume includes[].jobs ([619949c](https://github.com/getplumber/plumber/commit/619949c6763f1eb4f7eae43f838f63133016b1a6))
* **platform:** fetch policies and collected data from the platform ([9e3fb7e](https://github.com/getplumber/plumber/commit/9e3fb7ed66d47d937a2adc14ee3d0bcf9dbacf27))
* **platform:** fire the resolve request at setup and collect it at first use ([97656cb](https://github.com/getplumber/plumber/commit/97656cb5a5ad2805c469b7ed88acda666071de46))


### 🐛 Bug Fixes

* **cmd:** compare the checkout remote to --gitlab-url ignoring the scheme ([bdc398e](https://github.com/getplumber/plumber/commit/bdc398ebe985d0d3824fc9387b961fd34958e45d))
* **gitlab:** a platform cache miss is not an authoritative empty variables listing ([4c6f96e](https://github.com/getplumber/plumber/commit/4c6f96e12ec485db6a32868d700a9cd38fadf4af))
* **gitlab:** normalise the nested-include comparison and export SplitComponentPath ([81322b0](https://github.com/getplumber/plumber/commit/81322b0122c5fd534fce0b344aa5e5d560416bee))
* **platform:** drop the sync ResolveRunConfig wrapper the deadcode gate rejects ([9f2bb87](https://github.com/getplumber/plumber/commit/9f2bb87210ceac50c83cd0b99b21ca2a4679dba6))
* **platform:** push effective_config as the flat per-provider controls map ([fd04954](https://github.com/getplumber/plumber/commit/fd049544f313c51da7b8b0ca5ddba4e93f54c004))


### 👷 CI/CD

* **release:** pin v0.4.49 refs [skip ci] ([0c96d72](https://github.com/getplumber/plumber/commit/0c96d722cda12c0049f05979c7e19dfa4f1df1ad))

## [0.4.49](https://github.com/getplumber/plumber/compare/v0.4.48...v0.4.49) (2026-08-31)


### 🐛 Bug Fixes

* **ci:** treat a review that completes without structured output as zero findings ([fb00f18](https://github.com/getplumber/plumber/commit/fb00f18348f7e149a1daa03a159f710e2358a637))


### ✅ Tests

* **cli:** pin that --no-controls keeps collected include versions ([a6ab96d](https://github.com/getplumber/plumber/commit/a6ab96df5fa33698438a3d208d60b298e97cf3e2)), closes [#435](https://github.com/getplumber/plumber/issues/435)


### 👷 CI/CD

* **release:** pin v0.4.48 refs [skip ci] ([c5bb99e](https://github.com/getplumber/plumber/commit/c5bb99e31f9581bd75925686c9bfc9bb599915c3))

## [0.4.48](https://github.com/getplumber/plumber/compare/v0.4.47...v0.4.48) (2026-08-28)


### ✨ Features

* **cli:** add --no-controls to produce artifacts without a verdict ([0768e95](https://github.com/getplumber/plumber/commit/0768e95a38a64bdbdfac0e6d57ff7e90a6b0f767))


### 👷 CI/CD

* **release:** pin v0.4.47 refs [skip ci] ([515390b](https://github.com/getplumber/plumber/commit/515390bd199eab3dab6c4fb948c15e2dd8ec7c54))

## [0.4.47](https://github.com/getplumber/plumber/compare/v0.4.46...v0.4.47) (2026-08-28)


### ✨ Features

* **controls:** grade artipacked by exploitability (ISSUE-307 low + ISSUE-310 high) ([d76162c](https://github.com/getplumber/plumber/commit/d76162c14918caba91b67f5e13294e5976835504))
* **controls:** ship checkoutMustNotPersistCredentials (ISSUE-307) ([4ff3a9d](https://github.com/getplumber/plumber/commit/4ff3a9d7f5fb1986c0dd313eae1f908e9827784a))


### 🐛 Bug Fixes

* **controls:** finish the ISSUE-310 wiring ([210aad6](https://github.com/getplumber/plumber/commit/210aad6af7ab6641a59bacce29666b3013214878))


### 👷 CI/CD

* **release:** pin v0.4.46 refs [skip ci] ([fa2385f](https://github.com/getplumber/plumber/commit/fa2385fc109164e9d59088dbaecdf0ae1e3c2d91))

## [0.4.46](https://github.com/getplumber/plumber/compare/v0.4.45...v0.4.46) (2026-08-28)


### ✨ Features

* **controls:** extend ISSUE-215 to github.event.inputs (gated) ([3bce177](https://github.com/getplumber/plumber/commit/3bce177e389df5efd9049bc57c41b0a01725dfd3))


### 🐛 Bug Fixes

* **policies:** drop the trigger gate on github.event.inputs ([98fe157](https://github.com/getplumber/plumber/commit/98fe1573ac70fb21dd1001d0f13d20ac41609fc9))


### 👷 CI/CD

* **release:** pin v0.4.45 refs [skip ci] ([7c463a9](https://github.com/getplumber/plumber/commit/7c463a9871d0d413640b2f64d2eadbdd6bec5031))

## [0.4.45](https://github.com/getplumber/plumber/compare/v0.4.44...v0.4.45) (2026-08-28)


### 🐛 Bug Fixes

* **policies:** one finding per dangerous variable in unsafe-variable-expansion ([1f78450](https://github.com/getplumber/plumber/commit/1f78450f26cd7593d231e878d2ca288f525db1d8))


### 👷 CI/CD

* **release:** pin v0.4.44 refs [skip ci] ([c0cf184](https://github.com/getplumber/plumber/commit/c0cf184c0534104cd3fbd7f828056c2910f83cad))

## [0.4.44](https://github.com/getplumber/plumber/compare/v0.4.43...v0.4.44) (2026-08-26)


### ✨ Features

* **controls:** add projectMustHaveSecurityPolicySource (ISSUE-601, GitLab Ultimate) and renumber workflowsMustHaveExplicitName to ISSUE-422 for site parity ([9d62204](https://github.com/getplumber/plumber/commit/9d6220491a232849a331b6963a23248792345905))


### 🐛 Bug Fixes

* **controls:** address review on the security policy source control ([0217d76](https://github.com/getplumber/plumber/commit/0217d76eae448a0fef640b3cbe0c9b518b3c1d9a))


### 📚 Documentation

* **controls:** update controls doc to make it more precise ([1eaca39](https://github.com/getplumber/plumber/commit/1eaca399400a00c598f3482991ecee6385c6fc80))


### 👷 CI/CD

* **release:** pin v0.4.43 refs [skip ci] ([cfb0484](https://github.com/getplumber/plumber/commit/cfb0484442e90b18d15a741dc9ad660057906e52))

## [0.4.43](https://github.com/getplumber/plumber/compare/v0.4.42...v0.4.43) (2026-08-26)


### ✨ Features

* **controls:** add mergeRequestSettingsMustBeCompliant (ISSUE-506) with a conditional Premium/Ultimate caveat for merge-train and merged-pipeline expectations ([6345dc4](https://github.com/getplumber/plumber/commit/6345dc4fafa5f820c88adb0c819f2d6d70436608))
* **controls:** make ISSUE-503 approval-settings findings read as current-vs-expected and add a Premium/Ultimate tier caveat when no protections are in effect ([deacbfb](https://github.com/getplumber/plumber/commit/deacbfb61edd900d1921c97b61739926ae7b9cfe))


### 🐛 Bug Fixes

* **controls:** address review on the MR approval/settings controls ([a70ef57](https://github.com/getplumber/plumber/commit/a70ef57aacd44906a8bfbf5e0f93a666427e2986))


### 👷 CI/CD

* **release:** pin v0.4.42 refs [skip ci] ([4d247c2](https://github.com/getplumber/plumber/commit/4d247c293183c21f81c6c5539da52980b4a8fcb3))

## [0.4.42](https://github.com/getplumber/plumber/compare/v0.4.41...v0.4.42) (2026-08-25)


### ✨ Features

* **controls:** Add MR approval rules controls ([a2dfb69](https://github.com/getplumber/plumber/commit/a2dfb6961365ed99684a54780ed0cc1bca4842b7)), closes [#412](https://github.com/getplumber/plumber/issues/412)


### 👷 CI/CD

* **release:** pin v0.4.41 refs [skip ci] ([0baded9](https://github.com/getplumber/plumber/commit/0baded912f54e9f112455a5b33892bfcbf909054))

## [0.4.41](https://github.com/getplumber/plumber/compare/v0.4.40...v0.4.41) (2026-08-24)


### ✨ Features

* **controls:** Import variables protected and masked controls ([8e9cdf0](https://github.com/getplumber/plumber/commit/8e9cdf0d1becfe06b556551acdc11ed731e60d03))


### 👷 CI/CD

* **release:** pin v0.4.40 refs [skip ci] ([91cd7c2](https://github.com/getplumber/plumber/commit/91cd7c2f4bbf9cca2ee90ebb3d25c2e58cc7e53a))

## [0.4.40](https://github.com/getplumber/plumber/compare/v0.4.39...v0.4.40) (2026-08-21)


### 🐛 Bug Fixes

* **docker:** stamp version metadata into the published image ([f88e404](https://github.com/getplumber/plumber/commit/f88e404a1e60aaa17b4d4b302278cf18713cc93c)), closes [#425](https://github.com/getplumber/plumber/issues/425)


### 👷 CI/CD

* **release:** pin v0.4.39 refs [skip ci] ([e93967c](https://github.com/getplumber/plumber/commit/e93967c99ed5d579ecc514d805b6367405d1ffc1))

## [0.4.39](https://github.com/getplumber/plumber/compare/v0.4.38...v0.4.39) (2026-08-17)


### ✨ Features

* **ci:** Add findings control library ([8864b2d](https://github.com/getplumber/plumber/commit/8864b2d14d7c1b43c0565afbfe26cfb97be34e98))


### 👷 CI/CD

* **release:** pin v0.4.38 refs [skip ci] ([a5fccb7](https://github.com/getplumber/plumber/commit/a5fccb72f5f47c68d97880f39448f5d64a6ca826))

## [0.4.38](https://github.com/getplumber/plumber/compare/v0.4.37...v0.4.38) (2026-08-17)


### ✨ Features

* **ci:** restore the contract platform push, key results by policy_id, act on the gate block ([43dd0f8](https://github.com/getplumber/plumber/commit/43dd0f8ad165627350af8d4669fadb01e78c1ffc)), closes [#410](https://github.com/getplumber/plumber/issues/410)


### 👷 CI/CD

* **release:** pin v0.4.37 refs [skip ci] ([c1a149f](https://github.com/getplumber/plumber/commit/c1a149fc13a719e337d9a310ed4cca807996c03b))

## [0.4.37](https://github.com/getplumber/plumber/compare/v0.4.36...v0.4.37) (2026-08-16)


### ✨ Features

* **ci:** Add --platform feature to integrate pushing of results per policy ([d6c5d84](https://github.com/getplumber/plumber/commit/d6c5d8480737b3297721631a0c4c6e3f4dae39c4))


### 🐛 Bug Fixes

* **ci:** bump Go toolchain to 1.26.6 for stdlib security fixes ([73f5ebe](https://github.com/getplumber/plumber/commit/73f5ebe36ba21a3620b451aa9bb0d0ba0c731915))


### 👷 CI/CD

* **release:** pin v0.4.36 refs [skip ci] ([77eb302](https://github.com/getplumber/plumber/commit/77eb302508a01932990e16b31463b3f7cc5014d9))

## [0.4.36](https://github.com/getplumber/plumber/compare/v0.4.35...v0.4.36) (2026-08-10)


### 🔧 Chores

* **deps:** bump github.com/open-policy-agent/opa ([f04befa](https://github.com/getplumber/plumber/commit/f04befad7511df8ad8700b2866953a692fbd034d))


### 👷 CI/CD

* **release:** pin v0.4.35 refs [skip ci] ([3b308ff](https://github.com/getplumber/plumber/commit/3b308ffa808f70522aee42bdca07ebba40a65418))

## [0.4.35](https://github.com/getplumber/plumber/compare/v0.4.34...v0.4.35) (2026-08-08)


### 🐛 Bug Fixes

* **config:** embed the shipped default in place ([a27b4a5](https://github.com/getplumber/plumber/commit/a27b4a5c465f19603000f02d08f7abedfcfe30a9)), closes [#405](https://github.com/getplumber/plumber/issues/405)


### 👷 CI/CD

* **release:** pin v0.4.34 refs [skip ci] ([d4bf27b](https://github.com/getplumber/plumber/commit/d4bf27b3709de1b20d675309b7b02e085eba548a))

## [0.4.34](https://github.com/getplumber/plumber/compare/v0.4.33...v0.4.34) (2026-08-07)


### ✨ Features

* **identity:** expose the finding-identity recipe and make job mean a job ([e7af327](https://github.com/getplumber/plumber/commit/e7af3273786dd9f332c0474697b4fd0393fb8fe4)), closes [#403](https://github.com/getplumber/plumber/issues/403)


### 👷 CI/CD

* **release:** pin v0.4.33 refs [skip ci] ([4a0c59d](https://github.com/getplumber/plumber/commit/4a0c59d189a408924c01cdde8b87b2e0c0e64aa7))

## [0.4.33](https://github.com/getplumber/plumber/compare/v0.4.32...v0.4.33) (2026-08-07)


### 🐛 Bug Fixes

* **github:** normalize SHA case and peel nested tag objects ([fbfacde](https://github.com/getplumber/plumber/commit/fbfacdedfde62fefad673085727c7cde74f32e84))
* **github:** resolve action pins that name an annotated tag object ([4016170](https://github.com/getplumber/plumber/commit/4016170c336cc4921a83a36862a615f58e9d37a1)), closes [#401](https://github.com/getplumber/plumber/issues/401)


### ⚡ Performance

* **github:** skip the tag object probe for refs that cannot be one ([eb9c669](https://github.com/getplumber/plumber/commit/eb9c669db0123a790c81f11aedf5e1ab085c591e))


### 🔧 Chores

* drop a stray worktree entry committed by mistake ([82c947f](https://github.com/getplumber/plumber/commit/82c947f3d3ee8c81f8148f928cac548fe3cf5036))


### 📚 Documentation

* **github:** record that the fork blind spot now covers tag objects ([4eeee96](https://github.com/getplumber/plumber/commit/4eeee967332e87e3ebda2da71a30fad3983ad4e3))


### ✅ Tests

* **github:** lock the collector-to-IR metadata handoff ([ccfc59b](https://github.com/getplumber/plumber/commit/ccfc59b39ef4cffd4d866b1620b2b9d61c754c9c))
* **github:** lock the zero-cost happy path for the tag object fallback ([fae517e](https://github.com/getplumber/plumber/commit/fae517e590f5c295852b9c5977b58dec5b5a2b6a))


### 👷 CI/CD

* **release:** pin v0.4.32 refs [skip ci] ([e84e2c0](https://github.com/getplumber/plumber/commit/e84e2c078d9e34a0b995098180746d3e4d191ccc))

## [0.4.32](https://github.com/getplumber/plumber/compare/v0.4.31...v0.4.32) (2026-08-06)


### ✨ Features

* **sarif:** surface the issue code, doc link and stable alert identity in GHAS ([74691c6](https://github.com/getplumber/plumber/commit/74691c621040606428f6e074f013498df68b01fc)), closes [#372](https://github.com/getplumber/plumber/issues/372)


### 👷 CI/CD

* **release:** pin v0.4.31 refs [skip ci] ([c75127f](https://github.com/getplumber/plumber/commit/c75127f9cd1b768dad098271331e7851f517040c))

## [0.4.31](https://github.com/getplumber/plumber/compare/v0.4.30...v0.4.31) (2026-08-06)


### 🔧 Chores

* **ci:** bump the github-actions group across 1 directory with 5 updates ([c67b731](https://github.com/getplumber/plumber/commit/c67b7313b65dea89a7d108ac6a5575f3b3f7e8f5))


### 👷 CI/CD

* **release:** pin v0.4.30 refs [skip ci] ([75037fd](https://github.com/getplumber/plumber/commit/75037fd51c29c09c5f59172d0b1eb74754df7018))

## [0.4.30](https://github.com/getplumber/plumber/compare/v0.4.29...v0.4.30) (2026-08-05)


### 🐛 Bug Fixes

* **misc:** Update various stale documentation and fix incorrect array size in catalog ([98b399a](https://github.com/getplumber/plumber/commit/98b399a98485a4c4b7c2ea8dcc4e59997502507d))


### 👷 CI/CD

* **release:** pin v0.4.29 refs [skip ci] ([72d4610](https://github.com/getplumber/plumber/commit/72d461056e592082b2747a72196ea5a1266e7ac5))

## [0.4.29](https://github.com/getplumber/plumber/compare/v0.4.28...v0.4.29) (2026-08-05)


### ✨ Features

* **artifacts:** Add controlName in the outputs + add status for json output  + add csv format ([c9a08b4](https://github.com/getplumber/plumber/commit/c9a08b4c106d18790c09cdc0cc63619c755333ca))
* **artifacts:** stable per-finding fingerprint in JSON, CSV, SARIF, GLSAST ([faf7040](https://github.com/getplumber/plumber/commit/faf70406bd8b56a4063c8d0fea5ad330d7dc71f0))
* **cli:** add OCSF Compliance Finding export (--ocsf) ([9a7ef68](https://github.com/getplumber/plumber/commit/9a7ef68547acef19fd4c31a473c31ae843b690f4))


### 👷 CI/CD

* **release:** pin v0.4.28 refs [skip ci] ([0637800](https://github.com/getplumber/plumber/commit/0637800ee26dafb61ef2763d787b31210c69b645))

## [0.4.28](https://github.com/getplumber/plumber/compare/v0.4.27...v0.4.28) (2026-08-03)


### 🐛 Bug Fixes

* **github:** resolve default branch even when branchMustBeProtected is off ([3fed560](https://github.com/getplumber/plumber/commit/3fed560c051fc32706c5b7365874841883430dc7))


### 👷 CI/CD

* **release:** pin v0.4.27 refs [skip ci] ([7b8933d](https://github.com/getplumber/plumber/commit/7b8933da38fabe2dca6d2dfc5e940da2d86fdd72))

## [0.4.27](https://github.com/getplumber/plumber/compare/v0.4.26...v0.4.27) (2026-08-03)


### 🐛 Bug Fixes

* **lint:** report all issues instead of golangci-lint's truncated default ([cb5739a](https://github.com/getplumber/plumber/commit/cb5739adcaf0ff3ad69901febd1f238d1aa8ee5a))


### ♻️ Refactoring

* remove 50 dead functions unreachable from main ([a28393c](https://github.com/getplumber/plumber/commit/a28393ca6bc1e6ba9c4620a3daeaade415ff8122))


### ✅ Tests

* **config:** cover GitLab trustedUrls narrowing with includePlumberDefaults to false ([46f09ed](https://github.com/getplumber/plumber/commit/46f09ed7d79a75e7f46577fb5132ea85d37f1e82)), closes [#365](https://github.com/getplumber/plumber/issues/365)


### 👷 CI/CD

* **lint:** gate on whole-program dead code detection ([0aac54c](https://github.com/getplumber/plumber/commit/0aac54c5fe9cbf6f5f52372f81c45c78ef7becbb))
* **release:** pin v0.4.26 refs [skip ci] ([e461736](https://github.com/getplumber/plumber/commit/e461736d107dcf87c104cf776bb8e517924cd89b))

## [0.4.26](https://github.com/getplumber/plumber/compare/v0.4.25...v0.4.26) (2026-07-31)


### 🐛 Bug Fixes

* **config:** trust getplumber/* actions in the shipped default config ([771ec58](https://github.com/getplumber/plumber/commit/771ec58e9f9b6a32a4eced9e2f66eef5166a52a0))


### 👷 CI/CD

* **release:** pin v0.4.25 refs [skip ci] ([65c0c08](https://github.com/getplumber/plumber/commit/65c0c08e88246f0ebdae9f4b654f359ddedb67d6))

## [0.4.25](https://github.com/getplumber/plumber/compare/v0.4.24...v0.4.25) (2026-07-31)


### ✨ Features

* **config:** layered .plumber.yaml configuration ([17d3fdb](https://github.com/getplumber/plumber/commit/17d3fdb55db4e305ad5de900a614a598c4a27193)), closes [#375](https://github.com/getplumber/plumber/issues/375)
* **defaultconfig:** curate the shipped default and source `config init` from it ([aebf2d1](https://github.com/getplumber/plumber/commit/aebf2d1d5d1160e2ea58eabf42419261e127a26c)), closes [#1](https://github.com/getplumber/plumber/issues/1)


### 🐛 Bug Fixes

* **control:** avoid allocation-size-overflow pattern flagged by CodeQL ([c6bca30](https://github.com/getplumber/plumber/commit/c6bca306a6938f9c4bbea4a06dfa76197afba838))


### 🔧 Chores

* **defaultconfig:** simplify the embedded-default build pipeline ([f55c7de](https://github.com/getplumber/plumber/commit/f55c7debec78b391a4d7f830d786e4ebe0077f1e))


### ✅ Tests

* adapt self-scan parity/gating tests to the GitHub-only self-scan config ([9c53bc2](https://github.com/getplumber/plumber/commit/9c53bc2a25971c4b581205664291be8b4956b47a))


### 👷 CI/CD

* **release:** pin v0.4.24 refs [skip ci] ([c90df59](https://github.com/getplumber/plumber/commit/c90df592871aa02473b288381e20ee59bdf002f3))

## [0.4.24](https://github.com/getplumber/plumber/compare/v0.4.23...v0.4.24) (2026-07-31)


### 🔧 Chores

* **readme:** smooth token-free scan wording ([8bc4c80](https://github.com/getplumber/plumber/commit/8bc4c807d1ed418599a1c466a32c0ae2d210b00a))


### 📚 Documentation

* **readme:** tidy config comment and auth wording ([b1e4ff7](https://github.com/getplumber/plumber/commit/b1e4ff7dc9245513a91dba8a1a20bba114902d09))


### 👷 CI/CD

* **release:** pin v0.4.23 refs [skip ci] ([cf6b908](https://github.com/getplumber/plumber/commit/cf6b908389f5a6b2719866a4dbedcd2b864644a8))

## [0.4.23](https://github.com/getplumber/plumber/compare/v0.4.22...v0.4.23) (2026-07-30)


### ✨ Features

* **gitlab:** allow an embedding host to inject a shared HTTP client ([2579221](https://github.com/getplumber/plumber/commit/2579221ef7f4ea771aaa8d1968d92d82b179688f))


### ✅ Tests

* **gitlab:** integration — a real Fetch collects through the injected client ([84e18ee](https://github.com/getplumber/plumber/commit/84e18eed4fdbd913554b1294f2ded84f10450329))


### 👷 CI/CD

* **release:** pin v0.4.22 refs [skip ci] ([3851e87](https://github.com/getplumber/plumber/commit/3851e87e25f45997c8cb646895e821958c56e57e))

## [0.4.22](https://github.com/getplumber/plumber/compare/v0.4.21...v0.4.22) (2026-07-29)


### 🔧 Chores

* **ci:** bump the github-actions group with 9 updates ([2b22f47](https://github.com/getplumber/plumber/commit/2b22f4784c17d02215b7ed31c7ae586241a03755))


### 👷 CI/CD

* **release:** pin v0.4.21 refs [skip ci] ([21941df](https://github.com/getplumber/plumber/commit/21941df6be4ddeb5eb6f6e156ded3e8faebf272e))

## [0.4.21](https://github.com/getplumber/plumber/compare/v0.4.20...v0.4.21) (2026-07-29)


### 🐛 Bug Fixes

* **ci:** Merge dependabot same type ([2d42c8c](https://github.com/getplumber/plumber/commit/2d42c8c114ca20860e55128a7816d4c9689256f4))


### 👷 CI/CD

* **release:** pin v0.4.20 refs [skip ci] ([0fe1eef](https://github.com/getplumber/plumber/commit/0fe1eef31011169b4086487a74b8134ad020cba4))

## [0.4.20](https://github.com/getplumber/plumber/compare/v0.4.19...v0.4.20) (2026-07-29)


### 🐛 Bug Fixes

* **ci:** Component version not getting autoamtically bumped. Remove extra text from PR. change default pr names ([5b8e3ef](https://github.com/getplumber/plumber/commit/5b8e3efaf75a2090007c035f25e2a67100db984d))


### 👷 CI/CD

* **release:** pin v0.4.19 refs [skip ci] ([9da670e](https://github.com/getplumber/plumber/commit/9da670ee9fe9a3ac2be203cd7d8d4fc101f26c11))

## [0.4.19](https://github.com/getplumber/plumber/compare/v0.4.18...v0.4.19) (2026-07-29)


### 🐛 Bug Fixes

* **ci:** PR body when writing to website ([5ee0d15](https://github.com/getplumber/plumber/commit/5ee0d15b4d299a746961a5d4b1f51c6cf920b89d))


### 👷 CI/CD

* **release:** pin v0.4.18 refs [skip ci] ([e91e449](https://github.com/getplumber/plumber/commit/e91e4492b1386e1030dff831ddfbc861e63687ad))

## [0.4.18](https://github.com/getplumber/plumber/compare/v0.4.17...v0.4.18) (2026-07-29)


### ✨ Features

* **ci:** Automate component and documentation upgrade ([a0fea4a](https://github.com/getplumber/plumber/commit/a0fea4a57389236bcd14b4a7bce2f4fe2eee3708))


### 👷 CI/CD

* **release:** pin v0.4.17 refs [skip ci] ([6371abc](https://github.com/getplumber/plumber/commit/6371abc35796f8809bce3188309e7c896217d1e0))

## [0.4.17](https://github.com/getplumber/plumber/compare/v0.4.16...v0.4.17) (2026-07-29)


### 🐛 Bug Fixes

* **conf:** restore gitlab controls in self-scan .plumber.yaml ([34a4cbf](https://github.com/getplumber/plumber/commit/34a4cbf8dd84a49b1282b7e2dbb3f56f2c53ad27))


### 👷 CI/CD

* **release:** pin v0.4.16 refs [skip ci] ([cbb9172](https://github.com/getplumber/plumber/commit/cbb9172b5d8ad6de6002c1e8dfee749c9f90e970))

## [0.4.16](https://github.com/getplumber/plumber/compare/v0.4.15...v0.4.16) (2026-07-24)


### ✨ Features

* **output:** restructure control output into clear Passed/Skipped/Failed sections ([78b576f](https://github.com/getplumber/plumber/commit/78b576f8451f2af02381f4f1c7efbdca559682fb))


### 👷 CI/CD

* **release:** pin v0.4.15 refs [skip ci] ([5ad6b54](https://github.com/getplumber/plumber/commit/5ad6b5472460107be9975c155930f86bbc2adbd3))

## [0.4.15](https://github.com/getplumber/plumber/compare/v0.4.14...v0.4.15) (2026-07-24)


### 🐛 Bug Fixes

* **controls:** don't score GitHub-only controls on GitLab runs — gate findings by provider applicability so plumberScore.counts matches the rendered controls ([#349](https://github.com/getplumber/plumber/issues/349)) ([6cc38ec](https://github.com/getplumber/plumber/commit/6cc38ecc7d179f7d3588dd9aa72d5f53751300a8))


### 📚 Documentation

* **template:** Update comment in template and add version reference section in contributing ([5a6ec4e](https://github.com/getplumber/plumber/commit/5a6ec4e9a0de87361a6fdfd7abb243e1e3b23a50))


### 👷 CI/CD

* **release:** pin v0.4.14 refs [skip ci] ([f85f762](https://github.com/getplumber/plumber/commit/f85f762b466720b949c5da9d13274ee0e5beb4fe))

## [0.4.14](https://github.com/getplumber/plumber/compare/v0.4.13...v0.4.14) (2026-07-24)


### 🐛 Bug Fixes

* **ci:** Fix vuln and update grype ref ([6607bb8](https://github.com/getplumber/plumber/commit/6607bb863630b098daf8feda0c17a030efb5c309))


### 👷 CI/CD

* **release:** pin v0.4.13 refs [skip ci] ([8472496](https://github.com/getplumber/plumber/commit/8472496e62395bc130896b5e8a17d302539b0730))

## [0.4.13](https://github.com/getplumber/plumber/compare/v0.4.12...v0.4.13) (2026-07-24)


### ✨ Features

* **cli:** fall back to the built-in default config when no .plumber.yaml is found instead of failing, so scans work with zero setup. Remove the redundant config baked into the Docker image and drop the stale 'global config' wording ([#326](https://github.com/getplumber/plumber/issues/326)). ([9a1ea62](https://github.com/getplumber/plumber/commit/9a1ea62a70fc3314e26f0bd40a4b8365125c93e8))


### 👷 CI/CD

* **release:** pin v0.4.12 refs [skip ci] ([9da2169](https://github.com/getplumber/plumber/commit/9da2169c9fbc082c36158fe6769d7a9cf2750f2b))

## [0.4.12](https://github.com/getplumber/plumber/compare/v0.4.11...v0.4.12) (2026-07-20)


### 🐛 Bug Fixes

* **cli:** clearer, less noisy terminal output for analyze ([f33fe10](https://github.com/getplumber/plumber/commit/f33fe10649fdfac19ace44aa51ce0cbc80c3098f))


### 👷 CI/CD

* **release:** pin v0.4.11 refs [skip ci] ([a24f952](https://github.com/getplumber/plumber/commit/a24f9528fc5b0c70573bcfd114d8b55b59282cd0))

## [0.4.11](https://github.com/getplumber/plumber/compare/v0.4.10...v0.4.11) (2026-07-20)


### ✨ Features

* **controls:** actionsMustNotExecuteMutableRemoteCode (ISSUE-714/715/716) ([4357428](https://github.com/getplumber/plumber/commit/43574281418d8599a849659a6d5469aff9df904b)), closes [#295](https://github.com/getplumber/plumber/issues/295)
* **github:** detect mutable exec in Docker-image actions ([18be485](https://github.com/getplumber/plumber/commit/18be485a140dd10b26c1400c6639b154f2d9b7cd))


### 🐛 Bug Fixes

* **control:** emit actionsMustNotExecuteMutableRemoteCode findings in JSON output ([ceb92e4](https://github.com/getplumber/plumber/commit/ceb92e4b5b531bdc6e5b9d602ba8339f91ebaeee))
* **github:** cut false positives in actionsMustNotExecuteMutableRemoteCode and gate its source fetch on the control being enabled ([#299](https://github.com/getplumber/plumber/issues/299)) ([46ed6c5](https://github.com/getplumber/plumber/commit/46ed6c50fb114dd71f077a508a29f4edad0c8c5b))


### 👷 CI/CD

* **release:** pin v0.4.10 refs [skip ci] ([a7e5614](https://github.com/getplumber/plumber/commit/a7e5614cf3e22c337d32797d1d9584a6a401cb2a))

## [0.4.10](https://github.com/getplumber/plumber/compare/v0.4.9...v0.4.10) (2026-07-20)


### 🐛 Bug Fixes

* **cli:** render the progress bar only on a TTY, clarify --print vs --verbose semantics, drop dead LogLevel ([#309](https://github.com/getplumber/plumber/issues/309)) ([7fbc954](https://github.com/getplumber/plumber/commit/7fbc9541716eba7fa8b4457052ec724c5d94a1e0))


### 👷 CI/CD

* **release:** pin v0.4.9 refs [skip ci] ([4352de9](https://github.com/getplumber/plumber/commit/4352de9147ff008b56ae37f601d362be1e255ee8))

## [0.4.9](https://github.com/getplumber/plumber/compare/v0.4.8...v0.4.9) (2026-07-20)


### ✨ Features

* **controls:** Rename jobName to job. Add uses and ref to the output, highlighting offending lines better ([70b3c24](https://github.com/getplumber/plumber/commit/70b3c24c2a6a2ff3f7357d371066d77c49e1d8d0))


### 👷 CI/CD

* **release:** pin v0.4.8 refs [skip ci] ([cca202e](https://github.com/getplumber/plumber/commit/cca202e5bcaac15f576e77390aa9cfda8b878d27))

## [0.4.8](https://github.com/getplumber/plumber/compare/v0.4.7...v0.4.8) (2026-07-16)


### 🔧 Chores

* **ci:** bump actions/setup-node from 6.4.0 to 7.0.0 ([97ddc98](https://github.com/getplumber/plumber/commit/97ddc985aea3d4df10684d102fe420a65ec6c811))


### 👷 CI/CD

* **release:** pin v0.4.7 refs [skip ci] ([0d2e256](https://github.com/getplumber/plumber/commit/0d2e2565c73e0ea0ec223eef61b07f371d9bfdf3))

## [0.4.7](https://github.com/getplumber/plumber/compare/v0.4.6...v0.4.7) (2026-07-16)


### 🔧 Chores

* **ci:** bump docker/metadata-action from 6.1.0 to 6.2.0 ([dfaef4f](https://github.com/getplumber/plumber/commit/dfaef4f3d6875a84d4f5e42ba6c7f5e62c394f57))


### 👷 CI/CD

* **release:** pin v0.4.6 refs [skip ci] ([89d5b1d](https://github.com/getplumber/plumber/commit/89d5b1daab297cd72e370b38e23dcef0bd708754))

## [0.4.6](https://github.com/getplumber/plumber/compare/v0.4.5...v0.4.6) (2026-07-16)


### 🔧 Chores

* **ci:** bump github/codeql-action/autobuild from 4.36.2 to 4.37.0 ([ba7655e](https://github.com/getplumber/plumber/commit/ba7655e999c794f77c219a251213a07e6aec3c69))
* **ci:** bump github/codeql-action/init from 4.36.2 to 4.37.0 and bump github/codeql-action/analyze from 4.36.2 to 4.37.0 ([4c18e43](https://github.com/getplumber/plumber/commit/4c18e43380848976576a6dc4aab075acf2e1fa77))


### 👷 CI/CD

* **release:** pin v0.4.5 refs [skip ci] ([4100ab7](https://github.com/getplumber/plumber/commit/4100ab787380b16237b62ac794b5faf357e3b656))

## [0.4.5](https://github.com/getplumber/plumber/compare/v0.4.4...v0.4.5) (2026-07-16)


### 🔧 Chores

* **deps:** bump golang.org/x/term from 0.44.0 to 0.45.0 ([81627ba](https://github.com/getplumber/plumber/commit/81627ba4f58b6d8fb8e2145e07f65e377ed74ff8))


### 👷 CI/CD

* **release:** pin v0.4.4 refs [skip ci] ([aafbcee](https://github.com/getplumber/plumber/commit/aafbceed9f01d77beabd6e910dadccae7a64ece1))

## [0.4.4](https://github.com/getplumber/plumber/compare/v0.4.3...v0.4.4) (2026-07-16)


### 🔧 Chores

* **cleanup:** Remove gitleaks fully ([a2ad6fb](https://github.com/getplumber/plumber/commit/a2ad6fb31a299c7ef102840a721f0dd45b1b36c4))


### 📚 Documentation

* **template:** Update commented version in template ([dace2c4](https://github.com/getplumber/plumber/commit/dace2c4e72445925e70764dd53c5632d301f41cb))


### 👷 CI/CD

* **release:** pin v0.4.3 refs [skip ci] ([3e7d693](https://github.com/getplumber/plumber/commit/3e7d6933189432f9a2ebcc2f6ba813bef7916179))

## [0.4.3](https://github.com/getplumber/plumber/compare/v0.4.2...v0.4.3) (2026-07-14)


### 🔧 Chores

* use issue types instead of labels/title prefixes in bug_report.md ([989ff04](https://github.com/getplumber/plumber/commit/989ff0413d6ca786592fb4d0272dffeaa98a6089))
* use issue types instead of labels/title prefixes in feature_request.md ([488592f](https://github.com/getplumber/plumber/commit/488592f0625d6b0cbebe30103d7308f338b5ed53))


### 👷 CI/CD

* **release:** pin v0.4.2 refs [skip ci] ([2276ce6](https://github.com/getplumber/plumber/commit/2276ce66e45b5abfcca13a22fa971efff518d322))

## [0.4.2](https://github.com/getplumber/plumber/compare/v0.4.1...v0.4.2) (2026-07-10)


### 🐛 Bug Fixes

* **gate:** restore the pre-0.4.0 pass for GitHub repositories without (usable) workflows ([f22f5ef](https://github.com/getplumber/plumber/commit/f22f5efbf3115db3af0c17ec00f7329e936fd803))


### 👷 CI/CD

* **release:** pin v0.4.1 refs [skip ci] ([b885b8b](https://github.com/getplumber/plumber/commit/b885b8b7848ec3050932b658e06c368b79825287))

## [0.4.1](https://github.com/getplumber/plumber/compare/v0.4.0...v0.4.1) (2026-07-10)


### ✨ Features

* **control:** Add control actionRefsMustExistUpstream that emits issue 707 ([b9817e3](https://github.com/getplumber/plumber/commit/b9817e3a9d5a907ae70c089bc75bc74a00afaf3e))


### 👷 CI/CD

* **release:** pin v0.4.0 refs [skip ci] ([ddcfee6](https://github.com/getplumber/plumber/commit/ddcfee676cb4ed67dc920460259b79ea0e4bd732))

## [0.4.0](https://github.com/getplumber/plumber/compare/v0.3.101...v0.4.0) (2026-07-10)


### ⚠ BREAKING CHANGES

* **gate:** the JSON report and the GitHub Action no longer expose
'compliance'; 'passed' is redefined as 'score gate met'; the default
artifact name changed to plumber-report. Runs with nothing scoreable
now fail closed (exit 1): on GitHub, a repository with no workflows
previously passed the compliance gate and now fails, and a
configuration that enables zero controls for the scanned provider (or
a skip-all filter) also fails instead of passing with a perfect
score. Skip Plumber or use soft-fail on repos that intentionally have
no CI.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>

### ✨ Features

* **gate:** gate runs on the Plumber Score, drop the compliance percentage ([2bd2639](https://github.com/getplumber/plumber/commit/2bd26393123ebe29f2d6c04c4acbc5f54c055413)), closes [#320](https://github.com/getplumber/plumber/issues/320) [#320](https://github.com/getplumber/plumber/issues/320)


### 👷 CI/CD

* **claude:** use claude-opus-4-8 for PR review checks ([0c65684](https://github.com/getplumber/plumber/commit/0c65684441d67fcc9fe10ba07b4f4a25c73e9f48))
* **release:** pin v0.3.101 refs [skip ci] ([e209f31](https://github.com/getplumber/plumber/commit/e209f31449268f99df14022cc39a0e20b5768d6c))

## [0.3.101](https://github.com/getplumber/plumber/compare/v0.3.100...v0.3.101) (2026-07-10)


### ✨ Features

* **control:** Add control to check for cache poisoning releaseWorkflowsMustNotRestoreUntrustedCache ([2272c47](https://github.com/getplumber/plumber/commit/2272c47479e1cd53e0c684e2804d4f07cceb0f9d))


### 🐛 Bug Fixes

* **control:** close review FP/FN gaps in cache-poisoning control ([6b3a01b](https://github.com/getplumber/plumber/commit/6b3a01b1bce0de1bc26c995b921ec64aa5f495ef))
* **control:** Fix init to contain more default values ([3b37256](https://github.com/getplumber/plumber/commit/3b37256855fb15fb1c13abaf34f16e1bce4e9c81))


### 👷 CI/CD

* **release:** pin v0.3.100 refs [skip ci] ([3baf582](https://github.com/getplumber/plumber/commit/3baf582fea1f3240979cacfc03435410006c847a))

## [0.3.100](https://github.com/getplumber/plumber/compare/v0.3.99...v0.3.100) (2026-07-09)


### 🐛 Bug Fixes

* **docker:** build with Go 1.26.5 to clear GO-2026-4970 (Container Scan) ([7d7921d](https://github.com/getplumber/plumber/commit/7d7921d79f195eef8c0eb39360977f0783956850))


### 👷 CI/CD

* add advisory Claude PR review automation ([3d2dca6](https://github.com/getplumber/plumber/commit/3d2dca6b45445ec7f9b93806203c3d919f1e9bd4))
* **claude:** close review-agent secret-exfil surface + dedup/reliability ([e0d4057](https://github.com/getplumber/plumber/commit/e0d40577752eb1e1ddcd59c2f4fe91239021d4de))
* **claude:** extract poster logic to a unit-tested module ([ad39721](https://github.com/getplumber/plumber/commit/ad39721b8c87cdf4cc945ca6a9d1d05a0bf14e84))
* **claude:** fix dedup/redaction/sandbox issues from self-review ([26ae307](https://github.com/getplumber/plumber/commit/26ae3074c503261c1370fca8ae4eb496bbd5b537))
* **claude:** fix fingerprint/sanitize/parse bugs + add a relevance bar ([c370371](https://github.com/getplumber/plumber/commit/c3703715fdfbacaa83917418f177c4bc963b7b4b))
* **claude:** fix stateful posting bugs from cursor review ([897d3d1](https://github.com/getplumber/plumber/commit/897d3d11357e552702fb64271758bf025578ade2))
* **claude:** harden dedup fence, unanchored-on-failure, multi-line summary ([7748dd9](https://github.com/getplumber/plumber/commit/7748dd9ae40ee73536cf189a623c245d182c7628))
* **claude:** post each finding as a resolvable review comment ([5f6c56b](https://github.com/getplumber/plumber/commit/5f6c56b6f8c286e9b2eab0ce2f59e1a84f0652c0))
* **claude:** prompt for whole-system, cross-run review ([c079b1a](https://github.com/getplumber/plumber/commit/c079b1ada13e2594eedff96e11894c27992d2595))
* **claude:** semantic dedup of reworded findings via Haiku ([f23ee28](https://github.com/getplumber/plumber/commit/f23ee28a2c14371995b4af479d430f19a35f6e41))
* **claude:** stop the review from reviewing its own machinery ([ab52069](https://github.com/getplumber/plumber/commit/ab520695521f454e07d6a3dedbaa2db8e2be6598))
* **claude:** strip planted markers from untrusted finding text ([5a3d334](https://github.com/getplumber/plumber/commit/5a3d334398c855fcfb7044f0649c8bfc392a3614))
* **claude:** use Sonnet for semantic dedup to cut duplicate comments ([902f900](https://github.com/getplumber/plumber/commit/902f900f1602980f7bfce0a9d9fc3e8d34d235a8))
* fix scripts-test to pass the test file explicitly ([ffd7b4c](https://github.com/getplumber/plumber/commit/ffd7b4c4ae2794d7f39ab9c6bc58b1ea66718abe))
* **release:** pin v0.3.99 refs [skip ci] ([8f851d5](https://github.com/getplumber/plumber/commit/8f851d55f1c95afd107da5c521be00d9a63eab52))

## [0.3.99](https://github.com/getplumber/plumber/compare/v0.3.98...v0.3.99) (2026-07-08)


### 🐛 Bug Fixes

* **control:** Update control rendered display name for workflowMustNotExportEntireSecretsContext ([253822e](https://github.com/getplumber/plumber/commit/253822e4ce81b91f5ef1715cdca17d3153c009d0))


### 👷 CI/CD

* **release:** pin v0.3.98 refs [skip ci] ([adbdb12](https://github.com/getplumber/plumber/commit/adbdb12b03c95cf8faddf3ec44e44cdd2af86765))

## [0.3.98](https://github.com/getplumber/plumber/compare/v0.3.97...v0.3.98) (2026-07-08)


### 🐛 Bug Fixes

* **build:** bump Go toolchain to 1.26.5 / 1.25.12 for GO-2026-5856 ([868b45e](https://github.com/getplumber/plumber/commit/868b45ebe51cf48ddf4c1feb9e96d3d030bb9e10))


### 👷 CI/CD

* **release:** pin v0.3.97 refs [skip ci] ([3f0c5d9](https://github.com/getplumber/plumber/commit/3f0c5d900738857d02d9adbdebd5a396ffb85fb4))

## [0.3.97](https://github.com/getplumber/plumber/compare/v0.3.96...v0.3.97) (2026-07-08)


### 🔧 Chores

* **ci:** bump docker/login-action from 4.2.0 to 4.4.0 ([ae7e389](https://github.com/getplumber/plumber/commit/ae7e38900ec45d6fb6ad43b1ce9732f4d5932839))


### 👷 CI/CD

* **release:** pin v0.3.96 refs [skip ci] ([71c411f](https://github.com/getplumber/plumber/commit/71c411f1b351f3e169578faa87e12e90c2a3917a))

## [0.3.96](https://github.com/getplumber/plumber/compare/v0.3.95...v0.3.96) (2026-07-08)


### 🔧 Chores

* **ci:** bump docker/setup-buildx-action from 4.1.0 to 4.2.0 ([1a91876](https://github.com/getplumber/plumber/commit/1a918760d64f9780246d4358b39fddc73560dba1))


### 👷 CI/CD

* **release:** pin v0.3.94 refs [skip ci] ([b682530](https://github.com/getplumber/plumber/commit/b6825301279e905030af84bb25a6c8b63ff4dcbb))
* **release:** pin v0.3.95 refs [skip ci] ([f521eaf](https://github.com/getplumber/plumber/commit/f521eaf69aea4657be89031407e45813f7a92c55))

## [0.3.95](https://github.com/getplumber/plumber/compare/v0.3.94...v0.3.95) (2026-07-08)


### 🔧 Chores

* **ci:** bump docker/build-push-action from 7.2.0 to 7.3.0 ([b5a767b](https://github.com/getplumber/plumber/commit/b5a767b0eefbfcef41b1cb231195a997480045fa))


### 👷 CI/CD

* **release:** pin v0.3.93 refs [skip ci] ([9344075](https://github.com/getplumber/plumber/commit/93440757b463896e276b3c19a930fa9720e5cb8b))

## [0.3.94](https://github.com/getplumber/plumber/compare/v0.3.93...v0.3.94) (2026-07-08)


### 🔧 Chores

* **ci:** bump docker/setup-qemu-action from 4.1.0 to 4.2.0 ([c733df7](https://github.com/getplumber/plumber/commit/c733df7096f009bd5b3047ac951e55a222e3b103))

## [0.3.93](https://github.com/getplumber/plumber/compare/v0.3.92...v0.3.93) (2026-07-08)


### 🔧 Chores

* **deps:** bump github.com/schollz/progressbar/v3 ([93df998](https://github.com/getplumber/plumber/commit/93df99856ae537e1f802b65f6c903203f322d1ca))


### 👷 CI/CD

* **release:** pin v0.3.91 refs [skip ci] ([d562715](https://github.com/getplumber/plumber/commit/d562715497640eaf6332b7d6fb15e91140999b98))
* **release:** pin v0.3.92 refs [skip ci] ([2c39b14](https://github.com/getplumber/plumber/commit/2c39b140460ee42978dec9dd6f7b79800a6079ca))

## [0.3.92](https://github.com/getplumber/plumber/compare/v0.3.91...v0.3.92) (2026-07-08)


### 🔧 Chores

* **ci:** bump github/codeql-action/upload-sarif from 4.36.2 to 4.37.0 ([f2b3e2e](https://github.com/getplumber/plumber/commit/f2b3e2e32fe5d445e2c2fb46ee4c63fe989f109a))

## [0.3.91](https://github.com/getplumber/plumber/compare/v0.3.90...v0.3.91) (2026-07-08)


### 🔧 Chores

* **deps:** bump github.com/open-policy-agent/opa from 1.18.1 to 1.18.2 ([edd7d9a](https://github.com/getplumber/plumber/commit/edd7d9a3396fbfefb0230f84c7a44a6bf00aaf4e))


### 👷 CI/CD

* **release:** pin v0.3.90 refs [skip ci] ([fd41b0e](https://github.com/getplumber/plumber/commit/fd41b0e67d33d2f6557d09d7d089843b0a894775))

## [0.3.90](https://github.com/getplumber/plumber/compare/v0.3.89...v0.3.90) (2026-07-08)


### ✨ Features

* **control:** Ship control 186 workflowMustNotExportEntireSecretsContext ([25881bf](https://github.com/getplumber/plumber/commit/25881bfd844c286244a16cd294ddcd3add85ca6f))


### 👷 CI/CD

* **release:** pin v0.3.89 refs [skip ci] ([cd7a8d3](https://github.com/getplumber/plumber/commit/cd7a8d3138e3d15713cdbcb908d97112f93d95fc))

## [0.3.89](https://github.com/getplumber/plumber/compare/v0.3.88...v0.3.89) (2026-07-07)


### 🐛 Bug Fixes

* **config:** warn when a present local CI config is unreadable ([a099337](https://github.com/getplumber/plumber/commit/a099337ba6230632b9b8975c7d1980d9accbed5f))
* **github:** keep scanning repo artifacts when the workflows dir is rejected ([2a0fcb1](https://github.com/getplumber/plumber/commit/2a0fcb18d70c8190e21f6eb1f341b8e818fdbebf))


### 🔧 Chores

* **config:** bound configuration and CI-config file reads ([aff1f01](https://github.com/getplumber/plumber/commit/aff1f018c1923e08f62c205add7b05a853aa2578))
* **github:** harden workflow and dependabot file collection ([7ccfa4c](https://github.com/getplumber/plumber/commit/7ccfa4ce46672ee3fab3e45fcacf8ebda91b321a))
* **mrcomment:** harden comment text escaping ([52b1985](https://github.com/getplumber/plumber/commit/52b19853c740d635a9c8478c1dbc35280ea91a9b))
* **render:** harden degraded-reason and CI-error output ([2d785b8](https://github.com/getplumber/plumber/commit/2d785b8450178f659fafa139c7f02ca090e2e519))
* **render:** harden verification-warning output ([8179ff6](https://github.com/getplumber/plumber/commit/8179ff61cdb09ac5ce3c6aeeb311e15f3debbdc5))


### 👷 CI/CD

* **release:** pin v0.3.88 refs [skip ci] ([beb8d19](https://github.com/getplumber/plumber/commit/beb8d19655162ae1336eaa176c55f316b87cd2ce))

## [0.3.88](https://github.com/getplumber/plumber/compare/v0.3.87...v0.3.88) (2026-07-06)


### 🐛 Bug Fixes

* **ci:** Fix typo in ci to always rebuild runtime allowing update to layers. Necessary for security updates ([99d9e61](https://github.com/getplumber/plumber/commit/99d9e615fbc91a00bc82f1aeb27f2e3bc73f7e98))


### 👷 CI/CD

* **release:** pin v0.3.87 refs [skip ci] ([4dd1ec3](https://github.com/getplumber/plumber/commit/4dd1ec3e1bd8c3218894f9e311f2b371c30d2b80))

## [0.3.87](https://github.com/getplumber/plumber/compare/v0.3.86...v0.3.87) (2026-07-06)


### 🐛 Bug Fixes

* **collect:** contain local CI-config reads and skip symlinked Dockerfiles ([ef9c275](https://github.com/getplumber/plumber/commit/ef9c2751f9853831e8b208e6cf9e2df1fc7d076f))
* **gitlab:** harden local include resolution ([729e259](https://github.com/getplumber/plumber/commit/729e25937f01a417444b7d00f946bfa046c2d6e1))


### ♻️ Refactoring

* **render:** sanitize repo-derived text and bound resource use ([17ed05e](https://github.com/getplumber/plumber/commit/17ed05eaaca3efc00c6b7092794d1303b4c527c4))
* **score:** resolve the score endpoint from CLI/env only ([0a89351](https://github.com/getplumber/plumber/commit/0a89351c4098d2b2dd639281c7bd5d25810447c2))


### 👷 CI/CD

* **grype:** install pinned grype by checksum, drop scan-action ([a275cdf](https://github.com/getplumber/plumber/commit/a275cdff60a9abe189b5833dbdafbec7ef19124e)), closes [#294](https://github.com/getplumber/plumber/issues/294)
* pin runtime tool installs to immutable versions ([a203b7f](https://github.com/getplumber/plumber/commit/a203b7f1fbd3e2ac4aeaf55c4425cd215a138c1a))
* **release:** pin v0.3.86 refs [skip ci] ([101cd21](https://github.com/getplumber/plumber/commit/101cd2168b4eb5bc5d2944b57f28394f8d536a84))
* **release:** stop persisting credentials in the pin-refs checkout ([8f0f261](https://github.com/getplumber/plumber/commit/8f0f2619b9d725666209c2b42601d8d7ba871fa7)), closes [#293](https://github.com/getplumber/plumber/issues/293)
* **scorecard:** document the action's mutable-image gap ([61c8cdd](https://github.com/getplumber/plumber/commit/61c8cdd59edb8919d1d8ada375c6e21c4e598a59))

## [0.3.86](https://github.com/getplumber/plumber/compare/v0.3.85...v0.3.86) (2026-07-02)


### 🐛 Bug Fixes

* **gitleaks:** disable secret scanning ([e41475e](https://github.com/getplumber/plumber/commit/e41475ec20b10ff7e48dfc3010d5877d97a3dc3e))


### 👷 CI/CD

* **release:** pin v0.3.85 refs [skip ci] ([12df9db](https://github.com/getplumber/plumber/commit/12df9dba94f64e97763943d6583484f0a3a39115))

## [0.3.85](https://github.com/getplumber/plumber/compare/v0.3.84...v0.3.85) (2026-07-02)


### ✨ Features

* **control:** [#185](https://github.com/getplumber/plumber/issues/185) Add Control workflowMustNotWriteUntrustedContentToGitHubEnv ISSUE-207 ([8829586](https://github.com/getplumber/plumber/commit/88295861bde0d1efed6686c63806f35875abc558))


### 🐛 Bug Fixes

* **control:** Cover more of the attack surface ([bcd1076](https://github.com/getplumber/plumber/commit/bcd10767283156242872b043ff20a697a345e7c5))
* **readme:** Documentation about issue-209 ([a0e3e65](https://github.com/getplumber/plumber/commit/a0e3e65899f126f5fa982d93dcff06c3baf1c74a))


### 👷 CI/CD

* **release:** pin v0.3.84 refs [skip ci] ([0b7107f](https://github.com/getplumber/plumber/commit/0b7107f1c598a92c420748b7bc5b4c5df7baaaae))

## [0.3.84](https://github.com/getplumber/plumber/compare/v0.3.83...v0.3.84) (2026-07-02)


### 🐛 Bug Fixes

* **control:** Fix false positive hardcoded job ([15e484c](https://github.com/getplumber/plumber/commit/15e484cbaa3719a3f087082fcd96496ea5743fba))


### 👷 CI/CD

* **release:** pin v0.3.83 refs [skip ci] ([9945938](https://github.com/getplumber/plumber/commit/99459381ea8a9c1e0a0fc7fcbe1e0fb3d48d9bfc))

## [0.3.83](https://github.com/getplumber/plumber/compare/v0.3.82...v0.3.83) (2026-07-01)


### 🔧 Chores

* **ci:** bump actions/attest-build-provenance from 4.1.0 to 4.1.1 ([8e6b863](https://github.com/getplumber/plumber/commit/8e6b863ba3b9b0c6b9367cbee9452815f719af90))


### 👷 CI/CD

* **release:** pin v0.3.82 refs [skip ci] ([4f57fd7](https://github.com/getplumber/plumber/commit/4f57fd70b31a69f065cb5fdcbd099f2412700525))

## [0.3.82](https://github.com/getplumber/plumber/compare/v0.3.81...v0.3.82) (2026-07-01)


### 🔧 Chores

* **ci:** bump actions/setup-go from 6.4.0 to 6.5.0 ([e8fe5cf](https://github.com/getplumber/plumber/commit/e8fe5cfeb9713f817bdddf38851bc72400e13617))


### 👷 CI/CD

* **release:** pin v0.3.81 refs [skip ci] ([471ca8a](https://github.com/getplumber/plumber/commit/471ca8a1aaf6855203abf92bfb0b27dd7a3e12d2))

## [0.3.81](https://github.com/getplumber/plumber/compare/v0.3.80...v0.3.81) (2026-07-01)


### 🔧 Chores

* **deps:** bump github.com/open-policy-agent/opa from 1.17.1 to 1.18.1 ([1784446](https://github.com/getplumber/plumber/commit/17844467720cd8049a826aa031ba533a1a3af58b))


### 👷 CI/CD

* **release:** pin v0.3.80 refs [skip ci] ([f73828f](https://github.com/getplumber/plumber/commit/f73828fa3649871af0f14f2cae53aa17c581d702))

## [0.3.80](https://github.com/getplumber/plumber/compare/v0.3.79...v0.3.80) (2026-07-01)


### ✨ Features

* **config:** trust getplumber/plumber action in default authorized sources ([f883131](https://github.com/getplumber/plumber/commit/f88313181a0215b3a6bd0630ccf0dc6e5df5d671))


### 👷 CI/CD

* **release:** pin v0.3.79 refs [skip ci] ([42ed1c5](https://github.com/getplumber/plumber/commit/42ed1c5bf24a7b2e0859bdf30aeab89a5ab2e91f))

## [0.3.79](https://github.com/getplumber/plumber/compare/v0.3.78...v0.3.79) (2026-06-29)


### 🔧 Chores

* **action:** revert GitHub Action name to "Plumber Score" ([7c4ce7e](https://github.com/getplumber/plumber/commit/7c4ce7eba58c5b30203892700247d2f4fb1de9b9))


### 👷 CI/CD

* **release:** pin v0.3.78 refs [skip ci] ([ae540c6](https://github.com/getplumber/plumber/commit/ae540c6651b469f8f409c009f1b4ab7cf6939e93))

## [0.3.78](https://github.com/getplumber/plumber/compare/v0.3.77...v0.3.78) (2026-06-29)


### 🔧 Chores

* **action:** rename GitHub Action to "Plumber Security" ([044b9c6](https://github.com/getplumber/plumber/commit/044b9c641cdc9512081cfa1644b11fa93314b367))


### 👷 CI/CD

* **release:** pin v0.3.77 refs [skip ci] ([60f574c](https://github.com/getplumber/plumber/commit/60f574c11b70dce9670548a8cf0f4ef7b5a6572b))

## [0.3.77](https://github.com/getplumber/plumber/compare/v0.3.76...v0.3.77) (2026-06-29)


### 🔧 Chores

* **action:** rename GitHub Action to "Plumber" ([1f315d6](https://github.com/getplumber/plumber/commit/1f315d634be146e0efeaf0496b2533c5cf60ad37))


### 📚 Documentation

* **readme:** update doc links for getplumber.io docs restructuring ([bb11d13](https://github.com/getplumber/plumber/commit/bb11d139091551ed113bb14549b71dff8055dbbc)), closes [#199](https://github.com/getplumber/plumber/issues/199)


### 👷 CI/CD

* align self-scan workflow/job names to 'Plumber' ([371344e](https://github.com/getplumber/plumber/commit/371344ee63c840f17d6ff35001d273eacc2f2de7))
* **release:** pin v0.3.76 refs [skip ci] ([9c53473](https://github.com/getplumber/plumber/commit/9c534733f4cdbb78c8070b63567f277628066b90))

## [0.3.76](https://github.com/getplumber/plumber/compare/v0.3.75...v0.3.76) (2026-06-26)


### 🔧 Chores

* **score:** show the badge nudge in CI too and simplify its wording ([ac4111a](https://github.com/getplumber/plumber/commit/ac4111aa6c831c73cb30f468438d23b9bd6d809c))


### 📚 Documentation

* **readme:** add support contact tech@getplumber.io ([db3aba4](https://github.com/getplumber/plumber/commit/db3aba4327448877340c8228634c880a5bb6a26e))
* **readme:** security framing, drop 'compliance' wording ([a8b873a](https://github.com/getplumber/plumber/commit/a8b873af460c42823a44e2ccc833c268b66dbe1c))


### 👷 CI/CD

* **release:** pin v0.3.75 refs [skip ci] ([d79c2e9](https://github.com/getplumber/plumber/commit/d79c2e9b2a0eceabf87052c4298f0b616de0119d))

## [0.3.75](https://github.com/getplumber/plumber/compare/v0.3.74...v0.3.75) (2026-06-26)


### 🐛 Bug Fixes

* **action:** default points breakdown (beta) off ([06d3628](https://github.com/getplumber/plumber/commit/06d3628d1d94481a436aab0d45bd3410cb8a4473))
* **score:** skip push when the scan targets a foreign repo ([627129d](https://github.com/getplumber/plumber/commit/627129db5f3301a82d37787232421dc6d1b87756))


### ✅ Tests

* **score:** assert disabled score-push never publishes ([71d9589](https://github.com/getplumber/plumber/commit/71d9589dbc7452ed1254ec72c0048a9a42fa0d5d))


### 👷 CI/CD

* **release:** pin v0.3.74 refs [skip ci] ([b147582](https://github.com/getplumber/plumber/commit/b147582378568fe285ad487810c1f2549558df88))

## [0.3.74](https://github.com/getplumber/plumber/compare/v0.3.73...v0.3.74) (2026-06-26)


### ✨ Features

* add opt-in to push results on score.getplumber.io from CI ([175fc8c](https://github.com/getplumber/plumber/commit/175fc8c85146ccf4a87424f4feadb37247a14fd1))


### 🐛 Bug Fixes

* **build:** rebuild the runtime layer every release so apk upgrade ships current OS security fixes ([83eff9b](https://github.com/getplumber/plumber/commit/83eff9bf0f77040d645dd3e604ed32ba51e71542))


### 🔧 Chores

* **action:** rename Marketplace action to "Plumber Score" ([0fc9e8d](https://github.com/getplumber/plumber/commit/0fc9e8d2a60e8b10f3b1ebae5e6c89219d2a1203))


### 👷 CI/CD

* **release:** pin v0.3.73 refs [skip ci] ([1012f9c](https://github.com/getplumber/plumber/commit/1012f9c83589e7b23470eeaa01c79a39aebab2f6))

## [0.3.73](https://github.com/getplumber/plumber/compare/v0.3.72...v0.3.73) (2026-06-25)


### 🐛 Bug Fixes

* **ci:** Symlink the binary unto path inside the docker image so that it can run from anywhere ([94728a5](https://github.com/getplumber/plumber/commit/94728a50dac172c021393d66538eafe653be0770))


### 👷 CI/CD

* **release:** pin v0.3.72 refs [skip ci] ([8aba973](https://github.com/getplumber/plumber/commit/8aba973ea51820a2001d4171eaabe9cd0e1d1339))

## [0.3.72](https://github.com/getplumber/plumber/compare/v0.3.71...v0.3.72) (2026-06-25)


### 🐛 Bug Fixes

* **control:** Fix new control's (externalRefsMustNotCollide) schema and issue ([c5364bd](https://github.com/getplumber/plumber/commit/c5364bdd1a26c069395eb1f434ac002c7ee7ff0c))


### 👷 CI/CD

* **release:** pin v0.3.71 refs [skip ci] ([81b8ea2](https://github.com/getplumber/plumber/commit/81b8ea29b253131db36f07382a2d3e1ec66997f6))

## [0.3.71](https://github.com/getplumber/plumber/compare/v0.3.70...v0.3.71) (2026-06-24)


### 🔧 Chores

* **ci:** bump actions/checkout from 6.0.3 to 7.0.0 ([b9ad7a3](https://github.com/getplumber/plumber/commit/b9ad7a350370f9129652119b8e1682a8cb5f9385))
* **ci:** Fix trigger ci ([0641e69](https://github.com/getplumber/plumber/commit/0641e69b0064470e507f0d579c524df1b604fd70))


### 👷 CI/CD

* **release:** pin v0.3.70 refs [skip ci] ([18a8265](https://github.com/getplumber/plumber/commit/18a82651361aae6b23a12694d5954fef28569bd9))

## [0.3.70](https://github.com/getplumber/plumber/compare/v0.3.69...v0.3.70) (2026-06-22)


### ✨ Features

* **controls:** Issue-184. Add controls for github and gitlab that detect if actions/components versions also exist as branches, causing confusion ([da6d2c4](https://github.com/getplumber/plumber/commit/da6d2c4bcbdc8dea3288a010266a87e2f081de19))


### 👷 CI/CD

* **release:** pin v0.3.69 refs [skip ci] ([d617406](https://github.com/getplumber/plumber/commit/d617406ae6961cda533f27784fb17504d40790e0))

## [0.3.69](https://github.com/getplumber/plumber/compare/v0.3.68...v0.3.69) (2026-06-22)


### 🐛 Bug Fixes

* **template:** avoid circular GITLAB_TOKEN/PLUMBER_TOKEN reference ([d78e21e](https://github.com/getplumber/plumber/commit/d78e21ea3b588c604c46d1fffb198e4584df4217))


### 👷 CI/CD

* **release:** add all commit type in release notes ([db81766](https://github.com/getplumber/plumber/commit/db81766e0ab08a47f0cddf800d7b336368659b5d))
* **release:** pin v0.3.68 refs [skip ci] ([67fe2fc](https://github.com/getplumber/plumber/commit/67fe2fc08a3a8308b7712ceda1c9f60451b38de1))

## [0.3.68](https://github.com/getplumber/plumber/compare/v0.3.67...v0.3.68) (2026-06-19)

## [0.3.67](https://github.com/getplumber/plumber/compare/v0.3.66...v0.3.67) (2026-06-19)

## [0.3.66](https://github.com/getplumber/plumber/compare/v0.3.65...v0.3.66) (2026-06-19)

## [0.3.65](https://github.com/getplumber/plumber/compare/v0.3.64...v0.3.65) (2026-06-19)


### ♻️ Refactoring

* **provider:** add provider abstraction, dissolve collector into gitlab/github ([c309d1d](https://github.com/getplumber/plumber/commit/c309d1ddca2622a1f360b05c6b71e79f55e136fd))

## [0.3.64](https://github.com/getplumber/plumber/compare/v0.3.62...v0.3.64) (2026-06-18)


### ✨ Features

* **analyze,template:** add verbose env var and simplify CI template via env var delegation ([742487f](https://github.com/getplumber/plumber/commit/742487fd11d878c81269bec042de893ac6e43f35))
* **analyze:** support environment variables ([cd47fcd](https://github.com/getplumber/plumber/commit/cd47fcd329d85a4f9f346bc16c72e1fb911cec42))


### 🐛 Bug Fixes

* **analyze:** document env vars and cover fallbacks with tests ([3a659f9](https://github.com/getplumber/plumber/commit/3a659f90e591b108ac0fedab33502a1e4dd7d7a6))
* **lint:** replace spaces by tabs (gofmt) ([5a84933](https://github.com/getplumber/plumber/commit/5a849333836581b6ea2e0f91677125a9b1afd67b))

## [0.3.62](https://github.com/getplumber/plumber/compare/v0.3.61...v0.3.62) (2026-06-17)


### ✨ Features

* **control:** add githubActionMustComeFromAuthorizedSources (ISSUE-713) ([74d60c6](https://github.com/getplumber/plumber/commit/74d60c64f8ffe1ff8103d419489cde736202ec34)), closes [#253](https://github.com/getplumber/plumber/issues/253)

## [0.3.61](https://github.com/getplumber/plumber/compare/v0.3.60...v0.3.61) (2026-06-17)


### 🐛 Bug Fixes

* **wizard:** Make platform selection in wizard cleaner ([2987afb](https://github.com/getplumber/plumber/commit/2987afb95ee2d7cf53571cdfc741f03589105029))

## [0.3.60](https://github.com/getplumber/plumber/compare/v0.3.59...v0.3.60) (2026-06-15)


### 🐛 Bug Fixes

* **control:** Issue [#156](https://github.com/getplumber/plumber/issues/156) - Outdated Includes ([00d6866](https://github.com/getplumber/plumber/commit/00d68664e1d3542f82cbf57f92d3790240087fda))

## [0.3.59](https://github.com/getplumber/plumber/compare/v0.3.58...v0.3.59) (2026-06-15)


### 🐛 Bug Fixes

* **control:** Add missing pullRequestTargetHeadCheckoutResult and correctly count workflowsWithDangerousTrigger in reports ([4e73959](https://github.com/getplumber/plumber/commit/4e7395978aef1ffcd62e1265e4ac0520c7150b7b))

## [0.3.58](https://github.com/getplumber/plumber/compare/v0.3.57...v0.3.58) (2026-06-12)


### 🐛 Bug Fixes

* **control:** Fix false positives in issue 207 ([3a471ba](https://github.com/getplumber/plumber/commit/3a471ba59f14a84feccd700637fb3557b7b1514e))

## [0.3.57](https://github.com/getplumber/plumber/compare/v0.3.56...v0.3.57) (2026-06-12)


### 🐛 Bug Fixes

* **analysis:** Issue [#220](https://github.com/getplumber/plumber/issues/220) - Make data collection on github and gitlab more robust to network and fetch failures and render them in a UX friendly way ([650b13a](https://github.com/getplumber/plumber/commit/650b13a1f55ee3b25cc7fd94ebb4e6b3c854ffdf))

## [0.3.56](https://github.com/getplumber/plumber/compare/v0.3.55...v0.3.56) (2026-06-10)


### 🐛 Bug Fixes

* **control:** ISSUE-411 false positive when piping a local variable into an interpreter (echo "$VAR" | python3). Issue [#236](https://github.com/getplumber/plumber/issues/236) ([201755d](https://github.com/getplumber/plumber/commit/201755d2c71d1dba599280d0ff4c70f906bbf3fb))

## [0.3.55](https://github.com/getplumber/plumber/compare/v0.3.54...v0.3.55) (2026-06-10)


### 🐛 Bug Fixes

* **control:** Align dangerous-trigger metric with rule events and de-duplicate findings per job. Issue [#235](https://github.com/getplumber/plumber/issues/235) ([51e4c01](https://github.com/getplumber/plumber/commit/51e4c01c9433f86e861a660d729b2cd45e68789c))

## [0.3.54](https://github.com/getplumber/plumber/compare/v0.3.53...v0.3.54) (2026-06-10)


### 🐛 Bug Fixes

* **control:** Recognize safe dangerous triggers through protective mechanis such as psuh events and author association list. Issue [#235](https://github.com/getplumber/plumber/issues/235) ([7aea20e](https://github.com/getplumber/plumber/commit/7aea20ebd910a671ff392ec001ad599fa107b109))

## [0.3.53](https://github.com/getplumber/plumber/compare/v0.3.52...v0.3.53) (2026-06-10)


### 🐛 Bug Fixes

* **analysis:** Display clear error when fetching remote branch that doesnt exist ([9f15e31](https://github.com/getplumber/plumber/commit/9f15e31c95221e5d8433901994d824d58ec2b855))

## [0.3.52](https://github.com/getplumber/plumber/compare/v0.3.51...v0.3.52) (2026-06-10)


### ✨ Features

* **score:** Enforce --score always. Always make it so that this automatically uses this for the plumber compliance badge and mr comments ([809685a](https://github.com/getplumber/plumber/commit/809685a8261300262446137dda1dcc0bfdc77c32))

## [0.3.51](https://github.com/getplumber/plumber/compare/v0.3.50...v0.3.51) (2026-06-08)


### ✨ Features

* **gh:** Make data collector retry fetching tags with no auth if auth gets blocked + allow users to provide a metadata token to be used (a pat) ([dd65ebc](https://github.com/getplumber/plumber/commit/dd65ebc7d50dc0ea63f4b524b502bf6613ca3b5d))


### 🐛 Bug Fixes

* **ctrl:** False positive when using moving tags ([84b4a8f](https://github.com/getplumber/plumber/commit/84b4a8fd11ebde36a10dd6b107d15031a3ca635a))

## [0.3.50](https://github.com/getplumber/plumber/compare/v0.3.49...v0.3.50) (2026-06-04)

## [0.3.49](https://github.com/getplumber/plumber/compare/v0.3.48...v0.3.49) (2026-06-04)

## [0.3.48](https://github.com/getplumber/plumber/compare/v0.3.47...v0.3.48) (2026-06-04)

## [0.3.47](https://github.com/getplumber/plumber/compare/v0.3.46...v0.3.47) (2026-06-04)


### 🐛 Bug Fixes

* **docker:** Update docker image ([3b7bcfd](https://github.com/getplumber/plumber/commit/3b7bcfd7309b2118bce0f7b37e89d4b21def25c1))

## [0.3.46](https://github.com/getplumber/plumber/compare/v0.3.45...v0.3.46) (2026-06-04)

## [0.3.45](https://github.com/getplumber/plumber/compare/v0.3.44...v0.3.45) (2026-06-04)


### 🐛 Bug Fixes

* **component:** space separated inputs are now supported ([d1c90c7](https://github.com/getplumber/plumber/commit/d1c90c7121ef3e0a3ca1ad13c6b01589b69eef3f))

## [0.3.44](https://github.com/getplumber/plumber/compare/v0.3.43...v0.3.44) (2026-06-04)

## [0.3.43](https://github.com/getplumber/plumber/compare/v0.3.42...v0.3.43) (2026-06-03)


### 🐛 Bug Fixes

* **analysis:** handle multi-document YAML (spec: block) in CI config parsing ([b467b60](https://github.com/getplumber/plumber/commit/b467b608e7ab076344d82fc7e95da28f92452909))
* **parser:** Fix missing entries un unmarshal ([b2563a4](https://github.com/getplumber/plumber/commit/b2563a45b601601cc078588b00c490de44f043c9))

## [0.3.42](https://github.com/getplumber/plumber/compare/v0.3.41...v0.3.42) (2026-06-03)


### 🐛 Bug Fixes

* **controls:** Correct bug mixing up 301 and 309 ([2ef64fe](https://github.com/getplumber/plumber/commit/2ef64fe210be8e14e9787b0d30a343e8d383e9ab))

## [0.3.41](https://github.com/getplumber/plumber/compare/v0.3.40...v0.3.41) (2026-06-03)


### 🐛 Bug Fixes

* **ci:** Update toolchain in ci ([3a4e209](https://github.com/getplumber/plumber/commit/3a4e2099568246cf499ac3cd4a2ced15b55ea3a4))

## [0.3.40](https://github.com/getplumber/plumber/compare/v0.3.39...v0.3.40) (2026-06-03)


### 🐛 Bug Fixes

* **ci:** Update toolchain ([bd5205c](https://github.com/getplumber/plumber/commit/bd5205c1508d488d44d80ef5bb029f46d1b34f30))

## [0.3.39](https://github.com/getplumber/plumber/compare/v0.3.38...v0.3.39) (2026-06-03)


### ✨ Features

* **controls:** add pipeline secret detection via gitleaks (ISSUE-309) ([f902934](https://github.com/getplumber/plumber/commit/f90293451e6b0a03b07e6a3db1c7b1b574ea689f))


### 🐛 Bug Fixes

* **control:** Fixed and tested implementation for gitleaks ([d8170d4](https://github.com/getplumber/plumber/commit/d8170d4682f0943c59a4bf992f57ecd41658a31b))

## [0.3.38](https://github.com/getplumber/plumber/compare/v0.3.37...v0.3.38) (2026-06-02)


### ✨ Features

* **docs:** Fix typos ([251bc47](https://github.com/getplumber/plumber/commit/251bc47d6ae12fbc8f652aab4fb49f60969df91d))

## [0.3.37](https://github.com/getplumber/plumber/compare/v0.3.36...v0.3.37) (2026-06-02)


### ✨ Features

* **docs:** Simplify doc ([48859f1](https://github.com/getplumber/plumber/commit/48859f19afe18a4c24ecca9197945750b1d769a4))

## [0.3.36](https://github.com/getplumber/plumber/compare/v0.3.35...v0.3.36) (2026-06-02)

## [0.3.35](https://github.com/getplumber/plumber/compare/v0.3.34...v0.3.35) (2026-06-02)

## [0.3.34](https://github.com/getplumber/plumber/compare/v0.3.33...v0.3.34) (2026-06-02)

## [0.3.33](https://github.com/getplumber/plumber/compare/v0.3.32...v0.3.33) (2026-06-02)


### ✨ Features

* **controls:** ship pull-request-target-with-head-checkout (ISSUE-804) ([54e1162](https://github.com/getplumber/plumber/commit/54e11626c4bf5240d67ed4ef91a22629076ec016)), closes [#181](https://github.com/getplumber/plumber/issues/181)


### 🐛 Bug Fixes

* **controls:** Prevent duplicaiton with existing 802 issue for workflow ([a4a19a1](https://github.com/getplumber/plumber/commit/a4a19a1a3ff319999d7ae258f57fc35f73ff1c0f))

## [0.3.32](https://github.com/getplumber/plumber/compare/v0.3.31...v0.3.32) (2026-06-02)

## [0.3.31](https://github.com/getplumber/plumber/compare/v0.3.30...v0.3.31) (2026-06-02)

## [0.3.30](https://github.com/getplumber/plumber/compare/v0.3.29...v0.3.30) (2026-06-02)

## [0.3.29](https://github.com/getplumber/plumber/compare/v0.3.28...v0.3.29) (2026-06-01)


### 🐛 Bug Fixes

* **collector:** fold Docker Hub registry-host aliases to docker.io ([9df2679](https://github.com/getplumber/plumber/commit/9df26799f81349dfdce00dc5582f98b6063e2b87))

## [0.3.28](https://github.com/getplumber/plumber/compare/v0.3.27...v0.3.28) (2026-06-01)


### 🐛 Bug Fixes

* **controls:** scope ISSUE-411 trustedUrls to the curl/wget fetch target ([3541e75](https://github.com/getplumber/plumber/commit/3541e75507e0c9803b11b31b2417b20d9594234d)), closes [#214](https://github.com/getplumber/plumber/issues/214)
* **controls:** trustedUrls bare-hostname matching and partial semver false positives ([a7975cd](https://github.com/getplumber/plumber/commit/a7975cd7986fa28a0743ed6d8f2d3635b15f6cd0))

## [0.3.27](https://github.com/getplumber/plumber/compare/v0.3.26...v0.3.27) (2026-05-26)


### 🐛 Bug Fixes

* **control:** Fix bug in counting unpinned ([6401984](https://github.com/getplumber/plumber/commit/640198467b6c8f53d67cb9d173829eefa91d63dc))

## [0.3.26](https://github.com/getplumber/plumber/compare/v0.3.25...v0.3.26) (2026-05-26)


### ✨ Features

* **controls:** Implement pipelineMustNotExecuteUnverifiedScripts for github and cover a wider range such as the megalodon attack ([efcb8a7](https://github.com/getplumber/plumber/commit/efcb8a73c8b9c7931db5fe30403d50b56109371d))
* **reporting:** clickable source links in every output ([3b10260](https://github.com/getplumber/plumber/commit/3b102603282d20dbf93348d93ffd83b07f7c8327))

## [0.3.25](https://github.com/getplumber/plumber/compare/v0.3.24...v0.3.25) (2026-05-25)


### 🐛 Bug Fixes

* **controls:** treat moving major tags as a version span in advisory filter ([148bab8](https://github.com/getplumber/plumber/commit/148bab81f5691c6dc901de7718a82a9a29c0ecf6)), closes [#180](https://github.com/getplumber/plumber/issues/180) [#195](https://github.com/getplumber/plumber/issues/195)

## [0.3.24](https://github.com/getplumber/plumber/compare/v0.3.23...v0.3.24) (2026-05-25)


### 🐛 Bug Fixes

* **controls:** scope dangerous-triggers to exploitable cases ([af25ee0](https://github.com/getplumber/plumber/commit/af25ee0f1f339a2029bc0bfb385daecc4f83ee61)), closes [#192](https://github.com/getplumber/plumber/issues/192)

## [0.3.23](https://github.com/getplumber/plumber/compare/v0.3.22...v0.3.23) (2026-05-25)


### 🐛 Bug Fixes

* **controls:** scope template-injection to free-text github fields ([fcfbc05](https://github.com/getplumber/plumber/commit/fcfbc0585154369e1393716f7f930ef01618b5bd)), closes [#191](https://github.com/getplumber/plumber/issues/191)

## [0.3.22](https://github.com/getplumber/plumber/compare/v0.3.21...v0.3.22) (2026-05-25)


### 🐛 Bug Fixes

* **controls:** resolve SHA-pinned action refs in advisory filter ([43484a1](https://github.com/getplumber/plumber/commit/43484a160c718048e744908b80e7af7ec8042f9f)), closes [#179](https://github.com/getplumber/plumber/issues/179)

## [0.3.21](https://github.com/getplumber/plumber/compare/v0.3.20...v0.3.21) (2026-05-25)


### ✨ Features

* **init:** Interactive configuration generation when no config file ([5dd70c9](https://github.com/getplumber/plumber/commit/5dd70c91b1ec91e0c5471fa603a7fe0274446b49))

## [0.3.20](https://github.com/getplumber/plumber/compare/v0.3.19...v0.3.20) (2026-05-25)


### 🐛 Bug Fixes

* **ci:** Fix gitlab sast description ([c572607](https://github.com/getplumber/plumber/commit/c572607603f7fa372adb56af879cae7623037c09))

## [0.3.19](https://github.com/getplumber/plumber/compare/v0.3.18...v0.3.19) (2026-05-25)


### ✨ Features

* **action:** Update action documentation to stop conflict with existing name ([4401339](https://github.com/getplumber/plumber/commit/4401339a6e13a512de835a8bc9d8ef4355f732d0))

## [0.3.18](https://github.com/getplumber/plumber/compare/v0.3.17...v0.3.18) (2026-05-25)


### ✨ Features

* **action:** Update action documentation ([ce01848](https://github.com/getplumber/plumber/commit/ce0184848f0632fd927c8db780413b6dd0e76611))

## [0.3.17](https://github.com/getplumber/plumber/compare/v0.3.16...v0.3.17) (2026-05-22)


### 🐛 Bug Fixes

* improve GHES detection and add --provider flag ([#177](https://github.com/getplumber/plumber/issues/177)) ([e6779c5](https://github.com/getplumber/plumber/commit/e6779c54300191415544cdf6cb799db3bd1e8018))

## [0.3.16](https://github.com/getplumber/plumber/compare/v0.3.15...v0.3.16) (2026-05-22)

## [0.3.15](https://github.com/getplumber/plumber/compare/v0.3.14...v0.3.15) (2026-05-22)


### 🐛 Bug Fixes

* **sarif:** Not outputting correctly if only repo settings were bad ([d2fecc9](https://github.com/getplumber/plumber/commit/d2fecc9248c7e60e67ef2ff29a757d350632cd94))

## [0.3.14](https://github.com/getplumber/plumber/compare/v0.3.13...v0.3.14) (2026-05-22)


### 🐛 Bug Fixes

* **vulns:** Update some go deps ([760ae4d](https://github.com/getplumber/plumber/commit/760ae4d2e73c376507c9b505d932fb3d079757e6))

## [0.3.13](https://github.com/getplumber/plumber/compare/v0.3.12...v0.3.13) (2026-05-22)

## [0.3.12](https://github.com/getplumber/plumber/compare/v0.3.11...v0.3.12) (2026-05-22)


### ✨ Features

* **ci:** Automate version updates ([8a6f6df](https://github.com/getplumber/plumber/commit/8a6f6df29ea1977ed2621586aecff04d0b098a4e))

## [0.3.11](https://github.com/getplumber/plumber/compare/v0.3.10...v0.3.11) (2026-05-22)


### ✨ Features

* **aciton:** Pass token to CI and score point ([c9fe9a5](https://github.com/getplumber/plumber/commit/c9fe9a5bdb0f014d97f173b83383112b2adb4ba6))

## [0.3.10](https://github.com/getplumber/plumber/compare/v0.3.9...v0.3.10) (2026-05-21)


### ✨ Features

* **ci:** Add Github Action + SARIF format + GLSAST ([599125c](https://github.com/getplumber/plumber/commit/599125c23e6656ddbaf01234b0d72b17bc9d0f25))

## [0.3.9](https://github.com/getplumber/plumber/compare/v0.3.8...v0.3.9) (2026-05-21)


### ✨ Features

* **init:** Fix wizard to make it compatible with github ([bf49ae2](https://github.com/getplumber/plumber/commit/bf49ae24f90bd52ae58e6a2d8d491e77a8026101))

## [0.3.8](https://github.com/getplumber/plumber/compare/v0.3.7...v0.3.8) (2026-05-21)

## [0.3.7](https://github.com/getplumber/plumber/compare/v0.3.6...v0.3.7) (2026-05-21)


### 🐛 Bug Fixes

* **terminal:** Fix colors ([5a7637b](https://github.com/getplumber/plumber/commit/5a7637b956704ef4181ddb4312903b0f5323cbbb))

## [0.3.6](https://github.com/getplumber/plumber/compare/v0.3.5...v0.3.6) (2026-05-21)

## [0.3.5](https://github.com/getplumber/plumber/compare/v0.3.4...v0.3.5) (2026-05-21)

## [0.3.4](https://github.com/getplumber/plumber/compare/v0.3.3...v0.3.4) (2026-05-21)

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
