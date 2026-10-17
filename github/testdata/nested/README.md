# Nested actions reproduction (recorded)

The files under this directory are the raw bodies of the public reproduction
repositories of the nested actions resolution (spec 2026-10-16, section 1),
recorded byte for byte on 2026-10-16 through the contents API at the commits
below. `nested_golden_test.go` (this package) and `cmd/nested_golden_test.go`
read them.

| Directory | Repository | File | Commit |
|---|---|---|---|
| `a/` | `thomasboni/nested-actions-a` | `.github/workflows/ci.yml` (job `nested`, uses B at line 13) | `072a8123a364951d7e17fa845126ed6a4a8547ca` |
| `b/` | `thomasboni/nested-actions-b` | `action.yml` (composite: an echo, C at line 8, D at line 9) | `b7066485cd3df4314af027cf80f16d38b9c653f1` |
| `c/` | `thomasboni/nested-actions-c` | `action.yml` (composite leaf, one echo) | `28b3e8f87863fa737a33d9124cc1b80e0c9081e2` |
| `d/` | `thomasboni/nested-actions-d` | `action.yml` (composite: an echo, E at line 8) | `ff42ea157105a7f8eba57ba8cbb75d32f42374f1` |
| `e/` | `thomasboni/nested-actions-e` | `action.yml` (composite leaf, one echo) | `83333927ab23675c0b444122f2fe6d1bcd435954` |

B was reset to this plain chain on 2026-10-16 after the probe of plan ruling
14 (a `./` reference inside a composite resolves against the job's
workspace), so its recorded commit is the one after the reset.

Every `uses:` in these files is `@main` on purpose: the reproduction shows a
first-level scan judging B while C, D and E, pulled in by B and D, run
unseen.

`resolved_uses.golden.json` is the job's entry list after the resolution:
four entries in runner order, every one on line 13 of the workflow (the
outermost step, R9), C and D via B, E via B then D, each nested entry with
the container line it is defined at.

`synthetic/e/action.yml` is NOT recorded: a variant of E, never pushed to
the live repository, whose step pipes a script fetched from a moving ref into
bash, so the mutable-exec scan of a nested entry is asserted at tier `exec`.
