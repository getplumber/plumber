# Plumber pipeline scoring (profile `scoring-v3`)

This document describes how Plumber computes the **letter score** (A–E), **points** (0–100), and **Critical malus**, as implemented in `control/scoring.go`. It matches the active profile id `scoring-v3` (`PlumberScoreProfileID`).

> **Change from `scoring-v2`:** the per-severity cap is now applied **per issue code** (not on the total of a severity bucket). Distinct issue codes at the same severity each consume their own cap, so accumulating different *types* of issues keeps reducing the score even after one code is fully capped. High and Medium weights have been lowered (15 and 6).

---

## TL;DR: what each letter means

Each letter is derived from **final points** (see Step 4 for the exact thresholds).

| Letter | Final points | What it means |
|:------:|--------------|---------------|
| **A** 🟢 | ≥ 90 | **Excellent**, very low risk, clean pipeline |
| **B** 🟢 | 71 – 89 | **Good**, a few Low or Medium issues |
| **C** 🟡 | 51 – 70 | **Moderate**, Medium issues or accumulating Low findings, worth fixing |
| **D** 🟠 | 31 – 50 | **Poor**, High-severity issues impacting the pipeline |
| **E** 🔴 | < 31 | **Critical**, at least one Critical issue or heavy accumulated losses |

> **Rule of thumb:** any Critical issue forces the score into the **E** band regardless of how few other issues there are. See *Step 3: Critical malus* below.

---

## Language: score vs points

| Term | Meaning | In JSON (`plumberScore` / PBOM) |
|------|---------|----------------------------------|
| **Score** | The letter **A**, **B**, **C**, **D**, or **E**. This is what people usually mean by "what's our Plumber score?" | `score` (string) |
| **Points** | A number from **0** to **100** measuring pipeline risk from open issues. Higher is better. | `rawPoints`, `finalPoints` (numbers) |

- **Raw points** are computed from per-code losses **before** Critical malus.
- **Final points** apply Critical malus when relevant, then the **letter score** is read from **final points only**.

---

## Inputs: per-code counts

Plumber walks every open issue on **enabled** (non-skipped) controls and aggregates them by **issue code** (e.g. `ISSUE-401`, `ISSUE-205`). Each code carries a documented **severity** (Critical, High, Medium, Low) which determines its weight and per-code cap.

Both views are reported:

- `counts.{critical,high,medium,low}`: total findings per severity (banner, MR comment).
- `codeLosses[]`: per-code rows that drive the score (full breakdown via `--score-point`).

---

## Step 1: Loss per issue code

For each code with count `n > 0`, the **weight** `w` and **per-code cap** `C` come from its severity:

| Severity | Weight `w` | Cap `C` per code |
|----------|:----------:|:-----------------:|
| Critical | 25 | none (∞) |
| High     | 15 | 60 |
| Medium   | 6  | 20 |
| Low      | 3  | 10 |

**Uncapped loss** for a code uses a dampened logarithmic curve so repeated occurrences of the *same* code cost less than a linear or `log2` model:

```text
L_uncapped = w × (1 + 0.5 × log2(n))
```

**Capped loss** (what actually counts):

- If the severity has **no cap** (Critical): `L = L_uncapped`.
- Otherwise: `L = min(L_uncapped, C)`.

**Why per-code caps?** A pipeline that triggers 200 instances of the same issue keeps tapering off and is bounded by `C`. But *different* problems should not be free once one code is capped: each new code at the same severity opens a fresh budget up to its own `C`, so the score keeps reflecting the diversity of issues.

**Why `1 + 0.5·log2(n)`?** The first occurrence of a code costs the full weight. Each doubling of `n` adds half a weight unit instead of a full one, so repeats still hurt but taper off smoothly.

---

## Step 2: Raw points

Sum capped losses across **all codes**: `totalLoss`.

```text
rawPoints = max(0, 100 − totalLoss)
```

So you start from 100 and subtract the combined per-code capped losses. Raw points cannot go below 0.

The result also exposes a per-severity rollup (`losses[]`) which is the sum of per-code capped losses inside each severity. This rollup is informational and can exceed any single per-code cap once multiple codes accumulate.

---

## Step 3: Critical malus → final points

If **at least one** Critical issue exists (`counts.critical > 0`):

- **Critical malus** applies.
- Final points are capped:

  ```text
  finalPoints = min(rawPoints, 30)
  ```

- `criticalMalusApplied` is `true` and `criticalMalusMax` is **30** (the cap used in that `min`).

If there are **no** Critical issues:

- `finalPoints = rawPoints`.
- `criticalMalusApplied` is `false`.

**Rationale:** any Critical finding is treated as immediate, high-impact risk. Final points are forced into the **E band** (below 31), so the letter score cannot read better than **E** while Critical issues remain, even if raw points would otherwise be high.

---

## Step 4: Letter score from final points

The letter **score** is derived **only** from **final points** using fixed thresholds:

| Letter score | Final points (inclusive) |
|----------------|---------------------------|
| **A** | finalPoints ≥ 90 |
| **B** | 71 ≤ finalPoints < 90 |
| **C** | 51 ≤ finalPoints < 71 |
| **D** | 31 ≤ finalPoints < 51 |
| **E** | finalPoints < 31 |

So with malus, `finalPoints = 30` maps to **E** (because 30 < 31).

---

## Breakdown output (`--score-point`)

By default the CLI prints the **summary banner** (badge, final points, bar, severity counts, malus line). With `plumber analyze --score-point`, it also prints a **points breakdown** table with one row per issue code (`Code | Severity | Count | Weight | Cap | Loss`), then base 100, total loss, raw points, malus line (if any), final points, and letter score. That table is the same math as this document.

The legacy `--score` flag is deprecated and has no effect now that the score is shown by default. It is still accepted so existing invocations do not break.

---

## Where this appears

| Surface | When |
|---------|------|
| Terminal banner | By default |
| `plumber analyze --output …` JSON | `plumberScore` object, by default |
| PBOM / CycloneDX | Same fields and CycloneDX properties (see [PBOM.md](PBOM.md)) |
| Merge request comment | Short block by default; full points list with `--score-point` |

---

## Stability and changes

The profile id is exposed as `profileId: "scoring-v3"`. If weights, caps, malus, or letter thresholds change in code, the profile id should be bumped and this file updated so consumers can tell which rules produced a given result.
