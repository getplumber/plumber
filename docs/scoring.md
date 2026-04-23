# Plumber pipeline scoring (profile `scoring-v2`)

This document describes how Plumber computes the **letter score** (A–E), **points** (0–100), and **Critical malus**, as implemented in `control/scoring.go`. It matches the active profile id `scoring-v2` (`PlumberScoreProfileID`).

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

- **Raw points** are computed from severity losses **before** Critical malus.
- **Final points** apply Critical malus when relevant, then the **letter score** is read from **final points only**.

---

## Inputs: severity counts

Plumber walks every open issue on **enabled** (non-skipped) controls and assigns each issue a **severity** (Critical, High, Medium, Low) from its issue code. It then counts how many issues fall in each bucket:

- `counts.critical`, `counts.high`, `counts.medium`, `counts.low`

Those four integers drive the math below.

---

## Step 1: Loss per severity bucket

For each severity with count `n > 0`, base **weight** `w`, and per-severity **cap** `C` on total loss for that bucket:

| Severity | Weight `w` | Cap `C` on loss for this bucket |
|----------|:-----------:|:--------------------------------:|
| Critical | 25 | none (∞) |
| High     | 20 | 60 |
| Medium   | 8  | 20 |
| Low      | 3  | 10 |

**Uncapped loss** for that bucket uses a dampened logarithmic curve so repeated offenses of the same type cost less than they would under a linear or `log2` model:

```text
L_uncapped = w × (1 + 0.5 × log2(n))
```

**Capped loss** (what actually counts):

- If the bucket has **no cap** (Critical): `L = L_uncapped`.
- Otherwise: `L = min(L_uncapped, C)`.

**Why `1 + 0.5·log2(n)`?** The first occurrence of a class of issue costs the full weight. Each doubling of `n` adds half a weight unit instead of a full one, so repeats still hurt but taper off smoothly.

**Why caps?** So one severity bucket cannot erase the entire scale on its own. Critical stays uncapped on purpose so stacking Critical issues keeps hurting, though the malus in Step 3 already forces the letter into the **E** band.


---

## Step 2: Raw points

Sum capped losses across the four severities: `totalLoss`.

```text
rawPoints = max(0, 100 − totalLoss)
```

So you start from 100 and subtract the combined capped losses. Raw points cannot go below 0.

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

With `plumber analyze --score-point`, the CLI prints a **points breakdown** table: for each non-empty severity row it shows count, weight, cap, and **capped loss**, then base 100, total loss, raw points, malus line (if any), final points, and letter score. That table is the same math as this document.

With `--score` only, you still get the **summary banner** (badge, final points, bar, severity counts, malus line) but not the full breakdown table.

---

## Where this appears

| Surface | When |
|---------|------|
| `plumber analyze --output …` JSON | `plumberScore` object when `--score` or `--score-point` is set |
| PBOM / CycloneDX | Same fields and CycloneDX properties (see [PBOM.md](PBOM.md)) |
| Merge request comment | Short block with `--score`; full points list with `--score-point` |

---

## Stability and changes

The profile id is exposed as `profileId: "scoring-v2"`. If weights, caps, malus, or letter thresholds change in code, the profile id should be bumped and this file updated so consumers can tell which rules produced a given result.
