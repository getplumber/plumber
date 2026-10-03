# scoring-v3 to scoring-v4 migration report

This page is the template `plumber score-compare` fills in. It compares, over
a corpus of repositories, the letter score Plumber's default profile
(`scoring-v3`, per-code severities) produced against the contextual profile
(`scoring-v4`, attack paths and contextual severity, see `docs/scoring.md`
and `control/scoring_v4.go`).

Running the two Radar passes and feeding their output to the tool is
operational work; this page only documents how to read the result.

---

## Producing the corpus

For every repository in the Radar corpus, run the analysis twice, once per
profile, writing each result to its own JSON file named `<project>.v3.json`
/ `<project>.v4.json` so `plumber score-compare` can pair them:

```bash
plumber analyze github.com/<o>/<r> --score-profile v3 --print=false --output out/<o>__<r>.v3.json
plumber analyze github.com/<o>/<r> --score-profile v4 --print=false --output out/<o>__<r>.v4.json
```

Then build the report:

```bash
plumber score-compare --input out/ --output scoring-v4-report.md
```

---

## Letter migration matrix

How many repositories moved from each scoring-v3 letter to each scoring-v4
letter. The diagonal is unchanged; everything off it moved.

<!-- filled by plumber score-compare -->

## Top 20 codes by points recovered

The 20 codes where scoring-v4 recovered the most points across the corpus,
summed over every paired repository. A code's points recovered for one
repository is its scoring-v3 code loss (the full per-code `codeLosses`
entry) minus that code's scoring-v4 contribution:

- a gate-role finding's own `gateLosses` entry (on scoring-v4 output
  `codeLosses` restates the same content, so the tool falls back to it when
  `gateLosses` is absent);
- plus an even share of every `pathLosses` bucket the code anchors: each
  bucket's `cappedLoss` is split evenly across its `pathIds`, and each path
  id's share is attributed to the code named in `paths[].anchorCode` for
  that id.

A negative number means scoring-v4 charges that code more than scoring-v3
did; those codes are still listed, lowest in the top 20, as a regression to
look at.

<!-- filled by plumber score-compare -->

## Dropped two or more letters

Every repository whose score fell two or more letters moving from
scoring-v3 to scoring-v4, with its scoring-v4 `situation` paragraph (the
plain-language explanation of why).

**Release gate:** a v4 that moves more than a few percent of repositories
down is a bug until explained. Each row here is either a real contextual
finding (a path scoring-v3 missed entirely) or a bug in the formula, the
path assembly, or a control; it is not acceptable to ship scoring-v4 while
an unexplained row remains.

<!-- filled by plumber score-compare -->

## Unpaired

Files that had no matching `.v3.json` / `.v4.json` counterpart in the input
directory (a Radar run that only finished one of the two profiles). These
never affected the matrix or the dropped list above, since there is nothing
to compare them against; re-run the missing profile for each one.

<!-- filled by plumber score-compare -->
