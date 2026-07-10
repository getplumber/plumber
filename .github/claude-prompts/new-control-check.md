# New control check

First determine whether this PR adds or modifies a Plumber control — a
detection rule, policy, or analyzer check. If it does not, report nothing
and stop.

If it does, evaluate the control for false positives and false negatives
against real-world usage, not toy examples.

## False positives

Enumerate legitimate, common real-world pipeline patterns that would
wrongly trigger this control. Think about how actual teams write their CI
configs:

- Monorepos and matrix builds.
- Reusable / included workflows and templating.
- Vendored actions and self-hosted runners.
- Dynamic values coming from variables or secrets contexts.
- Commented-out code.
- Test fixtures that intentionally contain the flagged pattern.

For each candidate false positive, give a concrete minimal config snippet
that a real project could plausibly contain, and explain why the control
fires incorrectly on it.

## False negatives

Enumerate realistic evasions and variants the control misses —
semantically equivalent syntax the pattern does not cover:

- Quoting and escaping variants.
- Indirection through variables or the environment.
- Multi-line / folded YAML forms.
- YAML aliases and anchors.
- Case differences.
- Obfuscation via string concatenation or encoding.
- Equivalent commands or alternate tools achieving the same effect.
- The same risk expressed in an included or child pipeline.

For each, give a concrete snippet that SHOULD be caught but is not, and
identify which part of the detection logic misses it.

## Test fixtures

Check the control's test fixtures: do they cover the false-positive and
false-negative cases above? List missing fixtures as specific suggested
test cases.

## Verdict

Rate the control's real-world precision and recall as high / medium / low,
with a one-line justification for each rating.

## Rules

- Reference file and line for every claim about the detection logic.
- Do not write code to the repository.
