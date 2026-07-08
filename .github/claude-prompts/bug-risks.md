# Bug risks

Review the diff for:

- Logic errors: wrong conditions, inverted checks, off-by-one errors,
  incorrect algorithms.
- Unhandled edge cases: empty/nil inputs, zero values, boundary values,
  unexpected input shapes.
- Race conditions: unsynchronized shared state, TOCTOU, concurrent map or
  slice access, goroutine/thread lifetime issues.
- Incorrect error handling: swallowed errors, wrong error propagation,
  errors checked against the wrong value, missing cleanup on error paths.
- API misuse: standard library or third-party APIs used contrary to their
  contracts (ignored return values, invalid argument combinations, misuse
  of context/cancellation, resource leaks).
- Breaking changes to public interfaces: changed signatures, semantics, or
  serialized formats that existing callers or consumers depend on.

## Regressions and behavior changes

For each modified function, compare the new behavior with the previous one
(use the diff, and `git show <base>:<path>` when you need the full previous
version of a file). Flag:

- Outputs or return values that change for inputs the old code handled.
- Removed or altered handling of edge cases the old code covered.
- New side effects the old code did not have: writes, network calls,
  logging of sensitive data, mutation of shared state.
- Changed ordering, defaults, or error semantics that existing callers may
  rely on.

Distinguish changes that are intentional (consistent with the PR's stated
purpose) from likely accidents, and only report the latter — except for an
intentional-looking breaking change that nothing in the PR acknowledges,
which is worth reporting too.

Reference file and line for every finding.

Do not comment on style, formatting, naming, or other non-functional
preferences.

If there are no findings, report nothing.
