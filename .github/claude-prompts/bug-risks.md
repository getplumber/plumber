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

## Behavior across runs and over time

Do not reason only about a single clean execution. For code that runs
repeatedly, runs concurrently, or reads and writes state that outlives one
run (files, databases, caches, queues, external records, comments, locks),
trace how it behaves over multiple executions:

- Idempotency: running the same operation twice — via a retry, a replay, a
  re-trigger, or a duplicate concurrent invocation — should not double-apply,
  oscillate, corrupt, or erase state. Flag operations that replace prior
  results wholesale when they should merge, or that redo work already done.
- Persisted / external state: state that is written but never cleaned up
  (stale entries that linger after they are no longer valid), that grows
  without bound, or that is read back on a later run and trusted without
  re-validation.
- Partial failure and degraded runs: when an input is missing, present but
  empty/invalid, or a dependency fails, does the code silently treat it as
  success? A run that did nothing, or only part of the work, should not be
  indistinguishable from a complete, successful one.
- Ordering and interleaving: correctness must not depend on an order the
  runtime does not guarantee, or on one invocation observing another's
  half-written state.

Reference file and line for every finding.

Do not comment on style, formatting, naming, or other non-functional
preferences.

If there are no findings, report nothing.
