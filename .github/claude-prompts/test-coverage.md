# Test coverage

Assess whether the changes in the diff are adequately tested.

- Changed behavior without corresponding test changes: identify modified or
  added logic whose tests were not updated or added.
- Missing edge-case coverage: boundary values, error paths, empty inputs,
  concurrency, and failure modes that the new code introduces but the tests
  do not exercise.
- Weak assertions: tests that run the new code but assert too little to
  catch regressions (asserting only "no error", ignoring returned values,
  overly broad matchers).

Suggest specific test cases: name the function or behavior under test, the
input or scenario, and the expected outcome. Reference file and line for
the code you consider under-tested.

Do not write code to the repository.

If test coverage is adequate, report nothing.
