# unsound-contains — flag `contains(haystack, needle)` calls whose
# argument order makes the check always fail. The most frequent
# footgun is `contains('main', github.ref)`: the literal `'main'`
# does not contain `refs/heads/main`, so the gate never matches on
# the `main` branch — but the author intended the opposite.
#
# Detection heuristic: `contains('…literal…', …expression…)` — a
# string literal as the HAYSTACK with an expression as the NEEDLE is
# almost always the inverted form. The safe form is
# `contains(github.ref, 'refs/heads/main')` or
# `contains(fromJSON('[…]'), github.ref_name)` (explicit set).
package unsound_contains

import rego.v1

# First argument is a string literal (single quotes, no template
# expressions inside), second argument references a template
# expression (`github.`, `inputs.`, `needs.`, `env.`, `vars.`,
# `steps.`, `secrets.`, `matrix.`, `runner.`). The fromJSON(...)
# haystack form — a valid JSON list as the first argument — is the
# safe idiom, so we exclude `fromJSON(` from the literal match.
suspicious_pattern := `\bcontains\s*\(\s*'[^']{1,40}'\s*,\s*(github\.|inputs\.|needs\.|env\.|vars\.|steps\.|secrets\.|matrix\.|runner\.)`

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	cond := job.conditions[j]
	regex.match(suspicious_pattern, cond)
	finding := {
		"code":     "ISSUE-212",
		"severity": "medium",
		"message":  sprintf("job %q calls `contains()` with a literal haystack and an expression needle — arguments likely inverted in %q", [job.name, cond]),
		"job":      job.name,
	}
}

# Scripts can also build `contains(...)` calls inside ${{ }} blocks
# that feed env bindings or output assignments. Same check applied
# to the scripts slice.
deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	script := job.scripts[j]
	regex.match(suspicious_pattern, script)
	finding := {
		"code":     "ISSUE-212",
		"severity": "medium",
		"message":  sprintf("job %q has a script with an inverted `contains(literal, expression)` call", [job.name]),
		"job":      job.name,
	}
}
