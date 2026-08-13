# unsound-condition — flag `if:` expressions that are logically
# unsound: tautologies (`always()` short-circuiting an OR),
# contradictions (`false && ...`), and bare boolean conditions that
# never evaluate to the expected value because GitHub parses them as
# string literals when the author forgot the `${{ }}` wrapping.
#
# These are subtle bugs: the gate the author believes they have
# installed is not actually there, and the step / job runs (or never
# runs) silently. The policy is per-condition, reusing the IR's
# Conditions slice (job + step-level `if:` collected by the
# collector).
package unsound_condition

import rego.v1

tautology_patterns := [
	`\balways\(\)\s*\|\|`,
	`\|\|\s*always\(\)`,
	`\btrue\s*==\s*true\b`,
	`\b1\s*==\s*1\b`,
	`\b'[^']*'\s*==\s*'[^']*'\s*\|\|\s*true\b`,
]

contradiction_patterns := [
	`\bfalse\s*&&`,
	`&&\s*false\b`,
	`\btrue\s*==\s*false\b`,
	`\bfalse\s*==\s*true\b`,
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	cond := job.conditions[j]
	reason := _unsound_reason(cond)
	finding := {
		"code":      "ISSUE-211",
		"severity":  "medium",
		"message":   sprintf("job %q has an unsound `if:` condition (%s): %q", [job.name, reason, cond]),
		"job":       job.name,
		"condition": cond,
	}
}

_unsound_reason(cond) := "tautology" if {
	some p in tautology_patterns
	regex.match(p, cond)
}

_unsound_reason(cond) := "contradiction" if {
	some p in contradiction_patterns
	regex.match(p, cond)
}
