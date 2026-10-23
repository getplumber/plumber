# Package lib.location reads the source lines the collector records next to
# a job's constructs (#572), so a finding points at the step, image,
# variable or key it is about instead of the job header. Every helper
# answers 0 when the line is unknown, which leaves the engine's fallback to
# the job header in place: a collector that records nothing (GitLab, for
# now) behaves exactly as before.
package lib.location

import rego.v1

# script_line is the line of line li of job.scripts[j].
script_line(job, j, li) := n if {
	n := job.scriptLines[j][li]
} else := 0

# variable_line is the line of the entry that sets the variable name.
variable_line(job, name) := object.get(object.get(job, "variableLines", {}), name, 0)

# key_line is the line of the job-level key, the first of keys the job
# writes when several spell the same setting.
key_line(job, keys) := first({n |
	some k in keys
	n := object.get(object.get(job, "keyLines", {}), k, 0)
})

# first is the smallest known line of a set of candidates, 0 when none is
# known. A rule takes the first line that fires so a finding keeps the one
# location it reports, whatever else in the job fires the same way.
first(lines) := min(known) if {
	known := {n | some n in lines; n > 0}
	count(known) > 0
} else := 0
