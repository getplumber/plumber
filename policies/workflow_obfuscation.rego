# workflow-obfuscation — flag workflows whose scripts or expression
# fragments carry invisible or bidirectional Unicode characters. The
# rendered source reads harmless in a diff review, while the runner
# executes a different instruction. Two classes are covered:
#
#   - Zero-width spaces / joiners / non-joiners (U+200B–U+200F,
#     U+FEFF) — used to hide tokens inside an identifier or a URL.
#   - Bidirectional overrides (U+202A–U+202E, U+2066–U+2069) — the
#     Trojan Source attack class (CVE-2021-42574) exploited in the
#     wild since 2021 against npm / PyPI packages.
#
# The scan runs on every script line, every env binding value, and
# every action `with:` input. Normal ASCII, latin-1, and whitespace
# pass through untouched.
package workflow_obfuscation

import rego.v1

invisible_pattern := `[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]`

deny contains finding if {
	# GitHub-only control (workflowMustNotContainObfuscation). Reads generic
	# job.scripts / job.variables, so a stray zero-width or bidi character in
	# an ordinary GitLab script/variable would fire it (getplumber/plumber
	# #349). The catalog gate also drops it; this guard stops it at the source.
	input.pipeline.provider == "github"
	some i
	job := input.pipeline.jobs[i]
	_job_contains_obfuscation(job)
	finding := {
		"code":     "ISSUE-420",
		"severity": "high",
		"message":  sprintf("job %q contains zero-width or bidirectional Unicode in its scripts / env / action inputs — Trojan Source / invisible-character attack pattern", [job.name]),
		"job":      job.name,
	}
}

_job_contains_obfuscation(job) if {
	some k
	regex.match(invisible_pattern, job.scripts[k])
}

_job_contains_obfuscation(job) if {
	some _, value in job.variables
	regex.match(invisible_pattern, value)
}

_job_contains_obfuscation(job) if {
	some k
	action := job.uses[k]
	some _, value in action.with
	is_string(value)
	regex.match(invisible_pattern, value)
}
