# unverified-scripts — flag pipeline scripts that download and execute
# remote code without integrity verification. The classic offender is
# the `curl ... | bash` pattern, a well-known supply-chain attack
# vector: a single compromise of the upstream URL turns the pipeline
# into an attacker-controlled payload.
#
# The policy currently matches the "pipe-to-shell" shape. Other unsafe
# patterns (download-and-exec, download-redirect-exec) can be added
# incrementally.
#
# Lines that include a checksum / signature verification command on
# the same line (sha256sum, shasum, gpg --verify, cosign verify, …)
# are treated as intentionally verified and skipped.
package unverified_scripts

import rego.v1

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	line := job.scripts[j]
	regex.match(`(?i)(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(bash|sh|zsh|python[23]?|perl|ruby)\b`, line)
	not _line_is_verified(line)
	finding := {
		"code":       "ISSUE-411",
		"severity":   "high",
		"message":    sprintf("job %q downloads and executes a remote script without integrity check", [job.name]),
		"job":        job.name,
		"scriptLine": line,
	}
}

_line_is_verified(line) if {
	regex.match(`(?i)(sha256sum|sha512sum|sha1sum|shasum|gpg\s+--verify|cosign\s+verify)`, line)
}
