# container-hardcoded-credentials — flag GitHub Actions job containers
# whose `credentials.password` is a literal string instead of a
# `${{ secrets.X }}` reference. A literal password ends up in git
# history in plain text — anyone with read access to the repository can
# retrieve it, and rotating means rewriting history on every clone.
#
# The collector forwards the raw YAML value of credentials.password on
# the IR image. Template expressions (`${{ secrets.DOCKER_PASS }}`) pass
# through as-is — they are recognisable by the surrounding `${{ }}`.
package container_hardcoded_credentials

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	pw := job.image.credentialsPassword
	pw != ""
	not _is_expression(pw)
	finding := {
		"code":     "ISSUE-704",
		"severity": "critical",
		"message":  sprintf("job %q sets container.credentials.password to a literal value — use ${{ secrets.* }} instead", [job.name]),
		"job":      job.name,
	}
}

# _is_expression is true when the password value contains a GitHub
# Actions template expression. A bare `${{ }}` without an enclosed
# reference is technically also a literal (it would evaluate to an
# empty string) but the policy doesn't try to catch that micro-case —
# the interesting signal is the literal-password footprint.
_is_expression(value) if {
	contains(value, "${{")
	contains(value, "}}")
}
