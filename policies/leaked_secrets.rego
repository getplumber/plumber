# leaked-secrets — flag hardcoded secrets in the pipeline
# configuration. Detection happens in the collector
# (collector/gitleaks_scan.go), which shells out to gitleaks and
# redacts each match before writing it to
# input.pipeline.gitleaksHits. This rule converts each redacted hit
# into an ISSUE-309 finding.
#
# Why detection is outside rego: gitleaks is a regex + entropy
# engine over arbitrary text, not a structured-input check, so it
# belongs in the I/O / collector layer. The rule's job is the
# user-facing policy gate — opt-in toggle, finding shape, severity.
#
# Config gate (mirrors every other rego rule's enable check): silent
# unless input.config.pipelineMustNotLeakSecretsInConfig is set. The
# collector itself short-circuits on the same flag, so when the
# control is disabled the IR carries no hits and this gate is
# defence-in-depth.
package leaked_secrets

import rego.v1

deny contains finding if {
	input.config.pipelineMustNotLeakSecretsInConfig
	some hit in input.pipeline.gitleaksHits
	finding := {
		"code":     "ISSUE-309",
		"severity": "critical",
		"message":  sprintf("hardcoded secret detected (%s) at %s:%d — %s", [hit.ruleId, hit.file, object.get(hit, "line", 0), hit.preview]),
		"job":      hit.file,
		"file":     hit.file,
		"line":     object.get(hit, "line", 0),
		"ruleId":   hit.ruleId,
		"preview":  hit.preview,
	}
}
