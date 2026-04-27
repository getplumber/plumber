# dependabot-missing-cooldown — flag update ecosystems in
# .github/dependabot.yml that have no `cooldown:` window. Without a
# cooldown, Dependabot opens a PR the instant a new upstream version
# is published — including the minute-old release that a compromised
# maintainer just pushed. The security advisory pipeline needs hours
# / days to flag a bad release; a cooldown buys exactly that window.
package dependabot_missing_cooldown

import rego.v1

deny contains finding if {
	input.pipeline.dependabot
	some i
	ecosystem := input.pipeline.dependabot.missingCooldownEcosystems[i]
	finding := {
		"code":     "ISSUE-607",
		"severity": "low",
		"message":  sprintf("dependabot ecosystem %q has no cooldown window — a compromised upstream release would reach an auto-merge PR immediately", [ecosystem]),
		"file":     input.pipeline.dependabot.path,
	}
}
