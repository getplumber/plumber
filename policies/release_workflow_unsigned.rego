# release-workflow-unsigned — flag release / publish jobs that
# produce artefacts without any signing step. Consumers of the
# release then have no cryptographic handle to verify the artefact
# was built by the expected pipeline rather than tampered with
# along the way (cache poisoning, compromised runner, repository
# takeover). Signing (Sigstore cosign, GPG, SLSA provenance, npm
# --provenance) turns "I trust this came from that repo" into a
# falsifiable statement.
#
# Fires only when the job is a release / publish context (trigger
# `release`, or invokes a recognised publish action) AND none of its
# steps invoke a recognised signing action. OIDC-based publish
# actions (`pypa/gh-action-pypi-publish` with trusted publishing,
# `npm publish --provenance`) are considered self-signing.
package release_workflow_unsigned

import rego.v1

publish_actions := {
	"pypa/gh-action-pypi-publish",
	"JS-DevTools/npm-publish",
	"softprops/action-gh-release",
	"ncipollo/release-action",
	"goreleaser/goreleaser-action",
	"docker/build-push-action",
}

signing_actions := {
	"sigstore/cosign-installer",
	"sigstore/gh-action-sigstore-python",
	"crazy-max/ghaction-import-gpg",
	"slsa-framework/slsa-github-generator",
	"philips-labs/slsa-provenance-action",
	"sigstore/sigstore-java",
	# GitHub-native Sigstore attestation actions (keyless OIDC
	# signing into the Rekor transparency log). `attest-build-provenance`
	# is the SLSA provenance flavour; `attest-sbom` signs SBOMs; the
	# base `attest` action signs arbitrary predicates.
	"actions/attest-build-provenance",
	"actions/attest-sbom",
	"actions/attest",
}

# Self-signing publish contexts: the publish action itself handles
# provenance when the right inputs are passed, so absence of a
# dedicated signing step is expected.
self_signing_publish_actions := {
	"pypa/gh-action-pypi-publish", # trusted publishing attaches provenance
}

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_is_release_context(job)
	not _job_self_signs(job)
	not _job_runs_signing_step(job)
	finding := {
		"code":     "ISSUE-712",
		"severity": "medium",
		"message":  sprintf("job %q publishes release artefacts without any signing step — add cosign / sigstore / GPG alongside the publish action", [job.name]),
		"job":      job.name,
	}
}

_is_release_context(job) if {
	some t in job.triggers
	t == "release"
}

_is_release_context(job) if {
	some k
	action := job.uses[k]
	_is_publish_action(action.uses)
}

_is_publish_action(uses) if {
	some prefix in publish_actions
	startswith(uses, sprintf("%s@", [prefix]))
}

_is_publish_action(uses) if {
	some prefix in publish_actions
	uses == prefix
}

_job_runs_signing_step(job) if {
	some k
	action := job.uses[k]
	some prefix in signing_actions
	startswith(action.uses, sprintf("%s@", [prefix]))
}

_job_runs_signing_step(job) if {
	some k
	action := job.uses[k]
	some prefix in signing_actions
	action.uses == prefix
}

# npm --provenance on a run: script counts as self-signing.
_job_runs_signing_step(job) if {
	some k
	regex.match(`npm\s+publish\s.*--provenance`, job.scripts[k])
}

# cosign / gpg --detach-sign invoked directly in a run: script.
_job_runs_signing_step(job) if {
	some k
	regex.match(`\bcosign\s+sign\b`, job.scripts[k])
}

_job_runs_signing_step(job) if {
	some k
	regex.match(`\bgpg\s+--?detach-?sign\b`, job.scripts[k])
}

_job_self_signs(job) if {
	some k
	action := job.uses[k]
	some prefix in self_signing_publish_actions
	startswith(action.uses, sprintf("%s@", [prefix]))
}
