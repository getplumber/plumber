# image-pinned-by-digest — flag pipeline jobs whose container image is
# referenced by tag rather than by immutable content digest (`@sha256:…`).
# Only fires when the policy is opted into via
# `containerImageMustNotUseForbiddenTags.mustBePinnedByDigest: true` in
# the .plumber.yaml, matching the legacy Go control semantics. Tag-based
# references (even pinned to a specific version like `python:3.12.1`)
# are flagged because the tag can be moved to a different image at any
# point in time.
package image_pinned_by_digest

import rego.v1

deny contains finding if {
	_pin_by_digest_required
	some i
	job := input.pipeline.jobs[i]
	job.image
	not _image_has_digest(job.image)
	finding := {
		"code":     "ISSUE-103",
		"severity": "high",
		"message":  sprintf("job %q uses image without digest pinning: %s", [job.name, _image_ref(job.image)]),
		"job":      job.name,
		"link":     _image_ref(job.image),
		# Identity keys on imageRepo (registry/name, no tag): the subject
		# is "this image is not pinned by digest", so a routine tag bump
		# (still digestless) must not re-key it. link/tag stay as data.
		"imageRepo": _image_repo(job.image),
		"tag":       _image_tag(job.image),
	}
}

_image_tag(img) := img.tag if {
	img.tag != ""
} else := ""

_pin_by_digest_required if {
	input.config.containerImageMustNotUseForbiddenTags.mustBePinnedByDigest == true
}

_image_has_digest(img) if {
	img.digest != null
	img.digest != ""
}

# Build the full `<registry>/<name>:<tag>` ref the legacy "link"
# field surfaces. Falls back to bare name (and optionally :tag) when
# the registry is empty.
_image_ref(img) := ref if {
	img.registry != ""
	img.tag != ""
	ref := sprintf("%s/%s:%s", [img.registry, img.name, img.tag])
} else := ref if {
	img.registry != ""
	ref := sprintf("%s/%s", [img.registry, img.name])
} else := ref if {
	img.tag != ""
	ref := sprintf("%s:%s", [img.name, img.tag])
} else := img.name

# _image_repo is the tagless, digestless `<registry>/<name>` reference —
# the identity subject for the not-pinned-by-digest finding. The "unknown"
# registry literal the GitLab collector emits for a registryless image is
# collapsed to the bare name (matching ISSUE-101's _image_repo and _full_ref),
# so a registryless image gets a clean, stable identity and does not re-key if
# its registry later resolves.
_image_repo(img) := ref if {
	img.registry != ""
	img.registry != "unknown"
	ref := sprintf("%s/%s", [img.registry, img.name])
} else := img.name
