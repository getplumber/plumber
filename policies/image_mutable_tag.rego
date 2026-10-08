# image_mutable_tag — flag pipeline jobs whose container image uses a tag
# listed in the user's .plumber.yaml forbidden-tag set.
#
# Config contract:
#   input.config.imageMutableTag.forbiddenTags = ["latest", "dev", "v*-alpha", ...]
#
# Patterns support glob wildcards (`*`, `?`) for parity with the legacy Go
# control containerImageMustNotUseForbiddenTags. Issue code ISSUE-102 is
# kept identical to the Go output so findings stay comparable in shadow mode.
package image_mutable_tag

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	# An image reference that still held a `$VARIABLE` when it was parsed
	# describes a placeholder, not an image: registry, name and tag were
	# split out of the literal text. Judging it answers a real question
	# over a guess, so skip that job and keep judging the rest.
	some img in _job_images(job)
	not img.unresolved
	tag := img.tag
	tag != ""
	_tag_is_forbidden(tag)
	finding := {
		"code":     "ISSUE-102",
		"severity": "medium",
		"message":  sprintf("Job `%s` uses the forbidden tag `%s` of image `%s`.", [job.name, tag, _full_ref(img)]),
		"job":      job.name,
		"tag":      tag,
		"link":     _full_ref(img),
	}
}

# _job_images: the images the job's container reference resolves to
# through its matrix literals (matrixImages) when it has them, the image
# as written otherwise.
_job_images(job) := job.matrixImages if {
	count(object.get(job, "matrixImages", [])) > 0
} else := [job.image] if {
	job.image
} else := []

_full_ref(img) := ref if {
	img.registry != ""
	ref := sprintf("%s/%s:%s", [img.registry, img.name, img.tag])
} else := sprintf("%s:%s", [img.name, img.tag])

_tag_is_forbidden(tag) if {
	pattern := input.config.imageMutableTag.forbiddenTags[_]
	glob.match(pattern, null, tag)
}
