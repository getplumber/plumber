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
	tag := job.image.tag
	tag != ""
	_tag_is_forbidden(tag)
	finding := {
		"code":     "ISSUE-102",
		"severity": "high",
		"message":  sprintf("job %q uses forbidden image tag %q", [job.name, tag]),
		"job":      job.name,
		"tag":      tag,
		"link":     _full_ref(job.image),
	}
}

_full_ref(img) := ref if {
	img.registry != ""
	ref := sprintf("%s/%s:%s", [img.registry, img.name, img.tag])
} else := sprintf("%s:%s", [img.name, img.tag])

_tag_is_forbidden(tag) if {
	pattern := input.config.imageMutableTag.forbiddenTags[_]
	glob.match(pattern, null, tag)
}
