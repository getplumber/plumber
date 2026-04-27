# image-authorized-sources — flag pipeline jobs that pull a container
# image from a registry not listed in
# containerImageMustComeFromAuthorizedSources.trustedUrls. Official
# Docker Hub images (image name without a slash, or prefixed by
# "library/") are accepted implicitly when
# trustDockerHubOfficialImages is true.
package image_authorized_sources

import rego.v1

deny contains finding if {
	# Only run when the user has declared an authorized-sources policy;
	# without a config, the rule is effectively disabled.
	input.config.imageAuthorizedSources
	some i
	job := input.pipeline.jobs[i]
	job.image
	not _is_authorized(job.image)
	finding := {
		"code":     "ISSUE-101",
		"severity": "critical",
		"message":  sprintf("job %q uses image from untrusted source: %s", [job.name, _full_ref(job.image)]),
		"job":      job.name,
		"link":     _full_ref(job.image),
		"status":   "unauthorized",
	}
}

_is_authorized(img) if {
	input.config.imageAuthorizedSources.trustDockerHubOfficial == true
	_is_docker_hub_official(img)
}

_is_authorized(img) if {
	pattern := input.config.imageAuthorizedSources.trustedUrls[_]
	glob.match(pattern, null, _full_ref(img))
}

_is_docker_hub_official(img) if {
	_registry_is_docker_hub(img)
	not contains(img.name, "/")
}

_is_docker_hub_official(img) if {
	_registry_is_docker_hub(img)
	startswith(img.name, "library/")
}

_registry_is_docker_hub(img) if {
	img.registry == "docker.io"
}

_registry_is_docker_hub(img) if {
	not img.registry
}

_registry_is_docker_hub(img) if {
	img.registry == ""
}

# _full_ref builds the canonical `<registry>/<name>:<tag>` string the
# trusted-URL globs in .plumber.yaml are written against. Including
# the tag is essential — patterns like `docker.io/foo/bar:*`
# explicitly carry a colon and the glob would otherwise miss the
# untagged form. When no tag is set, fall back to the base ref.
_full_ref(img) := ref if {
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
