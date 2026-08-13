# image-authorized-sources — flag pipeline jobs that pull a container
# image from a registry not listed in
# containerImageMustComeFromAuthorizedSources.trustedUrls. Official
# Docker Hub images (image name without a slash) are accepted
# implicitly when trustDockerHubOfficialImages is true.
#
# Parity with the legacy Go control (controlGitlabImageUntrusted.go):
#   - The "unknown" registry literal emitted by the GitLab image
#     collector is treated the same as no registry (image name only).
#   - Both the image reference and each trustedUrls pattern are
#     normalised so `${VAR}` and `$VAR` compare equal — mirrors the
#     legacy normalizeVarNotation pass.
#   - Glob matching is performed via `glob.match(pat, null, ref)` which
#     mirrors go-wildcard.Match semantics for `*` and `?` patterns.
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
		# Identity keys on imageRepo (registry/name, no tag): the subject
		# of an untrusted-source finding is the repository, so a routine
		# tag bump (ruby:3.2 -> ruby:3.3, still untrusted) must not re-key
		# it. link stays as informational data / trusted-URL matching.
		"imageRepo": _image_repo(job.image),
		"status":    "unauthorized",
	}
}

_is_authorized(img) if {
	pattern := input.config.imageAuthorizedSources.trustedUrls[_]
	glob.match(_normalize_var(pattern), null, _normalize_var(_full_ref(img)))
}

_is_authorized(img) if {
	input.config.imageAuthorizedSources.trustDockerHubOfficial == true
	_is_docker_hub_official(img)
}

# Legacy treats only single-segment names (no slash) as Docker Hub
# official. The collector strips the canonical `library/` prefix
# upstream, so we match that contract literally — a name containing a
# slash is never treated as official.
_is_docker_hub_official(img) if {
	_registry_is_docker_hub(img)
	not contains(img.name, "/")
}

_registry_is_docker_hub(img) if img.registry == "docker.io"

_registry_is_docker_hub(img) if not img.registry

_registry_is_docker_hub(img) if img.registry == ""

# _normalize_var rewrites `${VAR}` references to `$VAR` so user
# patterns and rendered image refs compare equal regardless of which
# notation a pipeline author used. Mirrors the normalizeVarNotation
# helper in controlGitlabImageUntrusted.go.
_normalize_var(s) := regex.replace(s, `\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`, `$$$1`)

# _full_ref builds the canonical `<registry>/<name>:<tag>` string the
# trusted-URL globs in .plumber.yaml are written against. Including
# the tag is essential — patterns like `docker.io/foo/bar:*`
# explicitly carry a colon and the glob would otherwise miss the
# untagged form. The "unknown" registry literal is collapsed to no
# registry (legacy behaviour: imageUrl = image.Name only).
_full_ref(img) := ref if {
	_has_known_registry(img)
	img.tag != ""
	ref := sprintf("%s/%s:%s", [img.registry, img.name, img.tag])
} else := ref if {
	_has_known_registry(img)
	ref := sprintf("%s/%s", [img.registry, img.name])
} else := ref if {
	img.tag != ""
	ref := sprintf("%s:%s", [img.name, img.tag])
} else := img.name

_has_known_registry(img) if {
	img.registry != ""
	img.registry != "unknown"
}

# _image_repo is the tagless, digestless `<registry>/<name>` reference —
# the identity subject for the untrusted-source finding. Mirrors _full_ref
# minus the tag, collapsing an unknown/empty registry to the bare name.
_image_repo(img) := ref if {
	_has_known_registry(img)
	ref := sprintf("%s/%s", [img.registry, img.name])
} else := img.name
