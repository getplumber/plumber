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
	not _image_exempt(img)
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
		"line":     object.get(img, "line", 0),
	}
}

# _job_images: the job's container images, then the images its own
# `uses: docker://` steps run (stepImages, #571).
_job_images(job) := array.concat(_container_images(job), object.get(job, "stepImages", []))

# _container_images: the images the job's container reference resolves to
# through its matrix literals (matrixImages) when it has them, the image
# as written otherwise.
_container_images(job) := job.matrixImages if {
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

# ---------------------------------------------------------------------------
# exemptImages (issue #506): an image on an exemptImages entry AND on a
# forbidden tag is exempt from both the forbidden-tag and the digest checks;
# the same image on any other tag is judged as usual. Entries are matched on
# registry/name without tag or digest, with the glob syntax of trustedUrls.
# Both sides are brought to one canonical form first so a pattern means the
# same image on either provider: the GitHub collector leaves the registry
# empty (`debian`), the GitLab one splits it out (`docker.io` + `debian`).
# Docker Hub images become `docker.io/<namespace>/<name>` with `library`
# written out.
#
# image_mutable_tag.rego and image_pinned_by_digest.rego carry the same
# helpers, and utils.CanonicalImageRepo / utils.ImageExempt mirror them for
# the stat lines; TestImageExemptParity keeps the three in step.
# ---------------------------------------------------------------------------

_image_exempt(img) if {
	_exempt_tag_forbidden(object.get(img, "tag", ""))
	name := object.get(img, "name", "")
	name != ""
	repo := _canonical_repo(object.get(img, "registry", ""), name)
	some pattern in object.get(input.config, ["containerImageMustNotUseForbiddenTags", "exemptImages"], [])
	glob.match(_canonical_pattern(pattern), null, repo)
}

_exempt_tag_forbidden(tag) if {
	tag != ""
	some pattern in object.get(input.config, ["imageMutableTag", "forbiddenTags"], [])
	glob.match(pattern, null, tag)
}

_canonical_repo(registry, name) := _library_form(_hub_form(_fold_hub_alias(_normalize_var(_joined_repo(registry, split(name, "@")[0])))))

_joined_repo(registry, name) := sprintf("%s/%s", [registry, name]) if {
	registry != ""
	registry != "unknown"
} else := name

_hub_aliases := {"index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"}

_fold_hub_alias(repo) := concat("/", array.concat(["docker.io"], array.slice(parts, 1, count(parts)))) if {
	parts := split(repo, "/")
	count(parts) > 1
	parts[0] in _hub_aliases
} else := repo

# A first segment with a dot, a port or a `$VARIABLE`, or `localhost`, names
# a registry; anything else is a Docker Hub namespace or image.
_hub_form(repo) := repo if {
	parts := split(repo, "/")
	count(parts) > 1
	_is_registry_host(parts[0])
} else := sprintf("docker.io/%s", [repo])

_is_registry_host(segment) if regex.match(`[.:$]`, segment)

_is_registry_host("localhost")

_library_form(repo) := sprintf("docker.io/library/%s", [rest]) if {
	startswith(repo, "docker.io/")
	rest := substring(repo, count("docker.io/"), -1)
	not contains(rest, "/")
} else := repo

# A pattern whose first segment is a glob already spans hosts and is matched
# as written; any other pattern is canonicalized like an image.
_canonical_pattern(pattern) := normalized if {
	normalized := _normalize_var(pattern)
	regex.match(`[*?\[{]`, split(normalized, "/")[0])
} else := _canonical_repo("", pattern)

_normalize_var(s) := regex.replace(s, `\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`, `$$$1`)
