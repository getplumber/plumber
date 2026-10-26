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
	some img in _job_images(job)
	# An image reference that still held a `$VARIABLE` when it was parsed
	# describes a placeholder, not an image: registry, name and tag were
	# split out of the literal text. Judging it answers a real question
	# over a guess, so skip that job and keep judging the rest.
	not img.unresolved
	not _image_exempt(img)
	not _image_has_digest(img)
	finding := {
		"code":     "ISSUE-103",
		"severity": "high",
		"message":  sprintf("Job `%s` uses image `%s` without a digest.", [job.name, _image_ref(img)]),
		"job":      job.name,
		"link":     _image_ref(img),
		# Identity keys on imageRepo (registry/name, no tag): the subject
		# is "this image is not pinned by digest", so a routine tag bump
		# (still digestless) must not re-key it. link/tag stay as data.
		"imageRepo": _image_repo(img),
		"tag":       _image_tag(img),
		"line":      object.get(img, "line", 0),
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

# The forbidden tags are those of the forbidden-tag rule (image_mutable_tag),
# read from the same input key.
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
