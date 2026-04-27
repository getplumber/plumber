# dockerfile-unpinned-base — flag Dockerfile FROM directives that
# reference a base image without a `@sha256:…` digest. Tags are
# mutable at the registry level: an attacker who compromises the
# registry — or the image maintainer — can re-push the same tag to
# point at a different layer, silently injecting code into every
# later build that pulls the reference. Pinning by digest is the
# single control that neutralises this vector.
#
# The collector scans Dockerfile-shaped files at the repo root and
# under common build directories (up to two levels deep), parsing
# each FROM line and recording whether the reference carries a
# digest. Policy emits one finding per unpinned FROM.
package dockerfile_unpinned_base

import rego.v1

deny contains finding if {
	some i, j
	df := input.pipeline.dockerfiles[i]
	base := df.bases[j]
	not base.pinnedByDigest
	not _is_scratch(base.image)
	not _is_stage_ref(base.image)
	finding := {
		"code":     "ISSUE-107",
		"severity": "medium",
		"message":  sprintf("Dockerfile references base image %q without a @sha256 digest — pin by digest to neutralise registry-side retagging", [base.image]),
		"file":     df.path,
		"line":     base.line,
	}
}

# `FROM scratch` has no registry layer — nothing to pin.
_is_scratch(image) if {
	image == "scratch"
}

# `FROM builder` (alias from a previous build stage) is not an
# external reference; the stage was defined earlier in the same
# Dockerfile. Heuristic: no `/` and no `:` typically means a
# single-token alias, not an image ref.
_is_stage_ref(image) if {
	not contains(image, "/")
	not contains(image, ":")
	not contains(image, "@")
}
