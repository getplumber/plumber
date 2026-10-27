package utils

import (
	"strings"

	"github.com/getplumber/plumber/internal/ir"
)

// SplitGitHubImageRef parses a GitHub Actions image reference (a job's
// `container:`, a `uses: docker://` step without the scheme) into an
// ir.Image, folding Docker Hub registry-host aliases to docker.io. A
// reference with neither tag nor digest gets the tag `latest`, the one
// Docker pulls for it; one still holding a `${{ }}` expression keeps no
// tag, since the value is only known at run time.
func SplitGitHubImageRef(ref string) ir.Image {
	// Fold Docker Hub registry-host aliases (registry.hub.docker.com,
	// index.docker.io, registry-1.docker.io) to docker.io so trustedUrls
	// patterns match regardless of which Hub hostname was used. GitHub refs
	// keep the registry host inside Name, so we normalise the name string.
	ref = FoldDockerHubAliasInName(ref)
	// Digest form takes precedence: "alpine@sha256:..."
	if at := strings.Index(ref, "@"); at > 0 {
		return ir.Image{Name: ref[:at], Digest: ref[at+1:]}
	}
	// The tag colon comes after the last slash: the one in
	// `localhost:5000/app` is a registry port.
	if colon := strings.LastIndex(ref, ":"); colon > 0 && colon > strings.LastIndex(ref, "/") {
		return ir.Image{Name: ref[:colon], Tag: ref[colon+1:]}
	}
	if ref == "" || strings.Contains(ref, "${{") {
		return ir.Image{Name: ref}
	}
	return ir.Image{Name: ref, Tag: "latest"}
}
