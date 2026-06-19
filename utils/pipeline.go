package utils

import (
	"regexp"
	"strings"
)

// digestPinRegex matches an OCI image digest pin: `@<algo>:<hex>`.
// Algorithm is lowercase alphanumeric (sha256, sha512, ...) per the
// OCI image spec. Using a regex instead of `strings.Contains(@sha256:)`
// avoids false negatives on sha512 / future digest algorithms.
var digestPinRegex = regexp.MustCompile(`@[a-z0-9]+:[a-fA-F0-9]+`)

// HasDigestPin reports whether ref contains a digest reference using
// any algorithm allowed by the OCI image spec — sha256 today, sha512
// already in production at some registries, and any future algorithm
// without a code change. Empty refs return false.
func HasDigestPin(ref string) bool {
	if ref == "" {
		return false
	}
	return digestPinRegex.MatchString(ref)
}

// OverriddenJobDetail captures which job was overridden and with which forbidden CI/CD keywords.
// Shared across control (detection) and pbom (reporting) packages.
type OverriddenJobDetail struct {
	JobName        string   `json:"jobName"`
	OverriddenKeys []string `json:"overriddenKeys"`
}

const dockerHubCanonical = "docker.io"

// dockerHubRegistryAliases are alternative hostnames that all resolve to
// Docker Hub. Pipeline authors may write any of them; we fold them to the
// canonical "docker.io" at parse time so trustedUrls patterns match
// regardless of which Hub hostname was used.
var dockerHubRegistryAliases = map[string]string{
	"index.docker.io":         dockerHubCanonical,
	"registry-1.docker.io":    dockerHubCanonical,
	"registry.hub.docker.com": dockerHubCanonical,
}

// CanonicalizeDockerHubRegistry maps any known Docker Hub registry-host
// alias to "docker.io". Non-Hub hosts pass through unchanged.
func CanonicalizeDockerHubRegistry(host string) string {
	if canon, ok := dockerHubRegistryAliases[host]; ok {
		return canon
	}
	return host
}

// FoldDockerHubAliasInName rewrites the leading registry-host segment of an
// image name when that segment is a Docker Hub alias. Names without a leading
// host segment (e.g. bare "alpine") are returned unchanged.
func FoldDockerHubAliasInName(name string) string {
	slash := strings.Index(name, "/")
	if slash <= 0 {
		return name
	}
	host := name[:slash]
	if canon, ok := dockerHubRegistryAliases[host]; ok {
		return canon + name[slash:]
	}
	return name
}

// CleanOriginPath normalizes a GitLab include/component path by stripping
// the version suffix and instance URL prefix, producing a bare path suitable
// for comparison (e.g. "components/sast/sast").
func CleanOriginPath(location string) string {
	if idx := strings.LastIndex(location, "@"); idx != -1 {
		location = location[:idx]
	}
	location = strings.TrimPrefix(location, "$CI_SERVER_FQDN/")
	location = strings.TrimPrefix(location, "$CI_SERVER_HOST/")
	if idx := strings.Index(location, "/"); idx != -1 {
		parts := strings.SplitN(location, "/", 2)
		if len(parts) == 2 && strings.Contains(parts[0], ".") {
			location = parts[1]
		}
	}
	return location
}
