package utils

import (
	"regexp"
	"strings"

	"github.com/gobwas/glob"
)

// braceVarRegex matches a `${VAR}` reference so it can be folded to `$VAR`,
// the same normalization image_authorized_sources.rego applies before it
// matches a trustedUrls pattern.
var braceVarRegex = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// CanonicalImageRepo returns the tagless, digestless repository of an image
// in one spelling per image, so an exemption pattern matches it whichever
// collector parsed it. The GitHub collector leaves the registry empty and
// the host inside the name (`debian`, `ghcr.io/org/tool`); the GitLab one
// splits the host out (`docker.io` + `debian`) and emits "unknown" for a
// reference it could not resolve. Docker Hub images all end up as
// `docker.io/<namespace>/<name>`, with the implicit `library` namespace
// written out.
//
// policies/image_mutable_tag.rego and policies/image_pinned_by_digest.rego
// implement the same function as _canonical_repo; the two must stay in step.
func CanonicalImageRepo(registry, name string) string {
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	repo := name
	if registry != "" && registry != "unknown" {
		repo = registry + "/" + name
	}
	repo = braceVarRegex.ReplaceAllString(repo, `$$$1`)
	if repo == "" {
		return ""
	}
	repo = FoldDockerHubAliasInName(repo)
	first, _, hasSlash := strings.Cut(repo, "/")
	if !hasSlash || !isRegistryHost(first) {
		repo = dockerHubCanonical + "/" + repo
	}
	if rest, ok := strings.CutPrefix(repo, dockerHubCanonical+"/"); ok && !strings.Contains(rest, "/") {
		repo = dockerHubCanonical + "/library/" + rest
	}
	return repo
}

// isRegistryHost reports whether the first segment of an image reference
// names a registry rather than a Docker Hub namespace, following the
// Docker rule (a dot, a port, or localhost). A `$VARIABLE` segment is kept
// as written: it stands for a host the run did not know.
func isRegistryHost(segment string) bool {
	return strings.ContainsAny(segment, ".:$") || segment == "localhost"
}

// canonicalExemptPattern brings a pattern into the spelling
// CanonicalImageRepo produces. A pattern whose first segment is a glob is
// matched as written: it already spans hosts, and prefixing it would pin it
// to Docker Hub.
func canonicalExemptPattern(pattern string) string {
	pattern = braceVarRegex.ReplaceAllString(pattern, `$$$1`)
	first, _, _ := strings.Cut(pattern, "/")
	if strings.ContainsAny(first, "*?[{") {
		return pattern
	}
	return CanonicalImageRepo("", pattern)
}

// ImageExempt reports whether containerImageMustNotUseForbiddenTags exempts
// the image: its repository matches one of the exemptImages patterns AND its
// tag is one of the forbidden tags. The same image on any other tag is judged
// as usual. Patterns use the glob syntax of trustedUrls (OPA glob.match with
// no delimiters, so `*` spans `/` and `.`); a pattern that does not compile
// exempts nothing, as it matches nothing in rego either.
func ImageExempt(patterns, forbiddenTags []string, registry, name, tag string) bool {
	if len(patterns) == 0 {
		return false
	}
	name, tag = exemptionNameTag(name, tag)
	if !TagForbidden(forbiddenTags, tag) {
		return false
	}
	repo := CanonicalImageRepo(registry, name)
	if repo == "" {
		return false
	}
	for _, p := range patterns {
		if globMatch(canonicalExemptPattern(p), repo) {
			return true
		}
	}
	return false
}

// exemptionNameTag recovers the name and the tag of a reference that carries
// a digest, which neither collector splits cleanly: GitLab leaves `@<algo>`
// in the name (`python@sha256`, no tag) or in the tag (`latest@sha256`),
// GitHub leaves the tag in the name (`report-tool:latest`, empty tag). The
// digest itself plays no part in an exemption.
func exemptionNameTag(name, tag string) (string, string) {
	if before, _, ok := strings.Cut(name, "@"); ok {
		return before, ""
	}
	if before, _, ok := strings.Cut(tag, "@"); ok {
		return name, before
	}
	if tag == "" {
		if colon := strings.LastIndexByte(name, ':'); colon > strings.LastIndexByte(name, '/') {
			return name[:colon], name[colon+1:]
		}
	}
	return name, tag
}

// TagForbidden reports whether tag matches one of the forbidden tag
// patterns, with the glob.match semantics image_mutable_tag.rego applies.
func TagForbidden(patterns []string, tag string) bool {
	if tag == "" {
		return false
	}
	for _, p := range patterns {
		if globMatch(p, tag) {
			return true
		}
	}
	return false
}

func globMatch(pattern, s string) bool {
	g, err := glob.Compile(pattern)
	if err != nil {
		return false
	}
	return g.Match(s)
}
