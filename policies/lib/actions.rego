# Package lib.actions compares GitHub Actions `uses:` references by owner and
# repository without regard to case, matching GitHub's own resolution rules,
# while keeping any subpath after the repository and the `@ref` case-sensitive.
package lib.actions

import rego.v1

# canonical_name lowers the owner and repository segments of a `uses:` value
# (or bare `owner/repo[/subpath]` name) and preserves any trailing subpath.
canonical_name(uses) := concat("/", array.concat([lower(parts[0]), lower(parts[1])], array.slice(parts, 2, count(parts)))) if {
	spec := split(uses, "@")[0]
	parts := split(spec, "/")
	count(parts) >= 2
}

# matches reports whether `uses` (with an `@ref` suffix) targets `name`
# (`owner/repo` or `owner/repo/subpath`), comparing owner and repository
# case-insensitively and any subpath case-sensitively.
matches(uses, name) if {
	contains(uses, "@")
	canonical_name(uses) == canonical_name(name)
}

# matches_any_ref behaves like matches but also matches bare `owner/repo`
# references without an `@ref` suffix.
matches_any_ref(uses, name) if {
	canonical_name(uses) == canonical_name(name)
}
