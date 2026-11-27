package ir

import "strings"

// ActionName is the name a `uses:` reference resolves to on GitHub: the
// `@ref` dropped, the owner and repository lower-cased (GitHub resolves
// them without regard to case, so `Actions/Checkout@v4` runs
// actions/checkout), any subpath kept as written. A reference with fewer
// than two segments comes back without its ref, unchanged otherwise. It is
// the Go twin of canonical_name in policies/lib/actions.rego.
func ActionName(uses string) string {
	name, _, _ := strings.Cut(uses, "@")
	parts := strings.SplitN(name, "/", 3)
	if len(parts) < 2 {
		return name
	}
	parts[0], parts[1] = strings.ToLower(parts[0]), strings.ToLower(parts[1])
	return strings.Join(parts, "/")
}
