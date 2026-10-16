package control

import (
	"regexp"
	"strings"
)

// partClass is the kind of one token of a cache key template: a plain
// literal text token with no narrower semantic slot, or one of the
// semantic slots a caching action's key is known to carry (os, arch,
// version, a lockfile hash, a buildx scope, a rust-cache job id, or an
// unrecognised expression, "any").
type partClass string

const (
	partLiteral partClass = "literal"
	partOS      partClass = "os"
	partArch    partClass = "arch"
	partVersion partClass = "version"
	partHash    partClass = "hash"
	partScope   partClass = "scope"
	partJob     partClass = "job"
	partAny     partClass = "any"
)

// keyPart is one token of a key template, in order: Open is true when
// this slot's run-time value could not be resolved to one concrete
// string (an expression, a matrix placeholder, a hash, or a
// discriminator this program never reads a value for at all); Literal
// then carries no meaning. Open parts and the slots that are always open
// (hash, any) match anything; two resolved parts compare by Literal.
type keyPart struct {
	class   partClass
	open    bool
	literal string
}

// literalPart is a resolved, plain literal token: generic key text this
// file split out of a YAML key (actions/cache), or a fixed marker word
// a known action's key always carries ("python", "go"). Compared by
// exact text.
func literalPart(s string) keyPart { return keyPart{class: partLiteral, literal: s} }

// classPart is an open placeholder of class c: this program never has a
// concrete value for it (hash, an unrecognised expression) or could not
// resolve one this time.
func classPart(c partClass) keyPart { return keyPart{class: c, open: true} }

// resolvedPart is a semantic slot (os, arch, version, a rust-cache job
// id) this program resolved to the concrete value v.
func resolvedPart(c partClass, v string) keyPart { return keyPart{class: c, literal: v} }

// literalOrClass is resolvedPart(c, v) when v is non-empty, classPart(c)
// (open) otherwise: a discriminator this program could not resolve
// stays open, never a guessed literal.
func literalOrClass(v string, c partClass) keyPart {
	if v == "" {
		return classPart(c)
	}
	return resolvedPart(c, v)
}

// matches reports whether two parts, one from each side of a save/restore
// pair, can describe the same run-time key. Either side open (an
// unresolved expression, a matrix placeholder, a hash this program never
// has a static value for, or a discriminator it simply could not read)
// matches anything at all, whatever semantic class it nominally carries
// or the other side's: GitHub fills the open side in at run time to
// whatever that run's own value is, and this program does not assert the
// two differ (or agree) without evidence. Two resolved parts compare by
// their literal text, case-insensitively for an os or an arch slot
// (GitHub's own `runner.os`/`runner.arch` values and this program's
// resolved runs-on labels are not guaranteed the same case), case
// sensitively otherwise (a package manager name, a language marker word,
// a buildx scope: different case is a different value there).
func (p keyPart) matches(o keyPart) bool {
	if p.open || o.open {
		return true
	}
	if p.class == partOS || p.class == partArch || o.class == partOS || o.class == partArch {
		return strings.EqualFold(p.literal, o.literal)
	}
	return p.literal == o.literal
}

// keyTemplate is the parsed shape of one cache key: a family that names
// the cache's domain (compared only when both templates open on a
// resolved literal; an open first part means the family itself could be
// anything, so the check is skipped rather than compared against a
// fallback name), the ordered parts that discriminate one run's key from
// another's, and whether the template is a restore-keys prefix (matches
// the start of a longer key, never requires the whole of it). Unknown is
// true for an action this file does not parse into a template at all:
// such a key is never ruled out, only left unproven (control/cachewriters.go
// reads Unknown to carry that state forward).
type keyTemplate struct {
	family  string
	parts   []keyPart
	prefix  bool
	unknown bool
}

// openFamily reports whether t's family could be anything: it has no
// parts, or its first part is open.
func openFamily(t keyTemplate) bool {
	return len(t.parts) == 0 || t.parts[0].open
}

// Matches reports whether a's key and b's key can be the same string at
// run time. An unknown template on either side matches unconditionally:
// this file has nothing to exclude it with, and excluding it without
// evidence is exactly the guess this program refuses to make. Otherwise,
// unless either side's family is itself open (openFamily), the families
// must agree; every part up to the shorter template's length must match
// (keyPart.matches), except at the boundary where the lengths differ and
// the shorter template is a restore-keys prefix: a prefix does not
// necessarily end on a "-" boundary (a restore-keys value of "node-v"
// must still match a saved key "node-v20-<hash>"), so there the longer
// side's same-position literal only needs to start with the shorter
// side's, not equal it. Two templates that are both exact (neither a
// prefix) must also agree on length, so a literal remainder on the
// longer one (a different cache that merely shares a prefix) never
// matches.
func (a keyTemplate) Matches(b keyTemplate) bool {
	if a.unknown || b.unknown {
		return true
	}
	if !openFamily(a) && !openFamily(b) && a.family != b.family {
		return false
	}
	n := len(a.parts)
	if len(b.parts) < n {
		n = len(b.parts)
	}
	for i := 0; i < n; i++ {
		ap, bp := a.parts[i], b.parts[i]
		if i == n-1 && len(a.parts) != len(b.parts) {
			if shorterIsPrefixBoundary(a, b, ap, bp) {
				continue
			}
		}
		if !ap.matches(bp) {
			return false
		}
	}
	if !a.prefix && !b.prefix && len(a.parts) != len(b.parts) {
		return false
	}
	return true
}

// shorterIsPrefixBoundary reports whether the comparison at the last
// overlapping position is a restore-keys string-prefix check rather than
// an ordinary part match: the shorter template (fewer parts) is marked
// prefix and both the boundary parts are resolved literals, in which
// case the longer side's literal must start with the shorter side's
// (case-insensitively, the same rule a literal match itself would apply
// if the two were the same semantic class; restore-keys text is plain,
// so this stays a simple, case-sensitive prefix test). false when the
// boundary does not describe that shape at all, so the caller falls back
// to an ordinary keyPart.matches call.
func shorterIsPrefixBoundary(a, b keyTemplate, ap, bp keyPart) bool {
	switch {
	case len(a.parts) < len(b.parts) && a.prefix:
		return !ap.open && !bp.open && strings.HasPrefix(bp.literal, ap.literal)
	case len(b.parts) < len(a.parts) && b.prefix:
		return !ap.open && !bp.open && strings.HasPrefix(ap.literal, bp.literal)
	}
	return false
}

// cacheExprPattern finds one `${{ ... }}` expression in an actions/cache
// key; the text it captures is matched by class below.
var cacheExprPattern = regexp.MustCompile(`\$\{\{\s*([^}]*?)\s*\}\}`)

// cacheKeyTemplate parses c into the template its save or restore
// matches against: the known shape of the caching action c.Uses names, or
// an unknown template for an action this file does not read into. job is
// accepted for the shapes whose real key depends on something the job
// carries (none currently resolve one; kept for a future shape rather
// than changing this signature again).
func cacheKeyTemplate(c CacheFact, _ JobSituation) keyTemplate {
	name, _, _ := strings.Cut(strings.ToLower(c.Uses), "@")
	name = strings.TrimSuffix(name, "/")
	switch name {
	case "actions/cache", "actions/cache/restore", "actions/cache/save":
		return actionsCacheKeyTemplate(c)
	case "actions/setup-node":
		return keyTemplate{family: "node-cache", prefix: c.Prefix, parts: []keyPart{
			osPart(c), archPart(c), managerPart(c, "setup-node"), classPart(partHash),
		}}
	case "actions/setup-python":
		return keyTemplate{family: "setup-python", prefix: c.Prefix, parts: []keyPart{
			osPart(c), archPart(c), literalPart("python"), versionPart(c), managerPart(c, "setup-python"), classPart(partHash),
		}}
	case "actions/setup-go":
		return keyTemplate{family: "setup-go", prefix: c.Prefix, parts: []keyPart{
			osPart(c), archPart(c), literalPart("go"), versionPart(c), classPart(partHash),
		}}
	case "actions/setup-uv":
		return keyTemplate{family: "setup-uv", prefix: c.Prefix, parts: []keyPart{
			classPart(partAny), osPart(c), archPart(c), versionPart(c), classPart(partHash),
		}}
	case "swatinem/rust-cache":
		return rustCacheKeyTemplate(c)
	case "docker/build-push-action":
		return buildxKeyTemplate(c)
	}
	return keyTemplate{unknown: true}
}

// actionsCacheKeyTemplate parses an actions/cache (or /restore, /save)
// literal key into its template: the family is the key's first literal
// token (before any expression), left to openFamily to skip the family
// check entirely when the key opens on an expression instead, parts are
// then compared one by one.
func actionsCacheKeyTemplate(c CacheFact) keyTemplate {
	parts := parseCacheKeyParts(c.Key)
	family := ""
	if len(parts) > 0 && !parts[0].open {
		family = parts[0].literal
	}
	return keyTemplate{family: family, parts: parts, prefix: c.Prefix}
}

// parseCacheKeyParts splits an actions/cache key (or a restore-keys
// prefix) into its literal and placeholder parts: the key's text between
// `${{ ... }}` expressions, split on "-", each token its own literal
// part; `${{ runner.os }}` an os part, `${{ runner.arch }}` an arch part,
// any expression that calls hashFiles(...) a hash part, any other
// expression an any part.
func parseCacheKeyParts(key string) []keyPart {
	var parts []keyPart
	last := 0
	for _, m := range cacheExprPattern.FindAllStringSubmatchIndex(key, -1) {
		parts = append(parts, literalSegments(key[last:m[0]])...)
		parts = append(parts, exprPart(strings.TrimSpace(key[m[2]:m[3]])))
		last = m[1]
	}
	parts = append(parts, literalSegments(key[last:])...)
	return parts
}

// literalSegments splits plain (non-expression) key text on "-" into one
// literal part per non-empty token.
func literalSegments(s string) []keyPart {
	var out []keyPart
	for _, tok := range strings.Split(s, "-") {
		if tok == "" {
			continue
		}
		out = append(out, literalPart(tok))
	}
	return out
}

// exprPart classifies the body of one `${{ ... }}` expression.
func exprPart(body string) keyPart {
	switch {
	case body == "runner.os":
		return classPart(partOS)
	case body == "runner.arch":
		return classPart(partArch)
	case strings.Contains(body, "hashFiles("):
		return classPart(partHash)
	default:
		return classPart(partAny)
	}
}

// osPart, archPart read the concrete value this program resolved for a
// setup-* action's key (c.Parts), an open placeholder of the matching
// class when it did not.
func osPart(c CacheFact) keyPart   { return literalOrClass(c.Parts["os"], partOS) }
func archPart(c CacheFact) keyPart { return literalOrClass(c.Parts["arch"], partArch) }

// versionPart reads the version this program resolved (c.Parts), reduced
// to its major.minor precision when it is a plain numeric dotted value,
// the one a setup-* action actually keys its cache on (normalizedVersion):
// open otherwise, so a range, "latest", "stable", "lts/*" or a matrix
// list never becomes a guessed literal.
func versionPart(c CacheFact) keyPart {
	return literalOrClass(normalizedVersion(c.Parts["version"]), partVersion)
}

// versionNumberPattern is a plain dotted numeric version: digits, each
// optionally followed by ".digits" again.
var versionNumberPattern = regexp.MustCompile(`^\d+(\.\d+)*$`)

// normalizedVersion reduces a numeric dotted version to its major.minor
// (1.22.3 -> 1.22; 20 stays 20; 1.22 stays 1.22): the precision setup-*
// actions actually key their cache on, two patch releases of the same
// minor sharing one cache. "" for anything that is not a plain numeric
// dotted value (a range such as "3.11.x" or "3.x", "stable", "latest",
// "lts/*", a multi-line matrix list) or empty: too open to compare, an
// open part rather than a literal.
func normalizedVersion(v string) string {
	v = strings.TrimSpace(v)
	if !versionNumberPattern.MatchString(v) {
		return ""
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) > 2 {
		parts = parts[:2]
	}
	return strings.Join(parts, ".")
}

// managerPart reads the package manager name a setup-* action's key
// carries: c.Parts["manager"] when this program resolved it, else the
// collector's own Key or Family with the action's key prefix (short,
// e.g. "setup-node") stripped, a cache-dependency-path annotation
// trimmed. Either source can still hold an unresolved `${{ ... }}`
// expression (the collector does not filter every shape it builds a key
// string from); such a value is an open placeholder, never a literal
// that happens to contain the text of an expression.
func managerPart(c CacheFact, short string) keyPart {
	if m := c.Parts["manager"]; m != "" {
		return literalOrExpression(m)
	}
	base := c.Family
	if base == "" {
		base = c.Key
	}
	base, _, _ = strings.Cut(base, " (")
	if m, ok := strings.CutPrefix(base, short+"-"); ok && m != "" {
		return literalOrExpression(m)
	}
	return classPart(partAny)
}

// literalOrExpression is literalPart(s) unless s itself still carries a
// `${{ ... }}` expression, in which case it is an open part: a resolved
// value never contains expression syntax, so anything that does was
// never really resolved.
func literalOrExpression(s string) keyPart {
	if strings.Contains(s, "${{") {
		return classPart(partAny)
	}
	return literalPart(s)
}

// rustCacheKeyTemplate treats Swatinem/rust-cache's configured prefix (the
// collector's own Key or Family: the default "v0-rust", or prefix-key
// joined with shared-key/key and the job id) as one token: a literal
// when it holds no expression, an open placeholder when it does (the
// collector embeds prefix-key and shared-key/key as written, filtering
// neither); reads the job id back as its own part when the collector
// resolved one (c.Parts["job"], an open placeholder otherwise: a shared
// cache across jobs, add-job-id-key: false, still matches by prefix
// alone), then appends the os (c.Parts["os"], open otherwise) and hash
// segments the action always appends internally.
func rustCacheKeyTemplate(c CacheFact) keyTemplate {
	base := c.Family
	if base == "" {
		base = c.Key
	}
	var prefix keyPart
	switch {
	case base == "":
		prefix = classPart(partJob)
	case strings.Contains(base, "${{"):
		prefix = classPart(partAny)
	default:
		prefix = literalPart(base)
	}
	job := literalOrClass(c.Parts["job"], partJob)
	return keyTemplate{family: "rust-cache", prefix: true, parts: []keyPart{prefix, job, osPart(c), classPart(partHash)}}
}

// buildxScopePattern reads the gha scope the collector recorded in the
// synthetic key it built (ir.CacheRef via buildxGhaCaches): "<action>
// (scope=<scope>)".
var buildxScopePattern = regexp.MustCompile(`\(scope=([^)]*)\)`)

// buildxKeyTemplate keys a buildx gha cache by its scope alone: two
// backends sharing a scope share a cache, whatever image or target they
// build.
func buildxKeyTemplate(c CacheFact) keyTemplate {
	scope := ""
	if m := buildxScopePattern.FindStringSubmatch(c.Key); len(m) == 2 {
		scope = m[1]
	}
	return keyTemplate{family: "buildx-gha", parts: []keyPart{literalOrClass(scope, partScope)}}
}
