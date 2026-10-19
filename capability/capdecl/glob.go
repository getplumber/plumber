package capdecl

import (
	"errors"
	"unicode/utf8"
)

// Glob is one compiled capability pattern (spec 4.3): `*` matches any run of characters, a
// `/` included; `?` exactly one character; `[...]` one character of a class with ranges
// (`[a-z]`), negated by a leading `!` or `^`, a `]` first in the class (after the negation)
// being a literal; `\x` the character x; every other character itself. Matching is
// case-sensitive and on the whole subject. A character is a rune: subject and pattern are
// read as UTF-8 throughout.
//
// The matcher is the iterative wildcard algorithm with one remembered star (on a mismatch,
// resume one character further past the last star), with no recursion: a match costs at
// most len(subject) * len(pattern) steps whatever the pattern. A pattern is the user's and a
// subject any developer's script line, so a backtracking matcher (exponential on patterns
// such as `*b*a*a*`) would let a pattern and a line hang the run.
type Glob struct {
	tokens []globToken
}

// globKind is the kind of one pattern token.
type globKind uint8

const (
	globLiteral globKind = iota
	globAnyOne
	globStar
	globClass
)

// globToken is one pattern element: a literal rune, `?`, `*`, or a class.
type globToken struct {
	kind   globKind
	r      rune
	negate bool
	ranges []runeRange
}

// runeRange is one class item, lo to hi inclusive (a single rune has lo == hi).
type runeRange struct{ lo, hi rune }

// The two syntax errors. They are the same two cases the platform's own syntax check
// refuses at PUT, so a pattern the platform accepted always compiles here, and one from
// .plumber.yaml is judged by the same rule: keep the two in step.
var (
	errUnclosedClass     = errors.New("unclosed character class")
	errTrailingBackslash = errors.New("trailing backslash")
)

// CompileGlob compiles pattern, refusing an unclosed class (`[abc`, `[]`, `[!]`) and a
// trailing backslash. Inside a class a backslash is a literal: the class runs to the first
// `]` after its optional negation and optional leading `]`, exactly as ValidGlob scans it.
func CompileGlob(pattern string) (*Glob, error) {
	g := &Glob{}
	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			// Consecutive stars are one star.
			if n := len(g.tokens); n == 0 || g.tokens[n-1].kind != globStar {
				g.tokens = append(g.tokens, globToken{kind: globStar})
			}
			i++
		case '?':
			g.tokens = append(g.tokens, globToken{kind: globAnyOne})
			i++
		case '\\':
			if i+1 >= len(pattern) {
				return nil, errTrailingBackslash
			}
			r, size := utf8.DecodeRuneInString(pattern[i+1:])
			g.tokens = append(g.tokens, globToken{kind: globLiteral, r: r})
			i += 1 + size
		case '[':
			tok, next, err := compileClass(pattern, i)
			if err != nil {
				return nil, err
			}
			g.tokens = append(g.tokens, tok)
			i = next
		default:
			r, size := utf8.DecodeRuneInString(pattern[i:])
			g.tokens = append(g.tokens, globToken{kind: globLiteral, r: r})
			i += size
		}
	}
	return g, nil
}

// compileClass compiles the class opening at pattern[open] (a `[`) and returns it with the
// index just past its closing `]`.
func compileClass(pattern string, open int) (globToken, int, error) {
	tok := globToken{kind: globClass}
	j := open + 1
	if j < len(pattern) && (pattern[j] == '!' || pattern[j] == '^') {
		tok.negate = true
		j++
	}
	start := j
	if j < len(pattern) && pattern[j] == ']' {
		j++
	}
	for j < len(pattern) && pattern[j] != ']' {
		j++
	}
	if j >= len(pattern) {
		return globToken{}, 0, errUnclosedClass
	}
	body := []rune(pattern[start:j])
	for k := 0; k < len(body); k++ {
		lo := body[k]
		// `a-z` is a range; a `-` first or last in the class is a literal.
		if k+2 < len(body) && body[k+1] == '-' {
			tok.ranges = append(tok.ranges, runeRange{lo, body[k+2]})
			k += 2
			continue
		}
		tok.ranges = append(tok.ranges, runeRange{lo, lo})
	}
	return tok, j + 1, nil
}

// matches reports whether one non-star token matches the rune r.
func (t *globToken) matches(r rune) bool {
	switch t.kind {
	case globLiteral:
		return r == t.r
	case globAnyOne:
		return true
	case globClass:
		in := false
		for _, rg := range t.ranges {
			if rg.lo <= r && r <= rg.hi {
				in = true
				break
			}
		}
		return in != t.negate
	}
	return false
}

// Match reports whether the whole subject matches the pattern.
func (g *Glob) Match(subject string) bool {
	toks := g.tokens
	pi, si := 0, 0
	star, starSi := -1, 0
	for si < len(subject) {
		if pi < len(toks) && toks[pi].kind == globStar {
			star, starSi = pi, si
			pi++
			continue
		}
		r, size := utf8.DecodeRuneInString(subject[si:])
		if pi < len(toks) && toks[pi].matches(r) {
			pi++
			si += size
			continue
		}
		if star < 0 {
			return false
		}
		// The last star absorbs one more character and the rest of the pattern is tried
		// again from there.
		_, skip := utf8.DecodeRuneInString(subject[starSi:])
		starSi += skip
		si = starSi
		pi = star + 1
	}
	for pi < len(toks) && toks[pi].kind == globStar {
		pi++
	}
	return pi == len(toks)
}
