package expr

import "strings"

// node is the sealed interface implemented by every AST node this
// package produces. It has no methods a caller would ever call; it only
// restricts which types can appear in the tree.
type node interface {
	astNode()
}

type nodeAnd struct{ left, right node }

func (nodeAnd) astNode() {}

type nodeOr struct{ left, right node }

func (nodeOr) astNode() {}

type nodeNot struct{ x node }

func (nodeNot) astNode() {}

// nodeEq is both "==" (neq false) and "!=" (neq true).
type nodeEq struct {
	left, right node
	neq         bool
}

func (nodeEq) astNode() {}

type nodeCall struct {
	name string
	args []node
}

func (nodeCall) astNode() {}

type nodeStrLit struct{ val string }

func (nodeStrLit) astNode() {}

type nodeBoolLit struct{ val bool }

func (nodeBoolLit) astNode() {}

type nodeRef struct{ ref string }

func (nodeRef) astNode() {}

// nodeUnknown stands for anything the grammar does not cover: a parse
// failure never surfaces as an error, it surfaces as this leaf, which
// evaluates to Unknown. Isolation happens per operand (see
// parseAndOperand), so one unsupported fragment inside a larger && or
// || does not blank out the operands around it; parse's own top-level
// recover stays as a last-resort net for what per-operand isolation
// cannot localize, such as a genuinely unbalanced parenthesis.
type nodeUnknown struct{}

func (nodeUnknown) astNode() {}

// stripWrapper trims surrounding whitespace and, when present, the
// "${{ ... }}" wrapper GitHub Actions expressions are usually written
// inside.
func stripWrapper(expression string) string {
	s := strings.TrimSpace(expression)
	const open, close = "${{", "}}"
	if strings.HasPrefix(s, open) && strings.HasSuffix(s, close) {
		s = strings.TrimSpace(s[len(open) : len(s)-len(close)])
	}
	return s
}

// tokenKind enumerates the lexical categories the tokenizer produces.
type tokenKind int

const (
	tEOF tokenKind = iota
	tLParen
	tRParen
	tComma
	tAnd
	tOr
	tNot
	tEq
	tNeq
	tString
	tIdent
	// tGarbage marks input the tokenizer could not classify (a stray
	// '=', an unterminated string, ...). It never panics the lexer;
	// it just guarantees the parser will fail to build a known node
	// around it, which parseAndOperand (or, failing that, parse's
	// top-level recover) turns into nodeUnknown.
	tGarbage
)

type token struct {
	kind tokenKind
	text string
}

// lex tokenizes s. It always terminates and always appends a trailing
// tEOF token; it never panics, even on malformed input.
func lex(s string) []token {
	var toks []token
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{kind: tLParen})
			i++
		case c == ')':
			toks = append(toks, token{kind: tRParen})
			i++
		case c == ',':
			toks = append(toks, token{kind: tComma})
			i++
		case c == '&':
			if i+1 < n && s[i+1] == '&' {
				toks = append(toks, token{kind: tAnd})
				i += 2
			} else {
				toks = append(toks, token{kind: tGarbage})
				i++
			}
		case c == '|':
			if i+1 < n && s[i+1] == '|' {
				toks = append(toks, token{kind: tOr})
				i += 2
			} else {
				toks = append(toks, token{kind: tGarbage})
				i++
			}
		case c == '!':
			if i+1 < n && s[i+1] == '=' {
				toks = append(toks, token{kind: tNeq})
				i += 2
			} else {
				toks = append(toks, token{kind: tNot})
				i++
			}
		case c == '=':
			if i+1 < n && s[i+1] == '=' {
				toks = append(toks, token{kind: tEq})
				i += 2
			} else {
				toks = append(toks, token{kind: tGarbage})
				i++
			}
		case c == '\'':
			j := i + 1
			for j < n && s[j] != '\'' {
				j++
			}
			if j < n {
				toks = append(toks, token{kind: tString, text: s[i+1 : j]})
				i = j + 1
			} else {
				// Unterminated string literal: there is nothing more to
				// read, so stop here rather than scanning forever.
				toks = append(toks, token{kind: tGarbage})
				i = n
			}
		case isIdentStart(c):
			j := i
			for j < n && isIdentPart(s[j]) {
				j++
			}
			toks = append(toks, token{kind: tIdent, text: s[i:j]})
			i = j
		default:
			toks = append(toks, token{kind: tGarbage})
			i++
		}
	}
	toks = append(toks, token{kind: tEOF})
	return toks
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isIdentPart allows the characters that show up inside a dotted
// reference: letters, digits, underscore, the dot that separates
// segments, the '*' of a ".*.name" collection reference, and the hyphen
// that job and step ids are often written with.
func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '*' || c == '-' // '-': job and step ids
}

// parseFail is the sentinel panic value every parsing method raises on
// unexpected input. parse recovers it at the top and turns it into
// nodeUnknown, so a malformed expression never panics the caller.
type parseFail struct{}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token {
	return p.toks[p.pos]
}

func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) expect(k tokenKind) token {
	t := p.next()
	if t.kind != k {
		panic(parseFail{})
	}
	return t
}

// parse builds the AST for expression. It never panics: any failure
// inside the recursive-descent methods below is recovered here and
// reported as nodeUnknown instead.
func parse(expression string) (result node) {
	defer func() {
		if recover() != nil {
			result = nodeUnknown{}
		}
	}()
	p := &parser{toks: lex(expression)}
	n := p.parseOr()
	if p.peek().kind != tEOF {
		// Trailing tokens after a complete expression: the input is
		// not well-formed even though a prefix of it parsed.
		panic(parseFail{})
	}
	return n
}

func (p *parser) parseOr() node {
	left := p.parseAnd()
	for p.peek().kind == tOr {
		p.next()
		right := p.parseAnd()
		left = nodeOr{left: left, right: right}
	}
	return left
}

func (p *parser) parseAnd() node {
	left := p.parseAndOperand()
	for p.peek().kind == tAnd {
		p.next()
		right := p.parseAndOperand()
		left = nodeAnd{left: left, right: right}
	}
	return left
}

// parseAndOperand parses one operand of && (and, by composition through
// parseAnd, one operand of || too, since an || operand is always a
// parseAnd chain that starts here): a single unary term that must be
// followed by &&, ||, ')', or the end of input. Anything that fails to
// parse, or that parses cleanly but leaves unexpected trailing tokens
// before the next such boundary (a call followed by unsupported member
// access, a stray token glued to a reference, ...), becomes nodeUnknown
// for that operand alone. This is what makes "anything else parses as
// an unknown leaf" apply per operand rather than per expression: a real
// if: condition often mixes a supported github.*/needs.* comparison
// with something this grammar does not model (fromJSON(...),
// format(...), a numeric comparison), and the supported half must keep
// deciding.
func (p *parser) parseAndOperand() node {
	n := p.safely(p.parseUnary)
	if !isOperandFollower(p.peek().kind) {
		p.resyncOperand()
		return nodeUnknown{}
	}
	return n
}

// isOperandFollower reports whether kind can legally follow a complete
// operand: the next binary operator, a closing parenthesis, or the end
// of input.
func isOperandFollower(kind tokenKind) bool {
	switch kind {
	case tAnd, tOr, tRParen, tEOF:
		return true
	default:
		return false
	}
}

// resyncOperand skips past whatever is left of a failed or over-long
// operand, stopping just before the next && or || at this nesting
// depth, or just before a ')' that would close a group opened before
// this operand started (left for that group's own caller to consume),
// or at the end of input. It always terminates: every step other than
// the three stopping cases consumes a token.
func (p *parser) resyncOperand() {
	depth := 0
	for {
		switch t := p.peek(); t.kind {
		case tEOF:
			return
		case tAnd, tOr:
			if depth == 0 {
				return
			}
			p.next()
		case tLParen:
			depth++
			p.next()
		case tRParen:
			if depth == 0 {
				return
			}
			depth--
			p.next()
		default:
			p.next()
		}
	}
}

// safely runs fn and turns a parse panic into nodeUnknown instead of
// letting it propagate. parse's own top-level recover remains as the
// final net for whatever this narrower recovery cannot localize to a
// single operand, such as an unbalanced parenthesis with nothing left
// to resync around.
func (p *parser) safely(fn func() node) (result node) {
	defer func() {
		if recover() != nil {
			result = nodeUnknown{}
		}
	}()
	return fn()
}

func (p *parser) parseUnary() node {
	if p.peek().kind == tNot {
		p.next()
		return nodeNot{x: p.parseUnary()}
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() node {
	switch t := p.peek(); t.kind {
	case tLParen:
		p.next()
		inner := p.parseOr()
		p.expect(tRParen)
		return inner
	case tIdent:
		p.next()
		if p.peek().kind == tLParen {
			return p.parseCall(t.text)
		}
		left := identOperand(t.text)
		if p.peek().kind == tEq || p.peek().kind == tNeq {
			neq := p.next().kind == tNeq
			return nodeEq{left: left, right: p.parseOperand(), neq: neq}
		}
		return left
	case tString:
		p.next()
		left := nodeStrLit{val: t.text}
		if p.peek().kind == tEq || p.peek().kind == tNeq {
			neq := p.next().kind == tNeq
			return nodeEq{left: left, right: p.parseOperand(), neq: neq}
		}
		return left
	default:
		panic(parseFail{})
	}
}

func (p *parser) parseCall(name string) node {
	p.expect(tLParen)
	var args []node
	if p.peek().kind != tRParen {
		args = append(args, p.parseOperand())
		for p.peek().kind == tComma {
			p.next()
			args = append(args, p.parseOperand())
		}
	}
	p.expect(tRParen)
	return nodeCall{name: name, args: args}
}

// parseOperand parses a single value: a string literal or a dotted
// reference/boolean literal. It is used for the right-hand side of a
// comparison and for function arguments, neither of which allows a
// nested boolean expression.
func (p *parser) parseOperand() node {
	t := p.next()
	switch t.kind {
	case tString:
		return nodeStrLit{val: t.text}
	case tIdent:
		return identOperand(t.text)
	default:
		panic(parseFail{})
	}
}

// identOperand turns raw identifier text into the boolean literal it
// names, or otherwise into a reference leaf.
func identOperand(name string) node {
	if strings.EqualFold(name, "true") {
		return nodeBoolLit{val: true}
	}
	if strings.EqualFold(name, "false") {
		return nodeBoolLit{val: false}
	}
	return nodeRef{ref: name}
}
