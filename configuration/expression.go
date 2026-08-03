package configuration

import (
	"fmt"
	"strings"
	"unicode"
)

// Expression parser for human-readable boolean requirement expressions.
//
// Syntax:
//   component/a AND component/b         → both must be present
//   component/a OR component/b          → at least one must be present
//   (comp/a AND comp/b) OR comp/c       → grouped with parentheses
//   comp/a AND comp/b OR comp/c         → AND binds tighter: (comp/a AND comp/b) OR comp/c
//
// Grammar (AND has higher precedence than OR):
//   expression = or_expr
//   or_expr    = and_expr (OR and_expr)*
//   and_expr   = atom (AND atom)*
//   atom       = IDENT | LPAREN or_expr RPAREN
//
// The result is converted to DNF (Disjunctive Normal Form): [][]string
// where the outer slice is OR and each inner slice is AND.

// --------------------------------------------------------------------------
// Tokens
// --------------------------------------------------------------------------

type tokenType int

const (
	tokenIdent  tokenType = iota // component path identifier
	tokenAnd                     // AND operator
	tokenOr                      // OR operator
	tokenLParen                  // (
	tokenRParen                  // )
	tokenEOF                     // end of input
)

func (t tokenType) String() string {
	switch t {
	case tokenIdent:
		return "identifier"
	case tokenAnd:
		return "AND"
	case tokenOr:
		return "OR"
	case tokenLParen:
		return "("
	case tokenRParen:
		return ")"
	case tokenEOF:
		return "end of expression"
	}
	return "unknown"
}

type token struct {
	typ tokenType
	val string
	pos int // byte offset in the original expression
}

// --------------------------------------------------------------------------
// Tokenizer
// --------------------------------------------------------------------------

// tokenize splits a requirement expression into tokens.
// Component paths (e.g. "components/sast/sast") are treated as single identifiers.
// AND / OR are case-insensitive keywords.
func tokenize(expr string) ([]token, error) {
	var tokens []token
	runes := []rune(expr)
	i := 0

	for i < len(runes) {
		ch := runes[i]

		// Skip whitespace
		if unicode.IsSpace(ch) {
			i++
			continue
		}

		// Parentheses
		if ch == '(' {
			tokens = append(tokens, token{tokenLParen, "(", i})
			i++
			continue
		}
		if ch == ')' {
			tokens = append(tokens, token{tokenRParen, ")", i})
			i++
			continue
		}

		// Accumulate a word (anything that isn't whitespace or parens)
		start := i
		for i < len(runes) && !unicode.IsSpace(runes[i]) && runes[i] != '(' && runes[i] != ')' {
			i++
		}
		word := string(runes[start:i])

		switch strings.ToUpper(word) {
		case "AND":
			tokens = append(tokens, token{tokenAnd, word, start})
		case "OR":
			tokens = append(tokens, token{tokenOr, word, start})
		default:
			if word == "" {
				return nil, fmt.Errorf("unexpected character at position %d", start)
			}
			tokens = append(tokens, token{tokenIdent, word, start})
		}
	}

	tokens = append(tokens, token{tokenEOF, "", len(runes)})
	return tokens, nil
}

// --------------------------------------------------------------------------
// AST
// --------------------------------------------------------------------------

type exprNode any

type identNode struct {
	name string
}

type andNode struct {
	children []exprNode
}

type orNode struct {
	children []exprNode
}

// --------------------------------------------------------------------------
// Parser
// --------------------------------------------------------------------------

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) current() token {
	if p.pos >= len(p.tokens) {
		return token{tokenEOF, "", -1}
	}
	return p.tokens[p.pos]
}

func (p *parser) advance() token {
	t := p.current()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return t
}

// parseExpression is the entry point: parses a full or_expr.
func (p *parser) parseExpression() (exprNode, error) {
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	return node, nil
}

// parseOr: and_expr (OR and_expr)*
func (p *parser) parseOr() (exprNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	children := []exprNode{left}
	for p.current().typ == tokenOr {
		p.advance() // consume OR
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}

	if len(children) == 1 {
		return children[0], nil
	}
	return &orNode{children: children}, nil
}

// parseAnd: atom (AND atom)*
func (p *parser) parseAnd() (exprNode, error) {
	left, err := p.parseAtom()
	if err != nil {
		return nil, err
	}

	children := []exprNode{left}
	for p.current().typ == tokenAnd {
		p.advance() // consume AND
		right, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}

	if len(children) == 1 {
		return children[0], nil
	}
	return &andNode{children: children}, nil
}

// parseAtom: IDENT | LPAREN or_expr RPAREN
func (p *parser) parseAtom() (exprNode, error) {
	t := p.current()

	switch t.typ {
	case tokenIdent:
		p.advance()
		return &identNode{name: t.val}, nil

	case tokenLParen:
		p.advance() // consume (
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.current().typ != tokenRParen {
			return nil, fmt.Errorf("expected ')' at position %d, got %s", p.current().pos, p.current().typ)
		}
		p.advance() // consume )
		return node, nil

	case tokenEOF:
		return nil, fmt.Errorf("unexpected end of expression")

	case tokenAnd:
		return nil, fmt.Errorf("unexpected AND at position %d (expected a component/template path)", t.pos)

	case tokenOr:
		return nil, fmt.Errorf("unexpected OR at position %d (expected a component/template path)", t.pos)

	case tokenRParen:
		return nil, fmt.Errorf("unexpected ')' at position %d", t.pos)

	default:
		return nil, fmt.Errorf("unexpected token '%s' at position %d", t.val, t.pos)
	}
}

// --------------------------------------------------------------------------
// DNF conversion (AST → [][]string)
// --------------------------------------------------------------------------

// toDNF converts an AST node into Disjunctive Normal Form.
// The result is a slice of AND-clauses (outer = OR, inner = AND).
func toDNF(node exprNode) [][]string {
	switch n := node.(type) {
	case *identNode:
		return [][]string{{n.name}}

	case *orNode:
		// Union of all children's DNF clauses
		var result [][]string
		for _, child := range n.children {
			result = append(result, toDNF(child)...)
		}
		return result

	case *andNode:
		// Cross-product of all children's DNF clauses
		// Start with a single empty clause
		result := [][]string{{}}
		for _, child := range n.children {
			childDNF := toDNF(child)
			var newResult [][]string
			for _, existing := range result {
				for _, childClause := range childDNF {
					combined := make([]string, 0, len(existing)+len(childClause))
					combined = append(combined, existing...)
					combined = append(combined, childClause...)
					newResult = append(newResult, combined)
				}
			}
			result = newResult
		}
		return result
	}
	return nil
}

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

// ParseRequiredExpression parses a human-readable requirement expression
// and returns the equivalent DNF groups ([][]string).
//
// Examples:
//
//	"a AND b"             → [["a", "b"]]
//	"a OR b"              → [["a"], ["b"]]
//	"(a AND b) OR c"      → [["a", "b"], ["c"]]
//	"a AND (b OR c)"      → [["a", "b"], ["a", "c"]]
//	""                    → [] (empty — no requirements)
func ParseRequiredExpression(expr string) ([][]string, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return [][]string{}, nil
	}

	tokens, err := tokenize(expr)
	if err != nil {
		return nil, fmt.Errorf("invalid expression: %w", err)
	}

	p := &parser{tokens: tokens}
	node, err := p.parseExpression()
	if err != nil {
		return nil, fmt.Errorf("invalid expression: %w", err)
	}

	// Ensure all tokens were consumed
	if p.current().typ != tokenEOF {
		t := p.current()
		return nil, fmt.Errorf("invalid expression: unexpected %s '%s' at position %d", t.typ, t.val, t.pos)
	}

	return toDNF(node), nil
}
