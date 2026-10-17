package expr

// ComparedLiteral is the string literal the first of refs (any of them)
// is compared against in expression, read off that very comparison node:
// `ref == 'x'`, `'x' == ref`, `ref != 'x'`, or a contains / startsWith /
// endsWith call whose first argument is the reference and whose second is
// the literal. ok is false when no reference of refs is compared to a
// literal (compared to another reference, or not compared at all).
func ComparedLiteral(expression string, refs []string) (string, bool) {
	expression = stripWrapper(expression)
	if isBlank(expression) {
		return "", false
	}
	want := make(map[string]bool, len(refs))
	for _, r := range refs {
		want[r] = true
	}
	return comparedLiteral(parse(expression), want)
}

// ComparedLiterals is every string literal any of refs is compared
// against in expression, in source order, read off the same comparison
// shapes as ComparedLiteral. Empty when none is.
func ComparedLiterals(expression string, refs []string) []string {
	var out []string
	for _, c := range Comparisons(expression, refs) {
		out = append(out, c.Literal)
	}
	return out
}

// Comparison is one comparison of a reference to a string literal:
// Negated when the condition holds with the two different (`!=`, or an
// odd number of `!` around it), not when it holds with them equal (`==`,
// a contains / startsWith / endsWith call).
type Comparison struct {
	Literal string
	Negated bool
}

// Comparisons is every comparison of any of refs to a string literal in
// expression, in source order, read off the same shapes as
// ComparedLiteral, with its polarity.
func Comparisons(expression string, refs []string) []Comparison {
	expression = stripWrapper(expression)
	if isBlank(expression) {
		return nil
	}
	want := make(map[string]bool, len(refs))
	for _, r := range refs {
		want[r] = true
	}
	var out []Comparison
	comparisons(parse(expression), want, false, &out)
	return out
}

func comparisons(n node, refs map[string]bool, negated bool, out *[]Comparison) {
	switch v := n.(type) {
	case nodeAnd:
		comparisons(v.left, refs, negated, out)
		comparisons(v.right, refs, negated, out)
	case nodeOr:
		comparisons(v.left, refs, negated, out)
		comparisons(v.right, refs, negated, out)
	case nodeNot:
		comparisons(v.x, refs, !negated, out)
	case nodeEq:
		if s, ok := comparedLiteral(v, refs); ok {
			*out = append(*out, Comparison{Literal: s, Negated: negated != v.neq})
		}
	case nodeCall:
		if s, ok := comparedLiteral(v, refs); ok {
			*out = append(*out, Comparison{Literal: s, Negated: negated})
		}
	}
}

func comparedLiteral(n node, refs map[string]bool) (string, bool) {
	switch v := n.(type) {
	case nodeAnd:
		if s, ok := comparedLiteral(v.left, refs); ok {
			return s, true
		}
		return comparedLiteral(v.right, refs)
	case nodeOr:
		if s, ok := comparedLiteral(v.left, refs); ok {
			return s, true
		}
		return comparedLiteral(v.right, refs)
	case nodeNot:
		return comparedLiteral(v.x, refs)
	case nodeEq:
		if s, ok := refAgainstLiteral(v.left, v.right, refs); ok {
			return s, true
		}
		return refAgainstLiteral(v.right, v.left, refs)
	case nodeCall:
		if len(v.args) == 2 {
			return refAgainstLiteral(v.args[0], v.args[1], refs)
		}
	}
	return "", false
}

// refAgainstLiteral is lit's value when ref is one of refs and lit a
// string literal.
func refAgainstLiteral(ref, lit node, refs map[string]bool) (string, bool) {
	r, isRef := ref.(nodeRef)
	l, isLit := lit.(nodeStrLit)
	if !isRef || !isLit || !refs[r.ref] {
		return "", false
	}
	return l.val, true
}
