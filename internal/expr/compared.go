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
