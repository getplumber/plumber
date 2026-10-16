package expr

import "strings"

// evalNode evaluates an AST node against f under three-valued logic.
func evalNode(n node, f Facts) Value {
	switch v := n.(type) {
	case nodeAnd:
		return andVal(evalNode(v.left, f), evalNode(v.right, f))
	case nodeOr:
		return orVal(evalNode(v.left, f), evalNode(v.right, f))
	case nodeNot:
		return notVal(evalNode(v.x, f))
	case nodeEq:
		return evalEq(v, f)
	case nodeCall:
		return evalCall(v, f)
	case nodeBoolLit:
		if v.val {
			return True
		}
		return False
	default:
		// A bare string literal, a bare reference used outside a
		// comparison, or an unparsed leaf carries no boolean meaning
		// of its own.
		return Unknown
	}
}

// andVal is the standard three-valued AND: a known False on either side
// settles it; both sides need to be known True for a True result;
// anything else, including one side being unresolved, is Unknown
// because a condition that requires both halves cannot be judged on
// half the evidence.
func andVal(a, b Value) Value {
	if a == False || b == False {
		return False
	}
	if a == True && b == True {
		return True
	}
	return Unknown
}

// orVal is the standard three-valued OR (Kleene): True if either side is
// True, False if both sides are False, Unknown otherwise.
func orVal(a, b Value) Value {
	if a == True || b == True {
		return True
	}
	if a == False && b == False {
		return False
	}
	return Unknown
}

// notVal maps Unknown to Unknown and swaps True and False otherwise.
func notVal(a Value) Value {
	switch a {
	case True:
		return False
	case False:
		return True
	default:
		return Unknown
	}
}

// evalEq evaluates a "==" or "!=" comparison. Both operands must resolve
// to a known value, or the result is Unknown. GitHub compares every
// expression string case-insensitively, not only github.* references,
// so strings.EqualFold applies here unconditionally.
func evalEq(n nodeEq, f Facts) Value {
	lv, lok := resolveOperand(n.left, f)
	rv, rok := resolveOperand(n.right, f)
	if !lok || !rok {
		return Unknown
	}
	equal := strings.EqualFold(lv, rv)
	if n.neq {
		equal = !equal
	}
	if equal {
		return True
	}
	return False
}

// resolveOperand resolves a comparison operand (a string literal, a
// boolean literal, or a reference) to its string value.
func resolveOperand(n node, f Facts) (val string, known bool) {
	switch v := n.(type) {
	case nodeStrLit:
		return v.val, true
	case nodeBoolLit:
		if v.val {
			return "true", true
		}
		return "false", true
	case nodeRef:
		return f.Resolve(v.ref)
	default:
		return "", false
	}
}

// collectionSuffix marks a reference as a newline-joined list of values
// (one per matching element) rather than a single scalar.
const collectionSuffix = ".*.name"

// evalCall evaluates contains/startsWith/endsWith. An unrecognized
// function name is an unknown leaf, same as anything else outside the
// grammar.
func evalCall(n nodeCall, f Facts) Value {
	switch {
	case strings.EqualFold(n.name, "contains"):
		return evalContains(n, f)
	case strings.EqualFold(n.name, "startsWith"):
		return evalAffix(n, f, hasPrefixFold)
	case strings.EqualFold(n.name, "endsWith"):
		return evalAffix(n, f, hasSuffixFold)
	default:
		return Unknown
	}
}

// evalContains implements contains(collection, item): membership when
// the first argument is a ".*.name" collection reference (its resolved
// value is a newline-joined list, one line per element), substring
// otherwise.
func evalContains(n nodeCall, f Facts) Value {
	if len(n.args) != 2 {
		return Unknown
	}
	collVal, collOK := resolveOperand(n.args[0], f)
	itemVal, itemOK := resolveOperand(n.args[1], f)
	if !collOK || !itemOK {
		return Unknown
	}
	if ref, ok := n.args[0].(nodeRef); ok && strings.HasSuffix(ref.ref, collectionSuffix) {
		for _, line := range strings.Split(collVal, "\n") {
			if strings.EqualFold(line, itemVal) {
				return True
			}
		}
		return False
	}
	if containsFold(collVal, itemVal) {
		return True
	}
	return False
}

// evalAffix implements startsWith/endsWith with the given fold-aware
// matcher.
func evalAffix(n nodeCall, f Facts, match func(s, affix string) bool) Value {
	if len(n.args) != 2 {
		return Unknown
	}
	s, sok := resolveOperand(n.args[0], f)
	a, aok := resolveOperand(n.args[1], f)
	if !sok || !aok {
		return Unknown
	}
	if match(s, a) {
		return True
	}
	return False
}

// GitHub's string functions (contains, startsWith, endsWith) are
// case-insensitive too, same as ==/!=, so every fold helper below
// lowercases both sides before comparing.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func hasPrefixFold(s, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
}

func hasSuffixFold(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
}

// collectRefs walks n and appends every dotted reference it finds, in
// the order they appear in the source.
func collectRefs(n node, out *[]string) {
	switch v := n.(type) {
	case nodeAnd:
		collectRefs(v.left, out)
		collectRefs(v.right, out)
	case nodeOr:
		collectRefs(v.left, out)
		collectRefs(v.right, out)
	case nodeNot:
		collectRefs(v.x, out)
	case nodeEq:
		collectRefs(v.left, out)
		collectRefs(v.right, out)
	case nodeCall:
		for _, a := range v.args {
			collectRefs(a, out)
		}
	case nodeRef:
		*out = append(*out, v.ref)
	}
}
