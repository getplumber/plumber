package expr

import "strings"

// EvalLiteralInputs evaluates a condition that reads only `inputs.<name>`
// compared with strings or other inputs, through ==, !=, &&, || and !.
// Anything else is Unknown, even where Eval would decide it: an action
// input is always a string on GitHub, so a bare `inputs.flag` holding
// "false" is truthy and `inputs.flag == false` coerces both sides to
// numbers, while Eval reads both as the boolean false.
func EvalLiteralInputs(expression string, f Facts) Value {
	expression = stripWrapper(expression)
	if isBlank(expression) {
		return Unknown
	}
	n := parse(expression)
	if !comparesInputsOnly(n) {
		return Unknown
	}
	return evalNode(n, f)
}

func comparesInputsOnly(n node) bool {
	switch v := n.(type) {
	case nodeAnd:
		return comparesInputsOnly(v.left) && comparesInputsOnly(v.right)
	case nodeOr:
		return comparesInputsOnly(v.left) && comparesInputsOnly(v.right)
	case nodeNot:
		return comparesInputsOnly(v.x)
	case nodeEq:
		return isInputOrString(v.left) && isInputOrString(v.right)
	default:
		return false
	}
}

func isInputOrString(n node) bool {
	switch v := n.(type) {
	case nodeStrLit:
		return true
	case nodeRef:
		_, ok := InputName(v.ref)
		return ok
	default:
		return false
	}
}

// InputName returns the input a reference names, as written: "flag" for
// `inputs.flag`, in any case. A path below an input is not a name.
func InputName(ref string) (string, bool) {
	const prefix = "inputs."
	if len(ref) <= len(prefix) || !strings.EqualFold(ref[:len(prefix)], prefix) {
		return "", false
	}
	name := ref[len(prefix):]
	if strings.ContainsAny(name, ".*") {
		return "", false
	}
	return name, true
}
