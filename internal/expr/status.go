package expr

import (
	"regexp"
	"strings"
)

// statusCallText finds a status function call in an expression's text,
// string literals removed first: the fallback for a call the grammar
// could not place (inside an unsupported fragment).
var (
	stringLiteralText = regexp.MustCompile(`'(?:[^']|'')*'`)
	statusCallText    = regexp.MustCompile(`(?i)\b(always|failure|cancelled|success)\s*\(`)
)

// HasStatusCall reports whether expression calls a job status function
// that makes GitHub run the job even when a job it needs was skipped:
// always(), failure() or cancelled() anywhere, or success() under a
// negation (a plain success() is the default and changes nothing).
// Function names are case-insensitive, as GitHub reads them. A status
// call the grammar could not place (it sits inside a fragment parsed as
// unknown) counts too: reading a status call where there is none only
// keeps a predecessor's gate from closing the job, never the reverse.
func HasStatusCall(expression string) bool {
	expression = stripWrapper(expression)
	if isBlank(expression) {
		return false
	}
	found, seen := statusCalls(parse(expression), false)
	if found {
		return true
	}
	return len(statusCallText.FindAllString(stringLiteralText.ReplaceAllString(expression, "''"), -1)) > seen
}

// statusCalls walks n: found is whether a call that runs after a skip
// sits in it (negated tells whether n is under a !), seen how many
// status function calls of any kind the walk placed, for HasStatusCall's
// text fallback.
func statusCalls(n node, negated bool) (found bool, seen int) {
	switch v := n.(type) {
	case nodeAnd:
		return bothStatus(v.left, v.right, negated)
	case nodeOr:
		return bothStatus(v.left, v.right, negated)
	case nodeNot:
		return statusCalls(v.x, !negated)
	case nodeEq:
		// A comparison of a status call (`success() == false`) negates it
		// as surely as a !: read either side as negated.
		return bothStatus(v.left, v.right, true)
	case nodeCall:
		for _, a := range v.args {
			f, s := statusCalls(a, negated)
			found, seen = found || f, seen+s
		}
		switch strings.ToLower(v.name) {
		case "always", "failure", "cancelled":
			return true, seen + 1
		case "success":
			return found || negated, seen + 1
		}
		return found, seen
	}
	return false, 0
}

// bothStatus combines statusCalls over two operands.
func bothStatus(left, right node, negated bool) (bool, int) {
	f1, s1 := statusCalls(left, negated)
	f2, s2 := statusCalls(right, negated)
	return f1 || f2, s1 + s2
}
