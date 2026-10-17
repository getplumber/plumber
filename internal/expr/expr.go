// Package expr evaluates GitHub Actions style `if:` conditions under
// three-valued logic. A reference that the caller's Facts cannot resolve
// yields Unknown rather than a guess, so callers can tell "this condition
// is provably false" from "we don't have enough information to know."
//
// The grammar is the subset of GitHub's expression syntax actually used in
// job and step conditions: boolean literals, string literals in single
// quotes, dotted references (including `.*.name` collection references),
// the operators `==`, `!=`, `&&`, `||`, `!`, parentheses, and the
// functions contains, startsWith and endsWith. Anything outside that
// grammar parses as an unknown leaf instead of failing, since a condition
// this package cannot parse is exactly the kind of condition it should
// refuse to decide on.
package expr

// Value is the result of evaluating a condition under three-valued logic.
type Value int

const (
	// False means the condition is provably false given the facts.
	False Value = iota
	// True means the condition is provably true given the facts.
	True
	// Unknown means the facts do not determine the condition's outcome.
	Unknown
)

// Facts resolves a dotted reference such as "github.event_name" or
// "needs.policy.outputs.run" to its string value. known is false when the
// reference has no value in the facts the caller has available, which is
// distinct from the reference resolving to an empty string.
type Facts interface {
	Resolve(ref string) (val string, known bool)
}

// Eval evaluates expression against f and returns its three-valued
// result. An expression wrapped in "${{ ... }}" has the wrapper stripped
// first. An empty expression (no "if:" present) evaluates to True, since
// an absent condition runs unconditionally. Anything the grammar does not
// cover evaluates to Unknown rather than panicking.
func Eval(expression string, f Facts) Value {
	expression = stripWrapper(expression)
	if isBlank(expression) {
		return True
	}
	node := parse(expression)
	return evalNode(node, f)
}

// Refs returns every dotted reference an expression reads, in the order
// they appear, for callers that want to know what an expression depends
// on without evaluating it.
func Refs(expression string) []string {
	expression = stripWrapper(expression)
	if isBlank(expression) {
		return nil
	}
	node := parse(expression)
	var out []string
	collectRefs(node, &out)
	return out
}

func isBlank(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}
