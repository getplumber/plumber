# Package lib.expression reads what a GitHub `${{ }}` expression can expand
# to (#624). A comparison, a `!`, or a contains() / startsWith() /
# endsWith() call expands to true or false whatever its operands hold, so
# a free-text field inside one never reaches the script. `&&` and `||`
# expand to one of their operands, so a field that is itself an operand
# does. Checked on GitHub over 9 payloads:
# getplumber-examples/github-actions-miscellaneous-knowledge, branch
# test/2026-11-20-boolean-expressions.
package lib.expression

import rego.v1

# untrusted: an expression in s can expand to text one of patterns
# matches, its boolean-valued parts left out.
untrusted(s, patterns) if {
	some e in regex.find_n(`\$\{\{[^}]*`, s, -1)
	regex.match(patterns[_], reduced(e))
}

# reduced is e, a `${{ …` match, with every boolean-valued part removed:
# an injection pattern that still matches it names a field whose text can
# reach the script. An expression it cannot read (nesting deeper than
# three groups, an unterminated literal) comes back whole, so it fires as
# before.
reduced(e) := r if {
	s := regex.replace(trim_prefix(e, "${{"), `'(?:[^']|'')*'`, " __s__ ")
	t := _pass(_pass(_pass(s)))
	not regex.match(`[()'\[\]]`, t)
	kept := [o | some o in regex.split(`&&|\|\|`, t); not _boolean_operand(trim_space(o))]
	r := concat(" ", array.concat(["${{"], kept))
} else := e

# _pass reduces the innermost groups and indexes of s, in this order:
#   - an index becomes a property, so x['body'] still reads as x.__i__.body
#     and a comparison holding one stays a comparison;
#   - a boolean call or a negated group becomes __b__;
#   - any other call keeps its arguments in place: its value can be one of
#     them;
#   - a bare group (not after a function name, whose turn comes on the
#     next pass) becomes __b__ when every operand in it is boolean or when
#     it is one side of a comparison, and its content otherwise.
_pass(s) := t if {
	i := regex.replace(s, `\s*\[[^\[\]()]*\]`, ".__i__")
	a := regex.replace(i, `(?i)\b(contains|startswith|endswith)\s*\([^()]*\)`, " __b__ ")
	b := regex.replace(a, `!\s*\([^()]*\)`, " __b__ ")
	c := regex.replace(b, `\b[A-Za-z_][A-Za-z0-9_]*\s*\(([^()]*)\)`, " ${1} ")
	groups := regex.find_all_string_submatch_n(`(^|[^A-Za-z0-9_\s])(\s*)\(([^()]*)\)(\s*[=!<>]?)`, c, -1)
	t := strings.replace_n({m[0]: concat("", [m[1], m[2], _group(m[1], m[3], m[4]), m[4]]) | some m in groups}, c)
}

_group(before, content, after) := " __b__ " if {
	_all_boolean(content)
} else := " __b__ " if {
	_comparison_side(before, after)
} else := concat("", [" ", content, " "])

# _comparison_side: the group sits right after or right before a
# comparison operator. The comparison is the boolean, whatever the group
# expands to.
_comparison_side(before, _) if before in {"=", "<", ">"}

_comparison_side(_, after) if trim_space(after) != ""

_all_boolean(s) if {
	every o in regex.split(`&&|\|\|`, s) {
		_boolean_operand(trim_space(o))
	}
}

# _boolean_operand: o, an operand of `&&` / `||` with no group left in it,
# expands to true or false. Comparisons bind tighter than `&&` and `||`,
# so an operand holding one is a comparison. A comma (call arguments) can
# hide a value, so it does not count.
_boolean_operand(o) if {
	not contains(o, ",")
	_boolean_form(o)
}

_boolean_form(o) if o in {"__b__", "true", "false"}

_boolean_form(o) if startswith(o, "!")

_boolean_form(o) if regex.match(`==|!=|<|>`, o)
