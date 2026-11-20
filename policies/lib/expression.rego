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

# reduced is e, a `${{ …` match, with every boolean-valued part removed:
# an injection pattern that still matches it names a field whose text can
# reach the script. An expression it cannot read (nesting deeper than
# three groups, an unterminated literal) comes back whole, so it fires as
# before.
reduced(e) := r if {
	s := regex.replace(trim_prefix(e, "${{"), `'(?:[^']|'')*'`, " __s__ ")
	t := _pass(_pass(_pass(s)))
	not regex.match(`[()']`, t)
	kept := [o | some o in regex.split(`&&|\|\|`, t); not _boolean_operand(trim_space(o))]
	r := concat(" ", array.concat(["${{"], kept))
} else := e

# _pass reduces the innermost groups of s. A boolean call or a negated
# group becomes __b__. Any other call keeps its arguments in place: its
# value can be one of them. A bare group becomes __b__ when every operand
# in it is boolean, and its content otherwise.
_pass(s) := t if {
	a := regex.replace(s, `(?i)\b(contains|startswith|endswith)\s*\([^()]*\)`, " __b__ ")
	b := regex.replace(a, `!\s*\([^()]*\)`, " __b__ ")
	c := regex.replace(b, `\b[A-Za-z_][A-Za-z0-9_]*\s*\(([^()]*)\)`, " ${1} ")
	t := strings.replace_n({g: _group(g) | some g in regex.find_n(`\([^()]*\)`, c, -1)}, c)
}

_group(g) := " __b__ " if {
	_all_boolean(_inner(g))
} else := concat("", [" ", _inner(g), " "])

_inner(g) := trim_suffix(trim_prefix(g, "("), ")")

_all_boolean(s) if {
	every o in regex.split(`&&|\|\|`, s) {
		_boolean_operand(trim_space(o))
	}
}

# _boolean_operand: o, an operand of `&&` / `||` with no group left in it,
# expands to true or false. Comparisons bind tighter than `&&` and `||`,
# so an operand holding one is a comparison. A comma (call arguments) or
# an index can hide a value, so neither counts.
_boolean_operand(o) if {
	not contains(o, ",")
	not contains(o, "[")
	_boolean_form(o)
}

_boolean_form(o) if o in {"__b__", "true", "false"}

_boolean_form(o) if startswith(o, "!")

_boolean_form(o) if regex.match(`==|!=|<|>`, o)
