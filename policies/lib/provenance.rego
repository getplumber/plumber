# Package lib.provenance renders where a nested `uses:` entry comes from
# (monorepo spec 2026-10-16-nested-actions-resolution-design.md, sections
# 5 and 6). A nested entry carries nested, via (the chain of references it
# was reached through, outermost first) and definedIn (the line in the
# container that holds it). A direct entry carries none of them, so every
# helper here is the identity on a direct entry and no direct finding changes.
package lib.provenance

import rego.v1

# fields is the provenance keys an entry carries, to merge into its finding.
fields(entry) := {k: v |
	some k in ["nested", "via", "definedIn"]
	v := entry[k]
}

# clause is the provenance clause of a nested entry, "" on a direct one.
clause(entry) := sprintf(", pulled in via %s", [concat(" > ", entry.via)]) if {
	count(object.get(entry, "via", [])) > 0
} else := ""

# message is msg with the clause of entry: before the consequence dash when
# msg has one (the terminal report splits a message there), before the
# final period of a sentence, at the end otherwise. The consequence dash
# is the last one (review of PR 549): a message quotes user text before
# it (ISSUE-708 quotes the comment), and that text may hold the same dash,
# while a rule's own text never holds another.
message(msg, entry) := msg if {
	clause(entry) == ""
} else := out if {
	dashes := indexof_n(msg, " \u2014 ")
	count(dashes) > 0
	i := dashes[count(dashes) - 1]
	out := concat("", [substring(msg, 0, i), clause(entry), substring(msg, i, -1)])
} else := out if {
	endswith(msg, ".")
	out := concat("", [trim_suffix(msg, "."), clause(entry), "."])
} else := concat("", [msg, clause(entry)])
