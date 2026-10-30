# tag-unprotected — flag release tag patterns in use whose tags anyone
# with push access can move, delete or create (#398).
#
# The patterns checked are the ones declared in .plumber.yaml
# (tagMustBeProtected.namePatterns) plus the tag patterns GitHub
# workflows trigger on (`on.push.tags`). A pattern is only checked while
# it is in use: an existing tag matches it, or a workflow triggers on it,
# so a repository that never tags stays quiet.
#
# A pattern is protected when the provider's rules block tag updates and
# deletions on it, and restrict tag creation unless
# requireCreationRestricted is false. Each protection is judged across
# every rule, the way GitHub layers rulesets. A rule covers a pattern when
# it matches the pattern itself (a rule on `v*` or `**` covers `v*`, one
# on `v[0-9]*` does not) and every existing tag the pattern matches.
#
# The collectors translate both providers' wildcards into one glob
# dialect (see ir.TagProtection), so nothing here is provider specific
# except the GitLab tag-trigger shape in _gitlab_runs_on_tags.
package tag_unprotected

import rego.v1

deny contains finding if {
	tp := input.pipeline.tagProtection
	tp.known == true
	some pattern in _required_patterns
	_in_use(pattern, tp)
	missing := _missing(pattern, tp)
	count(missing) > 0
	finding := {
		"code":     "ISSUE-507",
		"severity": "critical",
		"message":  _message(pattern, missing),
		# No "job": a tag pattern is not a job. tagPattern names what this
		# finding is about and is what the identity recipe selects.
		"type":       "unprotected",
		"tagPattern": pattern,
		# missingProtections: the protections the pattern lacks, as stable
		# tokens a consumer parses ("update", "deletion", "creation").
		"missingProtections": missing,
		# occurrenceSeverity: critical when a workflow runs on a tag push,
		# since a moved or forged tag then ships through the release
		# itself; high otherwise.
		"triggered":          _is_triggered(pattern, tp),
		"occurrenceSeverity": _occurrence_severity(pattern, tp),
	}
}

_config := object.get(input.config, "tagMustBeProtected", {})

_jobs := object.get(input.pipeline, "jobs", [])

_strip(s) := trim_prefix(s, "refs/tags/")

_live(job) if object.get(job, "inert", "") == ""

_required_patterns contains p if {
	some raw in object.get(_config, "namePatterns", [])
	p := _strip(raw)
	p != ""
}

_required_patterns contains p if {
	some p in _workflow_tag_patterns
}

# _workflow_tag_patterns: the tag patterns live GitHub workflows run on.
# A `!` entry negates an earlier one and an expression cannot be read
# statically; neither is a pattern to protect.
_workflow_tag_patterns contains p if {
	some job in _jobs
	_live(job)
	some raw in object.get(job, "pushTags", [])
	not startswith(raw, "!")
	not contains(raw, "${{")
	p := _strip(raw)
	p != ""
}

_matching_tags(pattern, tp) := {t |
	some t in object.get(tp, "tags", [])
	_tag_matches(pattern, t)
}

# _tag_matches: a workflow pattern is a GitHub filter pattern, where `+`
# and `?` quantify the character before them; a configured pattern is a
# glob.
_tag_matches(pattern, t) if {
	pattern in _workflow_tag_patterns
	regex.match(_filter_regex(pattern), t)
}

_tag_matches(pattern, t) if {
	not pattern in _workflow_tag_patterns
	glob.match(pattern, ["/"], t)
}

# _filter_regex: a GitHub filter pattern as an anchored regex. `*` stops
# at `/`, `**` does not; `+`, `?`, `[...]` and `\` escapes read the same
# in both.
_filter_regex(p) := concat("", ["^", body, "$"]) if {
	escaped := strings.replace_n(
		{".": `\.`, "(": `\(`, ")": `\)`, "{": `\{`, "}": `\}`, "|": `\|`, "^": `\^`, "$": `\$`},
		p,
	)
	body := replace(replace(replace(escaped, "**", "\u0000"), "*", "[^/]*"), "\u0000", ".*")
}
_in_use(pattern, tp) if count(_matching_tags(pattern, tp)) > 0

_in_use(pattern, tp) if _pattern_triggered(pattern, tp)

# _pattern_triggered: a workflow triggers on this very pattern, or on one
# that matches an existing tag this pattern matches too.
_pattern_triggered(pattern, _) if pattern in _workflow_tag_patterns

_pattern_triggered(pattern, tp) if {
	some wp in _workflow_tag_patterns
	some t in _matching_tags(pattern, tp)
	regex.match(_filter_regex(wp), t)
}

# _triggered: the pattern's own trigger, or a workflow that runs on tags
# without naming a pattern (a GitHub release, a GitLab tag pipeline).
# Those raise the severity but never put a pattern in use on their own.
_triggered(pattern, tp) if _pattern_triggered(pattern, tp)

_triggered(_, _) if {
	some job in _jobs
	_live(job)
	"release" in object.get(job, "triggers", [])
}

_triggered(_, _) if {
	some job in _jobs
	_live(job)
	_gitlab_runs_on_tags(job)
}

_is_triggered(pattern, tp) if {
	_triggered(pattern, tp)
} else := false

_occurrence_severity(pattern, tp) := "critical" if {
	_triggered(pattern, tp)
} else := "high"

# _gitlab_runs_on_tags: `only: [tags]`, or a rule whose `if:` reads
# $CI_COMMIT_TAG positively and does not exclude the job (`when: never`).
# A bare job with no rules runs on tag pipelines too, but so does almost
# every job: only explicit tag intent counts.
_gitlab_runs_on_tags(job) if "tags" in object.get(job, "only", [])

_gitlab_runs_on_tags(job) if {
	some rule in object.get(job, "rules", [])
	object.get(rule, "when", "") != "never"
	cond := object.get(rule, "if", "")
	is_string(cond)
	_positive_tag_condition(cond)
}

# _positive_tag_condition: some $CI_COMMIT_TAG reference that is neither
# negated (`!$CI_COMMIT_TAG`) nor compared equal to an empty value
# (`$CI_COMMIT_TAG == null`, `== ""`), the shapes that mean "not a tag".
_positive_tag_condition(cond) if {
	some m in regex.find_all_string_submatch_n(`(!?)\$(?:\{CI_COMMIT_TAG\}|CI_COMMIT_TAG\b)(\s*(==|!=)\s*(null|""|''))?`, cond, -1)
	m[1] == ""
	not m[3] == "=="
}

_missing(pattern, tp) := [m |
	some m in ["update", "deletion", "creation"]
	_lacks(m, pattern, tp)
]

_lacks("update", pattern, tp) if not _has("blocksUpdate", pattern, tp)

_lacks("deletion", pattern, tp) if not _has("blocksDeletion", pattern, tp)

_lacks("creation", pattern, tp) if {
	object.get(_config, "requireCreationRestricted", true) == true
	not _has("restrictsCreation", pattern, tp)
}

_has(protection, pattern, tp) if {
	some rule in object.get(tp, "rules", [])
	object.get(rule, protection, false) == true
	_rule_covers_pattern(rule, pattern)
	not _uncovered_tag(protection, pattern, tp)
}

# _rule_covers_pattern: the rule names the pattern verbatim (a class like
# `v[0-9]*` does not glob-match its own text), or its globs match the
# pattern's text.
_rule_covers_pattern(rule, pattern) if {
	pattern in object.get(rule, "include", [])
	not _rule_excludes(rule, pattern)
}

_rule_covers_pattern(rule, pattern) if _rule_matches(rule, pattern)
_uncovered_tag(protection, pattern, tp) if {
	some t in _matching_tags(pattern, tp)
	not _tag_has(protection, t, tp)
}

_tag_has(protection, t, tp) if {
	some rule in object.get(tp, "rules", [])
	object.get(rule, protection, false) == true
	_rule_matches(rule, t)
}

_rule_matches(rule, s) if {
	some inc in object.get(rule, "include", [])
	glob.match(inc, ["/"], s)
	not _rule_excludes(rule, s)
}

_rule_excludes(rule, s) if {
	some exc in object.get(rule, "exclude", [])
	glob.match(exc, ["/"], s)
}

_clauses := {
	"update": "tag updates are not blocked",
	"deletion": "tag deletions are not blocked",
	"creation": "tag creation is not restricted",
}

_message(pattern, missing) := sprintf("Tag pattern `%s` is not protected.", [pattern]) if {
	count(missing) == count(_required_protections)
} else := sprintf("Tag pattern `%s` is not fully protected, %s.", [pattern, concat(" and ", [_clauses[m] | some m in missing])])

_required_protections := ["update", "deletion", "creation"] if {
	object.get(_config, "requireCreationRestricted", true) == true
} else := ["update", "deletion"]
