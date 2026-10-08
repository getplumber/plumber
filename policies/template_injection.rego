# template-injection — flag inline `run:` scripts that interpolate
# user-controlled GitHub template expressions directly into the shell
# command. The canonical attacker scenario: a pull request opens with
# a crafted title like `"; curl https://evil; #` and the workflow
# pastes it verbatim into a shell one-liner. Under a privileged
# trigger (`pull_request_target`, `workflow_run`, …) the attacker ends
# up executing arbitrary code with the repo's secrets.
#
# Severity is "critical" for the same reasons as dangerous-triggers
# (ISSUE-802): this is the pattern behind the March 2025
# tj-actions/changed-files supply-chain compromise
# (CVE-2025-30066). The safe way to use such values is via an env:
# binding, then dereferencing the environment variable ("$TITLE"),
# which shell-escapes the value. This policy flags only direct
# interpolation inside `run:`, so the env-binding pattern remains
# quiet.
package template_injection

import rego.v1

# Regex patterns matching template expressions whose value is
# attacker-controlled FREE TEXT — the genuine template-injection
# sinks. A pull-request author, issue/comment author or fork owner
# can put arbitrary shell metacharacters in any of these.
#
# Numeric, boolean, enum and SHA fields (`pull_request.number`,
# `*.commits`, `head.repo.fork`, `event_name`, `author_association`,
# `*.sha`, `github.repository`, …) are deliberately NOT matched: they
# cannot carry an injection payload, and flagging them drowns the
# real signal in false positives.
#
# `[^}]*` keeps every match inside a single `${{ … }}` expression so
# an unrelated safe expression on the same line cannot trigger one.
unsafe_patterns := [
	# Titles and bodies — issue, pull_request, comment, review,
	# discussion.
	`\${{[^}]*github\.event\.[^}]*\.(title|body)\b`,
	# Branch / ref names controlled on the attacker's fork.
	`\${{[^}]*github\.head_ref\b`,
	`\${{[^}]*github\.event\.[^}]*\.head\.(ref|label)\b`,
	`\${{[^}]*github\.event\.[^}]*head_branch\b`,
	# default_branch is attacker-controlled ONLY on the fork ("head")
	# repository: pull_request.head.repo.default_branch (an attacker can
	# rename their fork's default branch) and the workflow_run
	# head_repository form. The BASE repo's github.event.repository.
	# default_branch is admin metadata and must NOT be flagged (#230).
	# RE2 has no negative lookahead, so we require the fork qualifier
	# instead of excluding the base path.
	`\${{[^}]*github\.event\.[^}]*head\.repo\.default_branch\b`,
	`\${{[^}]*github\.event\.[^}]*head_repository\.default_branch\b`,
	# Commit messages.
	`\${{[^}]*github\.event\.[^}]*\.message\b`,
	# Repository metadata an attacker sets on their fork.
	`\${{[^}]*github\.event\.[^}]*\.(description|homepage)\b`,
	# Author / committer identity free text.
	`\${{[^}]*github\.event\.[^}]*(author|committer)\.(name|email)\b`,
	# GitHub Pages page name.
	`\${{[^}]*github\.event\.[^}]*page_name\b`,
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	script := job.scripts[j]
	lines := split(script, "\n")
	some li
	line := lines[li]
	_line_controlled(job, line)
	not _safe_sink(lines, li, line)
	finding := {
		"code":     "ISSUE-207",
		"severity": "critical",
		"message":  sprintf("job %q interpolates a user-controlled template expression into an inline script (template-injection risk)", [job.name]),
		"job":      job.name,
		"subject":  _job_subject(job),
	}
}

# _job_subject: the untrusted expression this job's finding names, "${{"
# and surrounding spaces removed, the smallest one when several lines
# fire. One value per job, so the job keeps the one finding it always had.
_job_subject(job) := s if {
	s := min({trim_space(trim_prefix(e, "${{")) |
		some script in job.scripts
		lines := split(script, "\n")
		some li, line in lines
		not _safe_sink(lines, li, line)
		some e in regex.find_n(`\$\{\{[^}]*`, line, -1)
		_expression_controlled(job, e)
	})
} else := ""

# _line_controlled: the line holds an expression whose value someone
# controls when the job runs (_expression_controlled).
_line_controlled(job, line) if {
	some e in regex.find_n(`\$\{\{[^}]*`, line, -1)
	_expression_controlled(job, e)
}

# _expression_controlled: the expression reads a free-text field, and not
# only fields of a pull request payload in a job no pull request runs.
# On any other event github.event.pull_request is empty and
# github.head_ref is "", so `${{ github.event.pull_request.head.ref ||
# github.ref_name }}` on a push-only workflow expands to the pushed
# branch: a constant nobody outside the repository writes.
_expression_controlled(job, e) if {
	_matches_unsafe(e)
	not _pull_request_fields_only_without_pull_request(job, e)
}

_pull_request_fields_only_without_pull_request(job, e) if {
	triggers := {t | some t in object.get(job, "triggers", [])}
	count(triggers) > 0
	count(triggers & _pull_request_payload_events) == 0
	stripped := regex.replace(e, `github\.event\.pull_request\.[A-Za-z0-9_.]*|github\.head_ref\b`, "")
	not _matches_unsafe(stripped)
}

# _pull_request_payload_events: the events whose payload carries a pull
# request (github.event.pull_request, github.head_ref), plus a reusable
# workflow's call, which runs under whatever event its caller had.
_pull_request_payload_events := {
	"pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment",
	"workflow_call",
}

_matches_unsafe(line) if {
	some k
	regex.match(unsafe_patterns[k], line)
}

# A matched expression is a safe sink (#229) only when it is BOTH wrapped
# in toJSON(...) AND sits inside a quoted heredoc body. Neither condition
# alone is sufficient:
#   - toJSON inside `echo "..."` still runs $()/backticks: the shell
#     evaluates them inside double quotes and toJSON does not escape `$`.
#   - a raw expression inside a quoted heredoc is substituted by GitHub
#     before the shell runs, so a payload carrying a newline + the
#     delimiter can break out of the heredoc.
# toJSON escapes the newline (no breakout) and the quoted heredoc
# (<<"EOF" / <<'EOF') disables all expansion, so together they are safe.
# Reading the value as data (jq, json.load) is a separate safe sink not
# special-cased here; bind through env: and dereference "$VAR" instead.
_safe_sink(lines, li, line) if {
	_tojson_wrapped(line)
	_inside_quoted_heredoc(lines, li)
}

_tojson_wrapped(line) if {
	regex.match(`(?i)\$\{\{[^}]*\btojson\s*\(`, line)
}

# Line li is inside a quoted heredoc when an earlier line opens one
# (<<"WORD" / <<'WORD', optionally <<-) and a later line closes it with
# WORD on its own line, with no earlier close of that same opener between
# the opener and li. An UNQUOTED opener (<<WORD) is deliberately ignored —
# it still expands $(), so it is not a safe sink.
_inside_quoted_heredoc(lines, li) if {
	some open
	open < li
	word := _heredoc_open_word(lines[open])
	some close
	close > li
	_heredoc_close(lines[close], word)
	not _closed_between(lines, word, open, li)
}

_heredoc_open_word(l) := word if {
	m := regex.find_all_string_submatch_n(`<<-?\s*["'](\w+)["']`, l, 1)
	word := m[0][1]
}

_heredoc_close(l, word) if {
	regex.match(sprintf(`^\s*%s\s*$`, [word]), l)
}

_closed_between(lines, word, open, li) if {
	some c
	c > open
	c < li
	_heredoc_close(lines[c], word)
}
