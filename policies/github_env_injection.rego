# github-env-injection — flag untrusted content reaching $GITHUB_ENV or
# $GITHUB_PATH. These two files are sticky: every later step of the job reads
# the variables / PATH entries they define. An attacker who controls the value
# (PR title, issue body, fork branch name, ...) can override `NODE_OPTIONS`,
# front-load a malicious directory on PATH, and hijack later tool invocations,
# exfiltrating secrets under a secret-bearing trigger (pull_request_target,
# workflow_run).
#
# Three shapes are flagged:
#
#   1. DIRECT — the untrusted expression and the redirect are on the SAME `run:`
#      line (`echo "K=${{ github.event.* }}" >> $GITHUB_ENV`).
#
#   2. ENV-BOUND — the value is bound through `env:` and the redirect writes the
#      shell variable (`env: { BODY: ${{ … }} }` then `echo "K=$BODY" >> …`).
#      The `env:` binding shell-escapes the value, so ISSUE-207 (command
#      injection) is satisfied — but it does NOT stop env / PATH poisoning, and
#      this is the case ISSUE-207 cannot see. For $GITHUB_ENV the value must be
#      able to carry a NEWLINE to open a second variable line, so only multiline
#      free text (bodies, commit messages) qualifies. For $GITHUB_PATH ANY
#      controlled value is a directory the attacker can plant a binary in, so
#      the full list applies. base64-encoding the VAR or toJSON neutralises the
#      newline; a base64 elsewhere on the line does not.
#
#   3. ENV-BOUND via HEREDOC — same as (2) but the redirect is a heredoc header
#      (`cat <<EOF >> $GITHUB_ENV`) and the `$VAR` is dereferenced on a later
#      line of the body, so per-line matching would miss it. Only a randomised
#      (unguessable) heredoc delimiter is a real fix here, not a fixed `EOF`.
#
# `unsafe_patterns` is the full attacker-controlled FREE TEXT list, kept
# byte-identical to template_injection.rego (ISSUE-207) by the parity test
# TestIssue209UnsafePatternsMatchTemplateInjection. Numeric / enum / SHA fields
# are excluded — they cannot carry a metacharacter or a newline.
package github_env_injection

import rego.v1

# KEEP IN SYNC with policies/template_injection.rego::unsafe_patterns
# (byte-for-byte; enforced by TestIssue209UnsafePatternsMatchTemplateInjection).
unsafe_patterns := [
	`\${{[^}]*github\.event\.[^}]*\.(title|body)\b`,
	`\${{[^}]*github\.head_ref\b`,
	`\${{[^}]*github\.event\.[^}]*\.head\.(ref|label)\b`,
	`\${{[^}]*github\.event\.[^}]*head_branch\b`,
	`\${{[^}]*github\.event\.[^}]*head\.repo\.default_branch\b`,
	`\${{[^}]*github\.event\.[^}]*head_repository\.default_branch\b`,
	`\${{[^}]*github\.event\.[^}]*\.message\b`,
	`\${{[^}]*github\.event\.[^}]*\.(description|homepage)\b`,
	`\${{[^}]*github\.event\.[^}]*(author|committer)\.(name|email)\b`,
	`\${{[^}]*github\.event\.[^}]*page_name\b`,
]

# NEWLINE-capable subset: fields that can contain a literal newline and thus
# open a SECOND `KEY=value` line in $GITHUB_ENV. Bodies and commit messages are
# multiline; titles, refs, labels, names, enums and SHAs are single-line and so
# cannot poison $GITHUB_ENV through an env-bound write. Used only by the
# env-bound $GITHUB_ENV rule. (A subset of unsafe_patterns by construction.)
newline_unsafe_patterns := [
	`\${{[^}]*github\.event\.[^}]*\.body\b`,
	`\${{[^}]*github\.event\.[^}]*\.message\b`,
]

# A redirect (`>>` / `>`) or `tee` writing into the named file, in `$VAR` or
# `${VAR}` form, optionally double-quoted (`"$GITHUB_ENV"`). Single quotes are
# NOT matched: the shell does not expand `$` inside `'...'`.
env_sink_patterns := [
	`>>?\s*"?\$\{?GITHUB_ENV\}?`,
	`\btee\s+(-a\s+)?"?\$\{?GITHUB_ENV\}?`,
]

path_sink_patterns := [
	`>>?\s*"?\$\{?GITHUB_PATH\}?`,
	`\btee\s+(-a\s+)?"?\$\{?GITHUB_PATH\}?`,
]

sink_patterns := array.concat(env_sink_patterns, path_sink_patterns)

# 1. DIRECT injection: untrusted expression and sink on the same line.
deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	line := split(job.scripts[j], "\n")[_]
	_matches(line, sink_patterns)
	_matches(line, unsafe_patterns)
	not _tojson_wrapped(line)
	finding := _finding(job.name, "writes a user-controlled template expression into $GITHUB_ENV or $GITHUB_PATH; an attacker can hijack later steps")
}

# 2. ENV-BOUND poisoning of $GITHUB_ENV: a multiline untrusted value bound in
# env: and written as "$VAR" into $GITHUB_ENV. The env: binding does not stop a
# newline opening a second variable.
deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	some varname
	_matches(job.variables[varname], newline_unsafe_patterns)
	not _tojson_wrapped(job.variables[varname])
	some j
	line := split(job.scripts[j], "\n")[_]
	_matches(line, env_sink_patterns)
	_dereferences(line, varname)
	not _base64_of(line, varname)
	finding := _finding(job.name, sprintf("binds an untrusted multiline value to $%s and writes it to $GITHUB_ENV; a newline still opens a second variable (base64-encode or use a heredoc delimiter)", [varname]))
}

# 3. ENV-BOUND poisoning of $GITHUB_PATH: any untrusted value bound in env: and
# written as "$VAR" into $GITHUB_PATH becomes a directory on PATH.
deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	some varname
	_matches(job.variables[varname], unsafe_patterns)
	not _tojson_wrapped(job.variables[varname])
	some j
	line := split(job.scripts[j], "\n")[_]
	_matches(line, path_sink_patterns)
	_dereferences(line, varname)
	not _base64_of(line, varname)
	finding := _finding(job.name, sprintf("binds an untrusted value to $%s and writes it to $GITHUB_PATH; an attacker controls a directory placed on PATH", [varname]))
}

# 4. ENV-BOUND poisoning of $GITHUB_ENV through a HEREDOC / split redirect. The
# sink (`>> $GITHUB_ENV`) sits on the `cat <<EOF` header line and the `$VAR`
# dereference is on a later line of the same run block, so the per-line rules
# above miss it — but the whole heredoc body still lands in $GITHUB_ENV and a
# newline in a multiline value opens a second variable.
deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	some varname
	_matches(job.variables[varname], newline_unsafe_patterns)
	not _tojson_wrapped(job.variables[varname])
	some j
	_heredoc_to_sink(job.scripts[j], varname, env_sink_patterns)
	finding := _finding(job.name, sprintf("writes $%s into $GITHUB_ENV through a heredoc/redirect; the multiline value still opens a second variable (base64-encode or use a randomised heredoc delimiter)", [varname]))
}

# 5. Same, for $GITHUB_PATH — any untrusted value written through a heredoc
# becomes a directory on PATH.
deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	some varname
	_matches(job.variables[varname], unsafe_patterns)
	not _tojson_wrapped(job.variables[varname])
	some j
	_heredoc_to_sink(job.scripts[j], varname, path_sink_patterns)
	finding := _finding(job.name, sprintf("writes $%s into $GITHUB_PATH through a heredoc/redirect; an attacker controls a directory placed on PATH", [varname]))
}

_matches(s, patterns) if regex.match(patterns[_], s)

# `\b` after the name avoids $TITLE matching $TITLE_SUFFIX. Env var names are
# shell identifiers, so they carry no regex metacharacters.
_dereferences(line, varname) if regex.match(sprintf(`\$\{?%s\b`, [varname]), line)

# _base64_of is true only when base64 is applied to the UNTRUSTED var itself —
# either the var is piped into base64 (`"$VAR" | base64`) or base64 consumes it
# directly (`base64 <<< "$VAR"`). A bare "contains base64" is too broad: it also
# silences `echo "K=$VAR X=$(date | base64)"` where the var is still raw.
# The second pattern excludes `)`, `|`, `;`, `&` between base64 and the var so
# the match cannot cross a command-substitution / pipeline / statement boundary
# (`ENC=$(echo hi | base64) RAW=$VAR` must NOT suppress — the var is the next
# command's raw argument, not base64's operand). Suppression is a negative
# guard, so any ambiguity falls through to a finding rather than silencing one.
_base64_of(line, varname) if regex.match(sprintf(`\$\{?%s\}?"?'?\s*\|\s*base64`, [varname]), line)

_base64_of(line, varname) if regex.match(sprintf(`base64[^\n)|;&]*\$\{?%s\b`, [varname]), line)

# _heredoc_to_sink: a heredoc header (`<<EOF`, `<<-'EOF'`, ...) whose redirect
# writes into the sink file on the SAME line, with the untrusted $VAR
# dereferenced somewhere after it (the heredoc body). RE2 has no backreferences,
# so the exact closing delimiter can't be pinned; the residual over-match (a
# static heredoc followed by an unrelated later use of the var) is rare and errs
# toward flagging a write to a sticky file.
_heredoc_to_sink(script, varname, sinkpatterns) if {
	some sinkpat in sinkpatterns
	regex.match(sprintf(`(?s)<<-?\s*["']?\w+["']?[^\n]*(%s).*\$\{?%s\b`, [sinkpat, varname]), script)
}

_tojson_wrapped(s) if regex.match(`(?i)\$\{\{[^}]*\btojson\s*\(`, s)

_finding(jobname, msg) := {
	"code":     "ISSUE-209",
	"severity": "high",
	"message":  sprintf("job %q %s", [jobname, msg]),
	"job":      jobname,
}
