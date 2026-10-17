package capability

import (
	"path"
	"strings"
)

// lineTokens returns the command words of one script line (cmds): the first word of the
// line and the first word after each `&&`, `||`, `;` and `|`, reduced to their base name,
// with a leading VAR=value assignment and the known command prefixes and launchers skipped
// (see stripPrefixes), and the module of `python -m <module>` and the hook of `pre-commit
// run <hook>` taken as the command; shell comments are dropped; the argument of `sh -c "..."` / `bash -c '...'` is
// tokenized in turn. It is a recognizer's input, not a shell: quotes are only used to find
// the -c argument, and nothing is evaluated. A line may hold several lines (a `- |` script
// entry): each newline is a segment boundary. lineTokens also returns the image candidates
// of the line's container-run segments (images): `docker run`, `podman run`, `nerdctl run`,
// the one image each runs, unquoted (see containerRunImage); the container's own command
// after the image is never a candidate, nor unwrapped as a `sh -c`. The third result, following, gives, for each cmds entry (same index), the
// fields of its segment that follow it: a multi-word recognizer command (`ggshield secret`)
// is matched against a cmds entry and the start of its following fields, so a
// multi-purpose tool's command is disambiguated by subcommand (`ggshield secret scan`
// matches, `ggshield iac scan` does not); a single-word command ignores following and
// matches as before.
func lineTokens(line string) (cmds, images []string, following [][]string) {
	segmentTokens(line, true, &cmds, &images, &following)
	return cmds, images, following
}

// segmentTokens appends the tokens of line to cmds and images, and the fields following
// each cmds entry to following (same index as cmds); unwrap says whether a `sh -c`
// argument is tokenized in turn. The unwrapped argument is tokenized with unwrap false, so
// the unwrap is one level deep and a line of repeated `sh -c` costs linear time, not
// quadratic (script lines come from any analyzed project's CI config).
func segmentTokens(line string, unwrap bool, cmds, images *[]string, following *[][]string) {
	for _, seg := range splitSegments(line) {
		fields := stripPrefixes(strings.Fields(seg))
		if len(fields) == 0 {
			continue
		}
		cmd := path.Base(fields[0])
		switch {
		case (cmd == "python" || cmd == "python3" || cmd == "py") && len(fields) >= 3 && fields[1] == "-m":
			// `python -m detect_secrets`: the module is the command, as written
			*cmds = append(*cmds, fields[2])
			*following = append(*following, fields[3:])
			continue
		case cmd == "pre-commit" && len(fields) >= 2 && fields[1] == "run":
			// `pre-commit run [options] <hook>`: the hook id is the command, as written, once
			// the run's own options are skipped (see preCommitHook); an all-hooks run (no
			// hook, or one whose id is absorbed into a `--files`/`--file` list and so
			// indistinguishable from a file path) falls through to `pre-commit`, by design:
			// the hook list is in `.pre-commit-config.yaml`, which the rules do not read
			if hook, ok := preCommitHook(fields[2:]); ok {
				*cmds = append(*cmds, hook)
				*following = append(*following, nil)
				continue
			}
		case (cmd == "docker" || cmd == "podman" || cmd == "nerdctl") && len(fields) >= 2 && fields[1] == "run":
			if img, ok := containerRunImage(fields[2:]); ok {
				*images = append(*images, img)
			}
		}
		*cmds = append(*cmds, cmd)
		*following = append(*following, fields[1:])
		if unwrap && (cmd == "sh" || cmd == "bash" || cmd == "dash" || cmd == "zsh") && len(fields) >= 3 && fields[1] == "-c" {
			segmentTokens(unquote(strings.Join(fields[2:], " ")), false, cmds, images, following)
		}
	}
}

// containerRunBoolFlags are the `docker|podman|nerdctl run` flags that take no value field
// (`--` ends the options and takes none either).
var containerRunBoolFlags = map[string]bool{
	"--rm": true, "-d": true, "--detach": true, "-i": true, "--interactive": true, "-t": true, "--tty": true,
	"--privileged": true, "--init": true, "--no-healthcheck": true, "--read-only": true, "--sig-proxy": true,
	"-P": true, "--publish-all": true, "-q": true, "--quiet": true, "--oom-kill-disable": true, "--help": true,
	"--": true,
}

// containerRunImage returns the image of a container-run segment from the fields after
// `run`: the first field that is neither a flag (a leading `-`) nor a flag's value. A flag
// holding `=`, a boolean flag (containerRunBoolFlags) or a combined boolean short form made
// of `d`, `i` and `t` only (`-it`, `-dit`) consumes nothing; every other flag consumes the
// next field as its value (`-v x:y`, `--entrypoint sh`), a generic rule with no table of
// value flags. The fields after the image are the container's command, never an image.
func containerRunImage(fields []string) (string, bool) {
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if !strings.HasPrefix(f, "-") {
			return unquote(f), true
		}
		if !strings.Contains(f, "=") && !containerRunBoolFlags[f] && !combinedDITFlag(f) {
			i++ // the flag's value
		}
	}
	return "", false
}

// combinedDITFlag reports whether f is a combined short form of the boolean `-d`, `-i` and
// `-t` flags (`-it`, `-dit`, `-itd`).
func combinedDITFlag(f string) bool {
	if len(f) < 2 || f[0] != '-' || f[1] == '-' {
		return false
	}
	for _, c := range f[1:] {
		if c != 'd' && c != 'i' && c != 't' {
			return false
		}
	}
	return true
}

// sudoValueOptions are the sudo options whose value is the next field (written without `=`).
var sudoValueOptions = map[string]bool{
	"-u": true, "-g": true, "-C": true, "-h": true, "-p": true, "-r": true, "-R": true, "-T": true, "-U": true,
	"--user": true, "--group": true, "--host": true, "--prompt": true, "--role": true,
	"--chroot": true, "--type": true, "--other-user": true,
}

// envFlagOptions and envValueOptions are the env options without and with a value field.
var (
	envFlagOptions  = map[string]bool{"-i": true, "-0": true, "--ignore-environment": true, "--null": true}
	envValueOptions = map[string]bool{"-u": true, "--unset": true, "-C": true, "--chdir": true}
)

// npxValueOptions are the npx options whose value is the next field.
var npxValueOptions = map[string]bool{"-p": true, "--package": true}

// launchers maps a launcher to the subcommand after which the next field is the command
// (`bundle exec gitleaks`, `poetry run detect-secrets`).
var launchers = map[string]string{
	"bundle": "exec", "poetry": "run", "pipenv": "run", "uv": "run", "pdm": "run", "pipx": "run", "pnpm": "exec",
}

// preCommitValueOptions are the pre-commit run options whose value is the next field
// (written without `=`); their `=` form, like any other option's, consumes none.
var preCommitValueOptions = map[string]bool{
	"--hook-stage": true, "--from-ref": true, "--to-ref": true, "--color": true,
	"--source": true, "-s": true, "--origin": true, "-o": true,
	"--commit-msg-filename": true, "--remote-name": true, "--remote-url": true,
	"--local-branch": true, "--remote-branch": true, "--checkout-type": true,
	"--prepare-commit-message-source": true, "--commit-object-name": true,
}

// preCommitHook returns the hook id of a `pre-commit run [options] <hook>` segment's fields
// after `run`: the first field that is not an option. An option in preCommitValueOptions
// consumes the next field as its value (its `=` form consumes none); `--files` and `--file`
// consume every field after them that does not start with `-`, so a hook id placed right
// after one of them is indistinguishable from a file path and is never returned, by design
// (ambiguous: no hook); every other `-` field is boolean and consumes nothing.
func preCommitHook(fields []string) (string, bool) {
	i := 0
	for i < len(fields) {
		f := fields[i]
		if !strings.HasPrefix(f, "-") {
			return f, true
		}
		switch {
		case f == "--files" || f == "--file":
			i++
			for i < len(fields) && !strings.HasPrefix(fields[i], "-") {
				i++
			}
		case strings.Contains(f, "="):
			i++
		case preCommitValueOptions[f]:
			i += 2
		default:
			i++
		}
	}
	return "", false
}

// stripPrefixes drops the leading VAR=value assignments of a segment's fields, then, as
// often as they repeat, the known command prefixes: `env` with its VAR=value fields and
// options, `sudo` with its options, `timeout` with its options and its duration, `time`,
// `nice`, `exec`, `command`, `nohup`, `npx` with its options, and the launchers (`bundle exec`, `poetry run`, `pipenv run`, `uv run`, `pdm
// run`, `pipx run`, `pnpm exec`). An option that takes a value drops the next field with it.
// Each pass drops at least one field, so the cost stays linear in the fields.
func stripPrefixes(fields []string) []string {
	for len(fields) > 0 && isAssignment(fields[0]) {
		fields = fields[1:]
	}
	for len(fields) > 0 {
		base := path.Base(fields[0])
		switch base {
		case "env":
			fields = envArgsDropped(fields[1:])
		case "sudo":
			fields = optionsDropped(fields[1:], sudoValueOptions)
		case "npx":
			fields = optionsDropped(fields[1:], npxValueOptions)
		case "timeout":
			fields = timeoutArgsDropped(fields[1:])
		case "time", "nice", "exec", "command", "nohup":
			fields = fields[1:]
		default:
			if sub, ok := launchers[base]; ok && len(fields) >= 2 && fields[1] == sub {
				fields = fields[2:]
				continue
			}
			return fields
		}
	}
	return fields
}

// envArgsDropped drops the leading VAR=value fields and env options of the fields after
// `env`, a value option (`-u NAME`, `--chdir DIR`) with the field after it.
func envArgsDropped(fields []string) []string {
	for len(fields) > 0 {
		f := fields[0]
		switch {
		case isAssignment(f), envFlagOptions[f], strings.HasPrefix(f, "--unset="), strings.HasPrefix(f, "--chdir="):
			fields = fields[1:]
		case envValueOptions[f]:
			fields = dropUpTo(fields, 2)
		default:
			return fields
		}
	}
	return fields
}

// timeoutFlagOptions and timeoutValueOptions are the timeout options without and with a
// value field (the `=` forms, `--signal=SIG` and `--kill-after=DUR`, take none).
var (
	timeoutFlagOptions  = map[string]bool{"--preserve-status": true, "--foreground": true, "-v": true, "--verbose": true}
	timeoutValueOptions = map[string]bool{"-s": true, "--signal": true, "-k": true, "--kill-after": true}
)

// timeoutArgsDropped drops, from the fields after `timeout`, its options (a value option
// with the field after it), then its one duration field when it is one (isDuration), so
// `timeout -s KILL 5m gitleaks detect` leaves `gitleaks detect`.
func timeoutArgsDropped(fields []string) []string {
	for len(fields) > 0 {
		f := fields[0]
		switch {
		case timeoutFlagOptions[f], strings.HasPrefix(f, "--signal="), strings.HasPrefix(f, "--kill-after="):
			fields = fields[1:]
		case timeoutValueOptions[f]:
			fields = dropUpTo(fields, 2)
		default:
			if isDuration(f) {
				return fields[1:]
			}
			return fields
		}
	}
	return fields
}

// isDuration reports whether f is a timeout duration: digits with an optional decimal part
// (`300`, `2.5`, `.5`) and an optional `s`, `m`, `h` or `d` suffix.
func isDuration(f string) bool {
	if n := len(f); n > 0 && strings.IndexByte("smhd", f[n-1]) >= 0 {
		f = f[:n-1]
	}
	digits, dots := 0, 0
	for i := 0; i < len(f); i++ {
		switch {
		case f[i] >= '0' && f[i] <= '9':
			digits++
		case f[i] == '.':
			dots++
		default:
			return false
		}
	}
	return digits > 0 && dots <= 1
}

// optionsDropped drops the leading option fields (a leading `-`), each value option of
// valueOptions with the field after it.
func optionsDropped(fields []string, valueOptions map[string]bool) []string {
	for len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
		if valueOptions[fields[0]] {
			fields = dropUpTo(fields, 2)
		} else {
			fields = fields[1:]
		}
	}
	return fields
}

// dropUpTo drops the first n fields, or all of them when there are fewer.
func dropUpTo(fields []string, n int) []string {
	if len(fields) < n {
		return nil
	}
	return fields[n:]
}

// splitSegments cuts a line at the shell operators and at newlines, outside quotes: each
// line of a multi-line script entry is its own segment (a CR before the newline is left to
// strings.Fields, which drops it as whitespace). An unquoted `#` that starts a field (at
// the start of a segment or after whitespace) begins a shell comment, dropped up to the
// next newline; a `#` inside a word (`foo#bar`, `$#`) or inside quotes is kept.
func splitSegments(line string) []string {
	var segs []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
		case c == '#' && atFieldStart(cur.String()):
			for i+1 < len(line) && line[i+1] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			quote = c
			cur.WriteByte(c)
		case c == '&' && i+1 < len(line) && line[i+1] == '&', c == '|' && i+1 < len(line) && line[i+1] == '|':
			segs = append(segs, cur.String())
			cur.Reset()
			i++
		case c == ';' || c == '|' || c == '\n':
			segs = append(segs, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	segs = append(segs, cur.String())
	return segs
}

// atFieldStart reports whether the next byte after seg starts a field: seg is empty or
// ends with whitespace.
func atFieldStart(seg string) bool {
	if seg == "" {
		return true
	}
	switch seg[len(seg)-1] {
	case ' ', '\t', '\r', '\v', '\f':
		return true
	}
	return false
}

func isAssignment(word string) bool {
	eq := strings.IndexByte(word, '=')
	if eq <= 0 {
		return false
	}
	for _, r := range word[:eq] {
		if !isNameRune(r) {
			return false
		}
	}
	return true
}

// isNameRune reports whether r may appear in a shell variable name.
func isNameRune(r rune) bool {
	return r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// wrapperPath reports the repository-relative shell script a line runs, when it runs one:
// `./x.sh`, `x.sh`, `sh x.sh`, `bash ./x.bash`, `source x.sh`, `. x.sh`, in any segment the
// shell operators and newlines split (`make && ./x.sh`, `./x.sh;`, the second line of a
// `- |` entry), the first one found. A relative
// `cd dir` segment before it is applied (`cd ci && ./x.sh` runs ci/x.sh); a cd that is
// absolute, bare, variable or escapes the root ends the search, since the script is then no
// longer known to be under the root. Absolute paths and paths with `..` are refused here
// (ResolveWithinRepo refuses them again at read time).
func wrapperPath(line string) (string, bool) {
	dir := ""
	for _, seg := range splitSegments(line) {
		fields := strings.Fields(seg)
		if len(fields) > 0 && fields[0] == "cd" {
			if len(fields) != 2 || !safeRelative(fields[1]) {
				return "", false
			}
			dir = path.Join(dir, fields[1])
			continue
		}
		if rel, ok := segmentWrapperPath(seg); ok {
			return path.Join(dir, rel), true
		}
	}
	return "", false
}

// safeRelative reports whether p is a plain relative path that stays under its base.
func safeRelative(p string) bool {
	return !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~") && !strings.HasPrefix(p, "-") &&
		!strings.Contains(p, "..") && !strings.ContainsAny(p, "$\"'`")
}

// segmentWrapperPath is wrapperPath for one segment without shell operators.
func segmentWrapperPath(seg string) (string, bool) {
	fields := strings.Fields(seg)
	for len(fields) > 0 && isAssignment(fields[0]) {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return "", false
	}
	candidate := fields[0]
	switch candidate {
	case "sh", "bash", "source", ".":
		if len(fields) < 2 || fields[1] == "-c" {
			return "", false
		}
		candidate = fields[1]
	}
	if !strings.HasSuffix(candidate, ".sh") && !strings.HasSuffix(candidate, ".bash") {
		return "", false
	}
	if strings.HasPrefix(candidate, "/") || strings.Contains(candidate, "..") || strings.ContainsAny(candidate, "$\"'") {
		return "", false
	}
	return strings.TrimPrefix(candidate, "./"), true
}
