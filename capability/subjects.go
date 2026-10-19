package capability

import (
	"path"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
)

// scriptLines returns the commands subject of a job's script entries (spec 4.3): each entry
// split on newlines (a `- |` entry holds several lines), an unquoted `#` comment removed,
// each line trimmed, the empty ones dropped. The line is otherwise kept whole: a pattern
// matches its text, so no tokenization, prefix catalogue or `sh -c` unwrapping is needed.
// Each step is one pass over the text, so the cost stays linear in it.
func scriptLines(entries []string) []string {
	var out []string
	for _, e := range entries {
		for _, l := range strings.Split(e, "\n") {
			if l = strings.TrimSpace(stripComment(l)); l != "" {
				out = append(out, l)
			}
		}
	}
	return out
}

// stripComment removes a shell comment from one line (no newline): an unquoted `#` that
// starts a word (at the start of the line, after whitespace or after a shell operator) and
// everything after it. A `#` inside a word (`foo#bar`, `$#`) or inside quotes is kept. A
// quote left open at the end of the line is closed there: a line is read on its own.
func stripComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#' && (i == 0 || wordBoundary(line[i-1])):
			return line[:i]
		}
	}
	return line
}

// wordBoundary reports whether a word starts right after c: whitespace or a shell operator.
func wordBoundary(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\v', '\f', ';', '&', '|', '(', ')':
		return true
	}
	return false
}

// splitSegments cuts a script entry into the segments the wrapper rule reads: each line
// (comment removed, see stripComment), then each part of it between the shell operators
// `&&`, `||`, `;` and `|`, outside quotes.
func splitSegments(entry string) []string {
	var segs []string
	for _, line := range strings.Split(entry, "\n") {
		line = stripComment(line)
		var quote byte
		start := 0
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '&' && i+1 < len(line) && line[i+1] == '&', c == '|' && i+1 < len(line) && line[i+1] == '|':
				segs = append(segs, line[start:i])
				i++
				start = i + 1
			case c == ';' || c == '|':
				segs = append(segs, line[start:i])
				start = i + 1
			}
		}
		segs = append(segs, line[start:])
	}
	return segs
}

// containerRunBoolFlags are the `docker|podman|nerdctl run` flags that take no value field
// (`--` ends the options and takes none either).
var containerRunBoolFlags = map[string]bool{
	"--rm": true, "-d": true, "--detach": true, "-i": true, "--interactive": true, "-t": true, "--tty": true,
	"--privileged": true, "--init": true, "--no-healthcheck": true, "--read-only": true, "--sig-proxy": true,
	"-P": true, "--publish-all": true, "-q": true, "--quiet": true, "--oom-kill-disable": true, "--help": true,
	"--": true,
}

// containerRunImage returns the image a script line runs through `docker run`, `podman run`
// or `nerdctl run` (the first such pair of fields on the line, a leading quote or a path
// before the binary tolerated, so `sh -c "docker run ..."` and `/usr/bin/docker run` count):
// the first field after `run` that is neither a flag (a leading `-`) nor a flag's value,
// unquoted. A flag holding `=`, a boolean flag (containerRunBoolFlags) or a combined boolean
// short form of `d`, `i` and `t` (`-it`, `-dit`) consumes nothing; every other flag consumes
// the next field as its value (`-v x:y`, `--entrypoint sh`). The fields after the image are
// the container's command, never an image.
func containerRunImage(line string) (string, bool) {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		switch path.Base(strings.TrimLeft(fields[i], `"'`)) {
		case "docker", "podman", "nerdctl":
			if fields[i+1] != "run" {
				continue
			}
			args := fields[i+2:]
			for k := 0; k < len(args); k++ {
				f := args[k]
				if !strings.HasPrefix(f, "-") {
					if img := strings.Trim(f, `"'`); img != "" {
						return img, true
					}
					return "", false
				}
				if !strings.Contains(f, "=") && !containerRunBoolFlags[f] && !combinedDITFlag(f) {
					k++ // the flag's value
				}
			}
			return "", false
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

// The cd chain the wrapper rule follows is short: a real script changes directory a few
// times at most. Past maxCdSegments cd segments, or once the directory would exceed
// maxCdDirBytes, the search ends (no wrapper evidence past that point), which keeps the
// rule linear on a 256 KiB `cd a && cd a && ...` line.
const (
	maxCdSegments = 16
	maxCdDirBytes = 1024
)

// wrapperPaths reports the repository-relative shell scripts a script entry runs, in order:
// `./x.sh`, `x.sh`, `sh x.sh`, `bash ./x.bash`, `source x.sh`, `. x.sh`, in every segment
// the shell operators and newlines split (`make && ./x.sh`, `./x.sh;`, each line of a `- |`
// entry); a commented-out call is not one. The launcher's own options are skipped first
// (`bash -x ci/scan.sh`, `sh -euo pipefail scan.sh`), see segmentWrapperPath. A relative
// `cd dir` segment before a call is applied (`cd ci && ./x.sh` runs ci/x.sh); a cd that is
// absolute, bare, variable or escapes the root ends the search, since a later script is then
// no longer known to be under the root, and so does a cd chain past maxCdSegments or
// maxCdDirBytes. Absolute paths and paths with `..` are refused here (ResolveWithinRepo
// refuses them again at read time).
func wrapperPaths(entry string) []string {
	var out []string
	dir := ""
	cds := 0
	for _, seg := range splitSegments(entry) {
		fields := strings.Fields(seg)
		if len(fields) > 0 && fields[0] == "cd" {
			cds++
			if len(fields) != 2 || !safeRelative(fields[1]) || cds > maxCdSegments || len(dir)+1+len(fields[1]) > maxCdDirBytes {
				return out
			}
			dir = path.Join(dir, fields[1])
			continue
		}
		if rel, ok := segmentWrapperPath(fields); ok {
			out = append(out, path.Join(dir, rel))
		}
	}
	return out
}

// safeRelative reports whether p is a plain relative path that stays under its base.
func safeRelative(p string) bool {
	return !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~") && !strings.HasPrefix(p, "-") &&
		!strings.Contains(p, "..") && !strings.ContainsAny(p, "$\"'`")
}

// segmentWrapperPath is wrapperPath for the fields of one segment without shell operators:
// leading VAR=value assignments skipped, then an optional `sh`, `bash`, `source` or `.`. A
// launcher may carry options before its script (`bash -x ci/scan.sh`, `sh -euo pipefail
// scan.sh`): a field starting with `-` is skipped; `-o` and `+o` consume the next field as
// their value, and so does a combined short option whose last letter is `o` (`-euo` takes
// `pipefail`); `--` ends the options, and the field right after it is the candidate; `-c`
// anywhere among the options (an inline command string, read by the commands subject, not
// this one) still yields no wrapper; running out of fields yields no wrapper. The loop is one
// linear pass over the options, so a long option list stays linear.
func segmentWrapperPath(fields []string) (string, bool) {
	for len(fields) > 0 && isAssignment(fields[0]) {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return "", false
	}
	candidate := fields[0]
	switch candidate {
	case "sh", "bash", "source", ".":
		rest := fields[1:]
		i := 0
		for i < len(rest) {
			f := rest[i]
			if f == "--" {
				i++
				break
			}
			if f == "-o" || f == "+o" {
				i += 2
				continue
			}
			if !strings.HasPrefix(f, "-") {
				break
			}
			if strings.ContainsRune(f[1:], 'c') {
				return "", false
			}
			i++
			if strings.HasSuffix(f, "o") {
				i++ // a combined short option ending in o, e.g. -euo, takes a value too
			}
		}
		if i >= len(rest) {
			return "", false
		}
		candidate = rest[i]
	}
	if !strings.HasSuffix(candidate, ".sh") && !strings.HasSuffix(candidate, ".bash") {
		return "", false
	}
	if strings.HasPrefix(candidate, "/") || strings.Contains(candidate, "..") || strings.ContainsAny(candidate, "$\"'") {
		return "", false
	}
	return strings.TrimPrefix(candidate, "./"), true
}

// isAssignment reports whether word is a shell VAR=value assignment.
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

// parseImageRef splits an image reference into the registry and the name imageKey reads:
// the part before the first `/` is a registry when it holds a `.` or a `:` or is
// `localhost`; otherwise the whole reference is a Docker Hub name.
func parseImageRef(ref string) *ir.Image {
	if i := strings.IndexByte(ref, '/'); i > 0 {
		if host := ref[:i]; strings.ContainsAny(host, ".:") || host == "localhost" {
			return &ir.Image{Registry: host, Name: ref[i+1:]}
		}
	}
	return &ir.Image{Name: ref}
}

// imageKey is the images subject of one image (spec 4.3): `<registry>/<name>` with the tag
// and digest stripped, a Docker Hub alias canonicalized, a bare name keyed under docker.io
// (`zricethezav/gitleaks` and `docker.io/zricethezav/gitleaks` compare equal). An unknown or
// empty registry (an unresolved `$VAR` reference) is read from the name itself when the name
// starts with a registry host.
func imageKey(img *ir.Image) string {
	registry, name := img.Registry, img.Name
	if registry == "" || registry == "unknown" {
		parsed := parseImageRef(name)
		registry, name = parsed.Registry, parsed.Name
	}
	if i := strings.IndexAny(name, ":@"); i >= 0 {
		name = name[:i]
	}
	registry = utils.CanonicalizeDockerHubRegistry(registry)
	if registry == "" {
		registry = "docker.io"
	}
	return registry + "/" + name
}
