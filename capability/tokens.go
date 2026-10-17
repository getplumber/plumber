package capability

import (
	"path"
	"strings"
)

// commandTokens returns the command words of one script line: the first word of the line
// and the first word after each `&&`, `||`, `;` and `|`, reduced to their base name, with a
// leading VAR=value assignment skipped; the argument of `sh -c "..."` / `bash -c '...'` is
// tokenized in turn. It is a recognizer's input, not a shell: quotes are only used to find
// the -c argument, and nothing is evaluated. A line may hold several lines (a `- |` script
// entry): each newline is a segment boundary.
func commandTokens(line string) []string {
	return segmentTokens(line, true)
}

// segmentTokens is commandTokens; unwrap says whether a `sh -c` argument is tokenized in
// turn. The unwrapped argument is tokenized with unwrap false, so the unwrap is one level
// deep and a line of repeated `sh -c` costs linear time, not quadratic (script lines come
// from any analyzed project's CI config).
func segmentTokens(line string, unwrap bool) []string {
	var out []string
	for _, seg := range splitSegments(line) {
		fields := strings.Fields(seg)
		for len(fields) > 0 && isAssignment(fields[0]) {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		cmd := path.Base(fields[0])
		out = append(out, cmd)
		if unwrap && (cmd == "sh" || cmd == "bash" || cmd == "dash" || cmd == "zsh") && len(fields) >= 3 && fields[1] == "-c" {
			out = append(out, segmentTokens(unquote(strings.Join(fields[2:], " ")), false)...)
		}
	}
	return out
}

// splitSegments cuts a line at the shell operators and at newlines, outside quotes: each
// line of a multi-line script entry is its own segment (a CR before the newline is left to
// strings.Fields, which drops it as whitespace).
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
