package github

import "strings"

// shellToken is one token of a shell line, as splitShellLine reads it:
// a word (quotes removed, command substitutions kept raw) or a control
// operator (`;`, `&&`, `||`, `|`, `&`, `(`, `)`).
type shellToken struct {
	val string
	op  bool
}

// splitShellLine splits one shell line into words and control
// operators, honouring single and double quotes, backslash escapes,
// `$(...)` and backtick command substitutions (kept whole inside the
// word that holds them). It stops at a `#` that starts a comment (at
// the start of a word, outside quotes) and returns the byte offset
// where that comment starts (len(line) when there is none).
func splitShellLine(line string) (tokens []shellToken, commentAt int) {
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			tokens = append(tokens, shellToken{val: cur.String()})
			cur.Reset()
			inWord = false
		}
	}
	i := 0
	for i < len(line) {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			flush()
			i++
		case c == '#' && !inWord:
			flush()
			return tokens, i
		case c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			flush()
			op := string(c)
			if (c == '&' || c == '|') && i+1 < len(line) && line[i+1] == c {
				op += string(c)
			}
			tokens = append(tokens, shellToken{val: op, op: true})
			i += len(op)
		case c == '\'':
			inWord = true
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				cur.WriteString(line[i+1:])
				i = len(line)
				continue
			}
			cur.WriteString(line[i+1 : i+1+end])
			i += end + 2
		case c == '"':
			inWord = true
			i = readDoubleQuoted(line, i+1, &cur)
		case c == '\\':
			inWord = true
			if i+1 < len(line) {
				cur.WriteByte(line[i+1])
			}
			i += 2
		case c == '$' && i+1 < len(line) && line[i+1] == '(':
			inWord = true
			end := substitutionEnd(line, i+2)
			cur.WriteString(line[i:end])
			i = end
		case c == '`':
			inWord = true
			end := backtickEnd(line, i+1)
			cur.WriteString(line[i:end])
			i = end
		default:
			inWord = true
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return tokens, len(line)
}

// readDoubleQuoted appends the content of a double-quoted string
// starting at line[i] (just after the opening quote) to cur, keeping
// command substitutions raw, and returns the offset just after the
// closing quote.
func readDoubleQuoted(line string, i int, cur *strings.Builder) int {
	for i < len(line) {
		c := line[i]
		switch {
		case c == '"':
			return i + 1
		case c == '\\' && i+1 < len(line):
			cur.WriteByte(line[i+1])
			i += 2
		case c == '$' && i+1 < len(line) && line[i+1] == '(':
			end := substitutionEnd(line, i+2)
			cur.WriteString(line[i:end])
			i = end
		case c == '`':
			end := backtickEnd(line, i+1)
			cur.WriteString(line[i:end])
			i = end
		default:
			cur.WriteByte(c)
			i++
		}
	}
	return i
}

// substitutionEnd returns the offset just after the `)` closing a
// `$(` whose content starts at line[i], skipping quoted text and
// nested parentheses (len(line) when it is never closed).
func substitutionEnd(line string, i int) int {
	depth := 1
	for i < len(line) {
		switch line[i] {
		case '\\':
			i += 2
			continue
		case '\'':
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				return len(line)
			}
			i += end + 2
			continue
		case '"':
			var discard strings.Builder
			i = readDoubleQuoted(line, i+1, &discard)
			continue
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return len(line)
}

// backtickEnd returns the offset just after the backtick closing a
// substitution whose content starts at line[i] (len(line) when it is
// never closed).
func backtickEnd(line string, i int) int {
	for i < len(line) {
		switch line[i] {
		case '\\':
			i += 2
			continue
		case '`':
			return i + 1
		}
		i++
	}
	return len(line)
}

// stripShellComment returns line without its trailing shell comment.
func stripShellComment(line string) string {
	_, at := splitShellLine(line)
	return line[:at]
}

// commandStartWords are the reserved words after which the next word
// starts a command of its own.
var commandStartWords = map[string]bool{
	"then": true, "do": true, "else": true, "elif": true, "if": true,
	"while": true, "until": true, "{": true, "!": true,
}

// digestIsComparisonOperand reports whether digest is one side of an
// `=`, `==` or `!=` comparison in line: inside a `[ ... ]` or
// `[[ ... ]]` test, or a `test` command, that starts a command (line
// start, after a control operator, or after a reserved word such as
// `then` or `do`). A bracket that does not start a command (inside an
// echo argument, say), or a digest that is not an operand (a comment,
// another argument), never counts.
func digestIsComparisonOperand(line, digest string) bool {
	tokens, _ := splitShellLine(line)
	atStart := true
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok.op {
			atStart = true
			continue
		}
		if !atStart {
			continue
		}
		var args []shellToken
		switch tok.val {
		case "[":
			args, i = collectTestArgs(tokens, i+1, "]", false)
		case "[[":
			args, i = collectTestArgs(tokens, i+1, "]]", true)
		case "test":
			args, i = collectTestArgs(tokens, i+1, "", false)
		default:
			atStart = commandStartWords[tok.val]
			continue
		}
		if comparesDigest(args, digest) {
			return true
		}
		atStart = false
	}
	return false
}

// collectTestArgs gathers the arguments of a test construct starting
// at tokens[i], up to the closing word (`]` or `]]`), or, for `test`
// (closing ""), up to the next control operator. Inside `[[ ... ]]`
// the operators `&&`, `||`, `(` and `)` belong to the expression. It
// returns the arguments (nil when a closing bracket is missing) and
// the index of the last token consumed.
func collectTestArgs(tokens []shellToken, i int, closing string, inDouble bool) ([]shellToken, int) {
	var args []shellToken
	for ; i < len(tokens); i++ {
		tok := tokens[i]
		if !tok.op && closing != "" && tok.val == closing {
			return args, i
		}
		if tok.op && !inDouble {
			if closing == "" {
				return args, i - 1
			}
			return nil, i - 1
		}
		args = append(args, tok)
	}
	if closing == "" {
		return args, i
	}
	return nil, i
}

// comparesDigest reports whether digest is a direct operand of an `=`,
// `==` or `!=` among args.
func comparesDigest(args []shellToken, digest string) bool {
	for j, a := range args {
		if a.op || (a.val != "=" && a.val != "==" && a.val != "!=") {
			continue
		}
		if j > 0 && !args[j-1].op && strings.EqualFold(args[j-1].val, digest) {
			return true
		}
		if j+1 < len(args) && !args[j+1].op && strings.EqualFold(args[j+1].val, digest) {
			return true
		}
	}
	return false
}
