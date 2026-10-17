package cmd

import "strings"

// The provenance chain of a nested finding (spec 2026-10-16 section 8) is
// set apart wherever the terminal prints it (maintainer, round 11 of PR
// 549): in backticks, and in the report's dim style with colour on. The
// wrap is presentation only: the finding message, the JSON, SARIF, GitLab
// SAST and PBOM outputs and every identity keep the bare chain.

// chainIntro opens a chain in a rendered text.
const chainIntro = " via "

// tickChain wraps every chain of s in backticks: the references after
// " via ", " > " separated. A closing punctuation stays outside, a chain
// already in backticks and a " via " that names no reference are left
// alone.
func tickChain(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, chainIntro)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		head, rest := s[:i+len(chainIntro)], s[i+len(chainIntro):]
		b.WriteString(head)
		n := chainLength(rest)
		if n == 0 {
			s = rest
			continue
		}
		b.WriteString("`" + rest[:n] + "`")
		s = rest[n:]
	}
}

// chainLength is how many bytes at the start of s are a chain: a
// reference, then any number of " > " and a reference, a closing
// punctuation left out. 0 when s does not start on a reference.
func chainLength(s string) int {
	n := 0
	for {
		word := s[n:]
		if sp := strings.IndexByte(word, ' '); sp >= 0 {
			word = word[:sp]
		}
		ref := strings.TrimRight(word, ".,;:)")
		if !chainRef(ref) {
			return n
		}
		end := n + len(ref)
		if len(ref) < len(word) || !strings.HasPrefix(s[end:], " > ") {
			return end
		}
		next := s[end+len(" > "):]
		if sp := strings.IndexByte(next, ' '); sp >= 0 {
			next = next[:sp]
		}
		if !chainRef(strings.TrimRight(next, ".,;:)")) {
			return end
		}
		n = end + len(" > ")
	}
}

// chainRef says whether word is a reference a chain holds: a remote
// action or workflow (owner/repo[/path]@ref) or a local composite (./x).
func chainRef(word string) bool {
	if strings.ContainsAny(word, "`\x1b") {
		return false
	}
	return strings.HasPrefix(word, "./") || strings.Contains(word, "/") && strings.Contains(word, "@")
}

// dimChains sets every backticked chain of lines (opened by "via `", or by
// a backtick opening a line that follows one ending on "via") in dim,
// backticks included, after the lines were laid out: a chain broken
// across lines is dim on each of its lines, from where it resumes, so the
// indent and the tree drawing under it stay plain. dim "" (colour off)
// returns lines as they are. Escapes are zero width to the wrap measure
// (cells), so the layout is the colour off one.
func dimChains(lines []string, dim, reset string) []string {
	if dim == "" {
		return lines
	}
	out := make([]string, len(lines))
	open, lead := false, false
	for i, l := range lines {
		var b strings.Builder
		if open {
			shut := strings.IndexByte(l, '`')
			if shut < 0 {
				start := chainResume(l, len(l))
				out[i] = l[:start] + dim + l[start:] + reset
				continue
			}
			start := chainResume(l, shut)
			b.WriteString(l[:start] + dim + l[start:shut+1] + reset)
			l, open = l[shut+1:], false
		}
		for {
			tick := chainOpening(l, lead)
			lead = false
			if tick < 0 {
				b.WriteString(l)
				break
			}
			b.WriteString(l[:tick] + dim)
			end := strings.IndexByte(l[tick+1:], '`')
			if end < 0 {
				b.WriteString(l[tick:] + reset)
				open = true
				break
			}
			end += tick + 1
			b.WriteString(l[tick:end+1] + reset)
			l = l[end+1:]
		}
		out[i] = b.String()
		trimmed := strings.TrimRight(lines[i], " ")
		lead = !open && (strings.HasSuffix(trimmed, " via") || trimmed == "via")
	}
	return out
}

// chainOpening is where the next chain of l opens, its backtick: after
// "via ", or, when the line before ended on "via" (lead), the backtick
// the line opens on after its indent and tree drawing. -1 when none.
func chainOpening(l string, lead bool) int {
	if lead {
		if at := strings.IndexByte(l, '`'); at >= 0 && strings.Trim(l[:at], " \u2502") == "" {
			return at
		}
	}
	if at := strings.Index(l, "via `"); at >= 0 {
		return at + len("via ")
	}
	return -1
}

// chainResume is where the chain resumes on a line it continues on, end
// being where its part on that line ends: the start of the run of
// references and ">" right before end.
func chainResume(line string, end int) int {
	start := end
	for {
		head := line[:start]
		if start < end {
			head = strings.TrimRight(head, " ")
		}
		sp := strings.LastIndexByte(head, ' ')
		word := head[sp+1:]
		if word == "" || word != ">" && !chainRef(word) {
			return start
		}
		start = sp + 1
	}
}

// styleChain is a one-line text with its chains in backticks and dim
// (the report's raw sequences, empty with colour off).
func styleChain(s string) string {
	return dimChains([]string{tickChain(s)}, colorDim, colorReset)[0]
}
