package cmd

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// uncomment strips a leading YAML comment marker and the whitespace
// around it, so a documentation block written as "# contents: read"
// reads the same as a live "contents: read" line. action.yml is a
// composite action and cannot declare a real permissions block (that is
// the calling workflow's job), so it documents the one the README's
// snippet carries as a commented block instead; the scan below reads
// either shape.
func uncomment(trimmed string) string {
	trimmed = strings.TrimPrefix(trimmed, "#")
	return strings.TrimSpace(trimmed)
}

// permissionsBlockHasScopes reads path line by line and reports whether a
// "permissions:" block, live or documented as a comment, contains both
// an "actions: read" line and a "contents: read" line before the block
// ends (a line back at the block's own indentation, or less, that is not
// one of its scope lines). A line-based scan is enough here: every file
// keeps the block as a short, flat list of "<scope>: <level>" lines.
func permissionsBlockHasScopes(path string) (hasActions, hasContents bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = f.Close() }()

	inBlock := false
	blockIndent := -1
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		indent := len(line) - len(strings.TrimLeft(line, " \t#"))
		trimmed := uncomment(strings.TrimSpace(line))
		if trimmed == "" {
			continue
		}
		if trimmed == "permissions:" {
			inBlock, blockIndent = true, indent
			continue
		}
		if !inBlock {
			continue
		}
		if indent <= blockIndent {
			// Back at or above the block's own indentation: it is over.
			inBlock = false
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "actions:") && strings.Contains(trimmed, "read"):
			hasActions = true
		case strings.HasPrefix(trimmed, "contents:") && strings.Contains(trimmed, "read"):
			hasContents = true
		}
	}
	return hasActions, hasContents, scanner.Err()
}

// TestActionTemplateGrantsActionsRead pins the shape no existing scripts
// test covers: action.yml's composite steps run against the GitHub API
// (workflow states, runs, one job log) through the token the calling
// workflow supplies, so both the action's own description (README.md's
// GitHub snippet, the one new contributors copy) and the action.yml
// metadata that documents it must keep naming "actions: read" next to
// "contents: read". Only README.md carries the actual permissions block
// a workflow copies (action.yml is a composite action and cannot declare
// permissions for its caller), so this test reads both files for it.
func TestActionTemplateGrantsActionsRead(t *testing.T) {
	for _, path := range []string{"../action.yml", "../README.md"} {
		hasActions, hasContents, err := permissionsBlockHasScopes(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !hasContents {
			t.Errorf("%s: permissions: block is missing contents: read", path)
		}
		if !hasActions {
			t.Errorf("%s: permissions: block is missing actions: read", path)
		}
	}
}
