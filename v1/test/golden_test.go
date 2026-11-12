//go:build cli

package test

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// golden is one call and what it produced, as testdata/golden/<name>.yaml
// stores it.
type golden struct {
	Command string            `yaml:"command"`
	Exit    int               `yaml:"exit"`
	Stdout  string            `yaml:"stdout"`
	Stderr  string            `yaml:"stderr"`
	Files   map[string]string `yaml:"files,omitempty"` // path in the work dir: content
}

// readGolden reads the golden file at path. A key that is not a field of
// golden is an error, so a typo can't pass for an empty field.
func readGolden(path string) (*golden, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the golden file: %w", err)
	}
	var g golden
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &g, nil
}

// cmp describes each field where got differs from g, the golden file, or
// returns "" when they match.
func (g *golden) cmp(got *golden) string {
	var diffs []string
	if got.Command != g.Command {
		diffs = append(diffs, fmt.Sprintf("command: got %q, want %q", got.Command, g.Command))
	}
	if got.Exit != g.Exit {
		diffs = append(diffs, fmt.Sprintf("exit: got %d, want %d", got.Exit, g.Exit))
	}
	diffs = appendTextDiff(diffs, "stdout", got.Stdout, g.Stdout)
	diffs = appendTextDiff(diffs, "stderr", got.Stderr, g.Stderr)
	paths := slices.Concat(slices.Collect(maps.Keys(g.Files)), slices.Collect(maps.Keys(got.Files)))
	slices.Sort(paths)
	for _, p := range slices.Compact(paths) {
		gotData, inGot := got.Files[p]
		wantData, inWant := g.Files[p]
		switch {
		case !inGot:
			diffs = append(diffs, fmt.Sprintf("file %s: in the golden file but not in the row's outputFiles", p))
		case !inWant:
			diffs = append(diffs, fmt.Sprintf("file %s: in the row's outputFiles but not in the golden file", p))
		default:
			diffs = appendTextDiff(diffs, "file "+p, gotData, wantData)
		}
	}
	return strings.Join(diffs, "\n")
}

// appendTextDiff appends to diffs the first line where got differs from want,
// if they differ.
func appendTextDiff(diffs []string, field, got, want string) []string {
	if got == want {
		return diffs
	}
	wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := range max(len(wantLines), len(gotLines)) {
		w, g := lineAt(wantLines, i), lineAt(gotLines, i)
		if w != g {
			return append(diffs, fmt.Sprintf("%s differs at line %d:\n  got:  %q\n  want: %q", field, i+1, g, w))
		}
	}
	// Same lines, but one has more trailing empty lines.
	return append(diffs, fmt.Sprintf("%s differs: got %d lines, want %d", field, len(gotLines), len(wantLines)))
}

// lineAt returns lines[i], or "" past the end.
func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return ""
}
