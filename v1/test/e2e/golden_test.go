//go:build cli && e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// golden is one e2e call and the report it wrote, as
// testdata/<provider>/golden/<Test>/<row>.yaml stores it. An e2e row is
// compared on its JSON report, not on its terminal output: the text shows
// some findings only as attack paths, without their code.
type golden struct {
	Command string `yaml:"command"`
	Exit    int    `yaml:"exit"`
	// Report is the report.json of the call: keys sorted, 2-space indent,
	// normalized, without plumberConfig (the effective config dump, the same
	// in every row and already covered by the local `config view` rows).
	Report string `yaml:"report"`
}

// requiredKeys are the keys every golden file sets, so a forgotten key can't
// pass for exit 0 or an empty report.
var requiredKeys = []string{"command", "exit", "report"}

// readGolden reads the golden file at path. A key that is not a field of
// golden is an error, and so is a missing key of requiredKeys.
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
	var keys map[string]any
	if err := yaml.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, k := range requiredKeys {
		if _, ok := keys[k]; !ok {
			return nil, fmt.Errorf("%s: missing key %q", path, k)
		}
	}
	return &g, nil
}

// readReport returns the JSON report at path without plumberConfig, with its
// keys sorted and a 2-space indent.
func readReport(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the report: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep numbers as written
	var report map[string]any
	if err := dec.Decode(&report); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	delete(report, "plumberConfig")
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return "", fmt.Errorf("format %s: %w", path, err)
	}
	return b.String(), nil
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
	diffs = appendTextDiff(diffs, "report", got.Report, g.Report)
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
