//go:build cli

package local

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// cliCase is one row of a table: one plumber call and what it must produce.
type cliCase struct {
	name        string     // row name, and the golden file testdata/golden/<Test>/<name>.yaml
	args        []string   // arguments of the plumber call under test
	inputs      []string   // paths under testdata/inputs copied into the work dir
	setup       [][]string // plumber calls run first, in the same work dir and home (not compared)
	outputFiles []string   // files the call writes, compared with the golden
	// sortLines compares the output lines sorted, for a call that prints them
	// in random order (a CLI bug).
	sortLines bool
}

// runCase compares a run of tt with testdata/golden/<Test>/<row>.yaml, named
// after the subtest.
func runCase(t *testing.T, tt cliCase) {
	t.Helper()
	path := filepath.Join("testdata", "golden", t.Name()+".yaml")
	want, err := readGolden(path)
	if err != nil {
		t.Fatal(err)
	}
	got := run(t, tt)
	if diff := want.cmp(got); diff != "" {
		t.Errorf("%s: output differs from %s:\n%s", got.Command, path, diff)
	}
}

// run runs the setup calls and the call under test in a fresh sandbox and
// returns the normalized result: exit code, stdout, stderr and the files the
// call wrote.
func run(t *testing.T, tt cliCase) *golden {
	t.Helper()
	sb := newSandbox(t, tt)

	for _, args := range tt.setup {
		if _, stderr, code := sb.runPlumber(t.Context(), args); code != 0 {
			t.Fatalf("setup `%s` exited %d\nstderr:\n%s", plumberCall(args), code, stderr)
		}
	}

	stdout, stderr, code := sb.runPlumber(t.Context(), tt.args)

	got, err := sb.newGolden(tt, stdout, stderr, code)
	if err != nil {
		t.Fatal(err)
	}
	// Sort after normalizing, so the order doesn't depend on the sandbox paths.
	if tt.sortLines {
		got.Stdout, got.Stderr = sortLines(got.Stdout), sortLines(got.Stderr)
	}
	return got
}

// plumberCall returns how a plumber call with args reads in messages and
// golden files.
func plumberCall(args []string) string {
	return "plumber " + strings.Join(args, " ")
}

// sortLines returns s with its lines sorted.
func sortLines(s string) string {
	lines := strings.Split(s, "\n")
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}
