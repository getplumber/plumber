package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDiffLines(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b []string
		want []line
	}{
		{name: "equal", a: []string{"x"}, b: []string{"x"}, want: []line{{' ', "x"}}},
		{name: "added", a: nil, b: []string{"x"}, want: []line{{'+', "x"}}},
		{name: "removed", a: []string{"x"}, b: nil, want: []line{{'-', "x"}}},
		{
			name: "replaced in the middle",
			a:    []string{"a", "b", "c"},
			b:    []string{"a", "B", "c"},
			want: []line{{' ', "a"}, {'-', "b"}, {'+', "B"}, {' ', "c"}},
		},
		{
			name: "trailing lines",
			a:    []string{"a", "b"},
			b:    []string{"a", "c", "d"},
			want: []line{{' ', "a"}, {'-', "b"}, {'+', "c"}, {'+', "d"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := diffLines(tt.a, tt.b); !slices.Equal(got, tt.want) {
				t.Errorf("diffLines(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCollapse(t *testing.T) {
	t.Parallel()
	var diff []line
	for range 7 {
		diff = append(diff, line{' ', "same"})
	}
	diff = append(diff, line{'+', "new"})
	got := collapse(diff)
	want := []line{{' ', "same"}, {' ', "same"}, {'…', "3 unchanged lines"}, {' ', "same"}, {' ', "same"}, {'+', "new"}}
	if !slices.Equal(got, want) {
		t.Errorf("collapse() = %q, want %q", got, want)
	}
	short := []line{{' ', "a"}, {'-', "b"}}
	if got := collapse(short); !slices.Equal(got, short) {
		t.Errorf("collapse(%q) = %q, want it unchanged", short, got)
	}
}

func TestLines(t *testing.T) {
	t.Parallel()
	if got := lines(""); got != nil {
		t.Errorf("lines(\"\") = %q, want nil", got)
	}
	if got := lines("a\nb\n"); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("lines() = %q, want [a b]", got)
	}
}

func testGoldens() (v0, v1 map[string]golden) {
	v0 = map[string]golden{
		"TestRoot/same":    {Command: "plumber help", Stdout: "help\n"},
		"TestRoot/changed": {Command: "plumber bogus", Exit: 2, Stderr: "Error: bogus\n"},
		"TestRoot/flag":    {Command: "plumber analyze --nope", Exit: 2, Stderr: "Error: nope\n"},
		"TestRoot/file":    {Command: "plumber out", Files: map[string]string{"a.json": "1"}},
		"TestOld/gone":     {Command: "plumber old"},
	}
	v1 = map[string]golden{
		"TestRoot/same":    {Command: "plumber help", Stdout: "help\n"},
		"TestRoot/changed": {Command: "plumber bogus", Exit: 1, Stderr: "\x1b[31mERR\x1b[0m bogus\n"},
		"TestRoot/flag":    {Command: "plumber version --nope", Exit: 1, Stderr: "ERR nope\n"},
		"TestRoot/file":    {Command: "plumber out", Files: map[string]string{"a.json": "2"}},
		"TestRoot/new":     {Command: "plumber version --short", Stdout: "dev"},
	}
	return v0, v1
}

func testNotes() map[string]string {
	return map[string]string{
		"TestRoot/changed": "Exit 1.",
		"TestRoot/flag":    "Other command.",
		"TestRoot/file":    "Other file.",
		"TestRoot/new":     "New row.",
	}
}

func TestRender(t *testing.T) {
	t.Parallel()
	v0, v1 := testGoldens()
	doc, err := render(v0, v1, testNotes())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"| 3 | 1 | 1 | 1 |",
		"### TestRoot/changed\n\n`$ plumber bogus`, exit 1 (v0: 2)\n\nExit 1.\n",
		"- Error: bogus\n+ ␛[31mERR␛[0m bogus\n",
		"`$ plumber version --nope` (v0: `$ plumber analyze --nope`)",
		"The file `a.json` differs.",
		"### TestRoot/new\n\n`$ plumber version --short`, exit 0\n\nNew row.\n\nstdout:\n\n```\ndev\n```\n",
		"## Identical\n\n- `TestRoot/same`\n",
		"- TestOld (1): `gone`\n",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("render() lacks %q in:\n%s", want, doc)
		}
	}
}

func TestRenderEmpty(t *testing.T) {
	t.Parallel()
	doc, err := render(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(doc, "None."); got != 3 {
		t.Errorf("render() of nothing has %d \"None.\", want 3:\n%s", got, doc)
	}
}

func TestRenderNotes(t *testing.T) {
	t.Parallel()
	v0, v1 := testGoldens()
	missing := testNotes()
	delete(missing, "TestRoot/new")
	stale := testNotes()
	stale["TestRoot/same"] = "Not a change."
	for name, notes := range map[string]map[string]string{"missing": missing, "stale": stale} {
		if _, err := render(v0, v1, notes); err == nil || !strings.Contains(err.Error(), "notes.go") {
			t.Errorf("render() with a %s note = %v, want a notes.go error", name, err)
		}
	}
}

// TestRun builds the document from the real golden files and checks that the
// committed docs/golden-diff.md is up to date.
func TestRun(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..")
	out := filepath.Join(t.TempDir(), "golden-diff.md")
	err := run([]string{
		"-v0", filepath.Join(root, "test", "v0", "local", "testdata", "golden"),
		"-v1", filepath.Join(root, "test", "v1", "local", "testdata", "golden"),
		"-o", out,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(root, "docs", "golden-diff.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("docs/golden-diff.md is out of date: run `make -C v1 golden-diff`")
	}
}

func TestRunErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	if err := os.MkdirAll(bad, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "x.yaml"), []byte("exit: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown flag", args: []string{"-nope"}},
		{name: "missing v0 dir", args: []string{"-v0", filepath.Join(dir, "none"), "-v1", dir}},
		{name: "missing v1 dir", args: []string{"-v0", dir, "-v1", filepath.Join(dir, "none")}},
		{name: "invalid YAML", args: []string{"-v0", bad, "-v1", dir}},
		{name: "unwritable output", args: []string{"-v0", dir, "-v1", dir, "-o", filepath.Join(dir, "none", "x.md")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := run(tt.args); err == nil {
				t.Errorf("run(%q) = nil, want an error", tt.args)
			}
		})
	}
}
