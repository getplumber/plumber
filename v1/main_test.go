//go:build cli

// Package v1 holds the CLI test suite of the refactoring (getplumber/monorepo#640).
//
// Each CLI input is one table row, run against the built binary as a
// subprocess and compared with a golden file. The suite has two files:
//
//   - main_test.go: TestMain, the row type and the helpers every test uses.
//   - integration_test.go: the local rows, which cover every input that
//     makes no backend request. They run with no token and with every proxy
//     pointed at a closed port, so a row that tries the network fails.
//     TestCoverage also lives there. `make test-integration` (#641).
//
// UPDATE=1 rewrites the golden files; review the diff before committing it.
package v1

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// closedPort refuses every connection. Local rows send all their traffic
// there, so any request fails instead of reaching a backend.
const closedPort = "http://127.0.0.1:9"

type mode string

const local mode = "local"

// cliCase is one row of the suite: one plumber call and what it must produce.
type cliCase struct {
	name     string // golden file: testdata/golden/<mode>/<name>.golden
	mode     mode
	args     []string   // arguments of the plumber call under test
	setup    [][]string // plumber calls run first, in the same work dir and home (not compared)
	inputs   []string   // paths under testdata/inputs copied into the work dir
	wantExit int
	files    []string // files the call writes, compared with the golden
	sorted   bool     // output lines are compared sorted: the CLI prints them in random order (a bug)
}

// run returns a local row.
func run(name string, exit int, args ...string) cliCase {
	return cliCase{name: name, mode: local, args: args, wantExit: exit}
}

// with copies the given testdata/inputs paths into the work dir.
func (c cliCase) with(inputs ...string) cliCase {
	c.inputs = append(c.inputs, inputs...)
	return c
}

// writes adds files the call writes to the compared output.
func (c cliCase) writes(files ...string) cliCase {
	c.files = append(c.files, files...)
	return c
}

// after runs `plumber args...` before the call under test.
func (c cliCase) after(args ...string) cliCase {
	c.setup = append(c.setup, args)
	return c
}

// unordered compares the output lines sorted.
func (c cliCase) unordered() cliCase {
	c.sorted = true
	return c
}

// command is one node of the binary's command tree, read from --help.
type command struct {
	path  []string
	flags map[string]string // long name -> shorthand ("" if none)
}

var (
	plumberBin string
	tree       []command
)

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "plumber-v1-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	plumberBin = filepath.Join(dir, "plumber")
	// -buildvcs=false keeps the version "dev". Outputs stay stable, and the
	// update check (cmd/update_check.go) skips dev builds.
	build := exec.Command("go", "build", "-buildvcs=false", "-o", plumberBin, "github.com/getplumber/plumber")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build plumber:", err)
		os.Exit(1)
	}
	tree, err = readTree()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read the command tree:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// runCases runs each row as a parallel subtest and compares it with its
// golden file.
func runCases(t *testing.T, cases []cliCase) {
	for _, c := range cases {
		t.Run(string(c.mode)+"/"+c.name, func(t *testing.T) {
			t.Parallel() // each row has its own work dir and home
			got := runCase(t, c)
			compareGolden(t, filepath.Join("testdata", "golden", string(c.mode), c.name+".golden"), got)
		})
	}
}

// allCases returns every row: the local rows and the generated --help rows.
func allCases() []cliCase {
	return append(append([]cliCase(nil), localCases...), helpCases()...)
}

// helpCases returns a --help row for every command of the tree.
func helpCases() []cliCase {
	var out []cliCase
	for _, cmd := range tree {
		name := "help-flag"
		if len(cmd.path) > 0 {
			name += "-" + strings.Join(cmd.path, "-")
		}
		args := append(append([]string(nil), cmd.path...), "--help")
		out = append(out, run(name, 0, args...))
	}
	return out
}

// inputsOf returns the inputs a call exercises: its command path ("config
// view") and each flag ("config view --explain"), with shorthands resolved.
func inputsOf(args []string) []string {
	byPath := map[string]command{}
	for _, c := range tree {
		byPath[strings.Join(c.path, " ")] = c
	}
	var path []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		next := strings.TrimSpace(strings.Join(append(append([]string(nil), path...), a), " "))
		if _, ok := byPath[next]; !ok {
			break
		}
		path = append(path, a)
	}
	name := strings.Join(path, " ")
	if len(path) > 0 && path[0] == "help" { // `plumber help analyze` runs help, not analyze
		name = "help"
	}
	cmd, root := byPath[name], byPath[""]
	out := []string{name}
	for _, a := range args {
		long := longFlag(a, cmd, root)
		if long == "" {
			continue
		}
		if _, ok := cmd.flags[long]; !ok {
			if _, global := root.flags[long]; global {
				out = append(out, "--"+long)
				continue
			}
		}
		out = append(out, strings.TrimSpace(name+" --"+long))
	}
	return out
}

// longFlag returns the long name of the flag in arg, looking up a shorthand
// in cmd first and then in the root command. It returns "" when arg is not a
// flag.
func longFlag(arg string, cmd, root command) string {
	switch {
	case strings.HasPrefix(arg, "--"):
		name, _, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		return name
	case strings.HasPrefix(arg, "-") && len(arg) == 2:
		for _, c := range []command{cmd, root} {
			for long, short := range c.flags {
				if short == arg[1:] {
					return long
				}
			}
		}
	}
	return ""
}

var (
	commandLine = regexp.MustCompile(`^  (\S+)\s{2,}`)
	flagLine    = regexp.MustCompile(`^\s+(?:-(\w), )?--([\w-]+)`)
)

// readTree reads the command tree from the --help output of every command.
func readTree() ([]command, error) {
	var out []command
	queue := append([][]string{{}}, hiddenCommands...)
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		help, err := exec.Command(plumberBin, append(append([]string(nil), path...), "--help")...).Output()
		if err != nil {
			return nil, fmt.Errorf("plumber %s --help: %w", strings.Join(path, " "), err)
		}
		cmd := command{path: path, flags: map[string]string{}}
		section := ""
		for _, line := range strings.Split(string(help), "\n") {
			switch {
			case strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " "):
				section = line
			case section == "Available Commands:":
				if m := commandLine.FindStringSubmatch(line); m != nil {
					queue = append(queue, append(append([]string(nil), path...), m[1]))
				}
			case section == "Flags:":
				if m := flagLine.FindStringSubmatch(line); m != nil {
					cmd.flags[m[2]] = m[1]
				}
			}
		}
		out = append(out, cmd)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i].path, " ") < strings.Join(out[j].path, " ")
	})
	return out, nil
}

// sandbox is the private file system of one row.
type sandbox struct {
	root string // parent of work and home, also TMPDIR
	work string // working directory of the plumber calls
	home string
}

// newSandbox creates the work dir and home of a row and copies its inputs
// into the work dir.
func newSandbox(t *testing.T, c cliCase) sandbox {
	t.Helper()
	root := t.TempDir()
	// macOS returns a symlinked temp dir; resolve it so normalize matches the
	// paths the CLI prints.
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	sb := sandbox{root: root, work: filepath.Join(root, "work"), home: filepath.Join(root, "home")}
	for _, d := range []string{sb.work, sb.home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, in := range c.inputs {
		copyPath(t, filepath.Join("testdata", "inputs", in), filepath.Join(sb.work, in))
	}
	return sb
}

// caseEnv returns the environment of a row. Every proxy points at closedPort,
// so a request fails instead of reaching a backend.
func caseEnv(sb sandbox) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + sb.home,
		"XDG_CACHE_HOME=" + filepath.Join(sb.home, ".cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(sb.home, ".config"),
		"GH_CONFIG_DIR=" + filepath.Join(sb.home, "gh"), // no `gh auth token` fallback
		"TMPDIR=" + sb.root,
		"TERM=dumb",
		"HTTPS_PROXY=" + closedPort,
		"HTTP_PROXY=" + closedPort,
		"ALL_PROXY=" + closedPort,
		"NO_PROXY=",
	}
}

// runCase runs the setup calls and the call under test in a fresh sandbox,
// and returns the normalized transcript: exit code, stdout, stderr and the
// files the call wrote.
func runCase(t *testing.T, c cliCase) string {
	t.Helper()
	sb := newSandbox(t, c)
	env := caseEnv(sb)

	for _, args := range c.setup {
		if _, _, code := runPlumber(sb.work, env, args); code != 0 {
			t.Fatalf("setup `plumber %s` exited %d", strings.Join(args, " "), code)
		}
	}
	stdout, stderr, code := runPlumber(sb.work, env, c.args)
	if c.sorted {
		stdout, stderr = sortLines(stdout), sortLines(stderr)
	}
	if code != c.wantExit {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, c.wantExit, stdout, stderr)
	}
	return normalize(transcript(t, c, sb.work, stdout, stderr, code), sb)
}

// transcript formats a call and its results the way golden files store them.
func transcript(t *testing.T, c cliCase, work, stdout, stderr string, code int) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "$ plumber %s\nexit: %d\n--- stdout\n%s\n--- stderr\n%s\n", strings.Join(c.args, " "), code, stdout, stderr)
	for _, f := range c.files {
		data, err := os.ReadFile(filepath.Join(work, f))
		if err != nil {
			t.Errorf("expected file %s: %v", f, err)
			continue
		}
		fmt.Fprintf(&b, "--- file %s\n%s\n", f, data)
	}
	return b.String()
}

// sortLines returns s with its lines sorted.
func sortLines(s string) string {
	lines := strings.Split(s, "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// runPlumber runs the built binary in dir with exactly env. A run that could
// not start returns exit code -1 with the error appended to stderr.
func runPlumber(dir string, env, args []string) (stdout, stderr string, code int) {
	cmd := exec.Command(plumberBin, args...)
	cmd.Dir, cmd.Env = dir, env
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if err == nil {
		return o.String(), e.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return o.String(), e.String(), exitErr.ExitCode()
	}
	return o.String(), e.String() + err.Error(), -1
}

var (
	timestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?`)
	urnUUID   = regexp.MustCompile(`urn:uuid:[0-9a-f-]{36}`) // CycloneDX serialNumber, random per run
	epochMs   = regexp.MustCompile(`\b1[78]\d{11}\b`)        // epoch milliseconds, 2023-2033 (OCSF time, correlation_uid)
)

// normalize replaces what changes from one run to the next: temp paths and
// timestamps.
func normalize(s string, sb sandbox) string {
	cache := filepath.Join(sb.home, ".cache")
	if runtime.GOOS == "darwin" {
		cache = filepath.Join(sb.home, "Library", "Caches")
	}
	s = strings.NewReplacer(cache, "<CACHE>", sb.work, "<WORK>", sb.home, "<HOME>", sb.root, "<TMP>").Replace(s)
	s = timestamp.ReplaceAllString(s, "<TIME>")
	s = epochMs.ReplaceAllString(s, "<EPOCH>")
	return urnUUID.ReplaceAllString(s, "urn:uuid:<UUID>")
}

// compareGolden fails t when got differs from the golden file at path, and
// reports the first line that differs. With -update it rewrites the file.
func compareGolden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no golden file %s: run `make test-integration UPDATE=1` and review it", path)
	}
	if string(want) == got {
		return
	}
	wantLines, gotLines := strings.Split(string(want), "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w != g {
			t.Errorf("output differs from %s at line %d:\n  got:  %q\n  want: %q\nrefresh on purpose with UPDATE=1 and review the diff", path, i+1, g, w)
			return
		}
	}
}

// copyPath copies the file or directory src to dst.
func copyPath(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
