//go:build cli

// Package test holds the CLI test suite of the refactoring (getplumber/monorepo#640).
//
// The suite is a firewall: it runs the built plumber binary on the inputs we
// want to protect and compares each run with a golden file, so a refactoring
// that changes a behavior goes red. It is not a coverage gate.
//
// main_test.go builds the binary and holds the helpers. Every other file is
// one command group with its own table-driven test (TestConfig in
// config_test.go, and so on). help_test.go has a --help row for every
// command, so a flag lost in the refactoring shows up.
//
// Rows make no backend request: they run with no token and with every proxy
// pointed at a closed port, so a row that tries the network fails.
//
// UPDATE=1 rewrites the golden files; review the diff before committing it.
package test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// closedPort refuses every connection. Rows send all their traffic there, so
// any request fails instead of reaching a backend.
const closedPort = "http://127.0.0.1:9"

// cliCase is one row of a table: one plumber call and what it must produce.
type cliCase struct {
	name   string     // golden file: testdata/golden/<name>.golden
	args   []string   // arguments of the plumber call under test
	exit   int        // expected exit code
	inputs []string   // paths under testdata/inputs copied into the work dir
	setup  [][]string // plumber calls run first, in the same work dir and home (not compared)
	files  []string   // files the call writes, compared with the golden
	// sortLines compares the output lines sorted, for a call that prints them
	// in random order (a CLI bug).
	sortLines bool
}

var plumberBin string

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
	build := exec.CommandContext(context.Background(), "go", "build", "-buildvcs=false", "-o", plumberBin, "github.com/getplumber/plumber")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err = build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build plumber:", err)
		os.Exit(1)
	}
	code := m.Run()
	if err = os.RemoveAll(dir); err != nil {
		fmt.Fprintln(os.Stderr, "remove the build dir:", err)
	}
	os.Exit(code)
}

// sandbox is the private file system of one row.
type sandbox struct {
	root string // parent of work and home, also TMPDIR
	work string // working directory of the plumber calls
	home string
}

// newSandbox creates the work dir and home of a row and copies its inputs
// into the work dir.
func newSandbox(t *testing.T, tt cliCase) sandbox {
	t.Helper()
	root := t.TempDir()
	// macOS returns a symlinked temp dir; resolve it so normalize matches the
	// paths the CLI prints.
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	sb := sandbox{root: root, work: filepath.Join(root, "work"), home: filepath.Join(root, "home")}
	if err := os.Mkdir(sb.home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sb.work, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, in := range tt.inputs {
		copyInput(t, filepath.Join("testdata", "inputs", in), filepath.Join(sb.work, in))
	}
	return sb
}

// env returns the environment of a row. Every proxy points at closedPort, so
// a request fails instead of reaching a backend.
func (sb sandbox) env() []string {
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
// and compares the normalized transcript (exit code, stdout, stderr and the
// files the call wrote) with testdata/golden/<name>.golden.
func runCase(t *testing.T, tt cliCase) {
	t.Helper()
	sb := newSandbox(t, tt)
	env := sb.env()

	for _, args := range tt.setup {
		if _, _, code := runPlumber(t.Context(), sb.work, env, args); code != 0 {
			t.Fatalf("setup `plumber %s` exited %d", strings.Join(args, " "), code)
		}
	}
	stdout, stderr, code := runPlumber(t.Context(), sb.work, env, tt.args)
	if tt.sortLines {
		stdout, stderr = sortLines(stdout), sortLines(stderr)
	}
	if code != tt.exit {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.exit, stdout, stderr)
	}

	got := sb.normalize(transcript(t, tt, sb.work, stdout, stderr, code))

	compareGolden(t, filepath.Join("testdata", "golden", tt.name+".golden"), got)
}

// transcript formats a call and its results the way golden files store them.
func transcript(t *testing.T, tt cliCase, work, stdout, stderr string, code int) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "$ plumber %s\nexit: %d\n--- stdout\n%s\n--- stderr\n%s\n", strings.Join(tt.args, " "), code, stdout, stderr)
	for _, f := range tt.files {
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
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// runPlumber runs the built binary in dir with exactly env. A run that could
// not start returns exit code -1 with the error appended to stderr.
func runPlumber(ctx context.Context, dir string, env, args []string) (stdout, stderr string, code int) {
	cmd := exec.CommandContext(ctx, plumberBin, args...)
	cmd.Dir, cmd.Env = dir, env
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if err == nil {
		return o.String(), e.String(), 0
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return o.String(), e.String(), exitErr.ExitCode()
	}
	return o.String(), e.String() + err.Error(), -1
}

var (
	timestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?`)
	urnUUID   = regexp.MustCompile(`urn:uuid:[0-9a-f-]{36}`) // CycloneDX serialNumber, random per run
	epochMs   = regexp.MustCompile(`\b1[78]\d{11}\b`)        // epoch milliseconds, 2023-2033 (OCSF time, correlation_uid)
)

// normalize replaces what changes from one run to the next: the sandbox
// paths and timestamps.
func (sb sandbox) normalize(s string) string {
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
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no golden file %s: run `make -C v1 test-integration UPDATE=1` and review it", path)
	}
	if string(want) == got {
		return
	}
	wantLines, gotLines := strings.Split(string(want), "\n"), strings.Split(got, "\n")
	for i := range max(len(wantLines), len(gotLines)) {
		w, g := lineAt(wantLines, i), lineAt(gotLines, i)
		if w != g {
			t.Errorf("output differs from %s at line %d:\n  got:  %q\n  want: %q\nrefresh on purpose with UPDATE=1 and review the diff", path, i+1, g, w)
			return
		}
	}
}

// lineAt returns lines[i], or "" past the end.
func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return ""
}

// copyInput copies the file or directory src to dst.
func copyInput(t *testing.T, src, dst string) {
	t.Helper()
	info, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		err = os.CopyFS(dst, os.DirFS(src))
	} else {
		var data []byte
		if data, err = os.ReadFile(src); err == nil {
			err = os.WriteFile(dst, data, 0o644)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}
