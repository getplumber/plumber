//go:build cli

// Package v1 holds the CLI test suite of the refactoring (getplumber/monorepo#640).
//
// Each CLI input is one table row, run against the built binary as a
// subprocess and compared with a golden file. The suite has two files:
//
//   - main_test.go: TestMain, the row type and the helpers every test uses.
//   - e2e_test.go: the e2e rows, which cover every input that calls GitHub or
//     GitLab. They run against the fixture repositories, one branch per case
//     (testdata/e2e, pushed by testdata/e2e/sync.sh). `make test-e2e` (#651).
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
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const (
	githubRepo   = "getplumber-examples/plumber-cli-e2e"
	gitlabRepo   = "getplumber/examples/plumber-cli-e2e"
	githubTarget = "github.com/" + githubRepo
	gitlabTarget = "gitlab.com/" + gitlabRepo
)

type mode string

const e2e mode = "e2e"

// cliCase is one row of the suite: one plumber call and what it must produce.
type cliCase struct {
	name     string // golden file: testdata/golden/<mode>/<name>.golden
	mode     mode
	provider string     // e2e: "github" or "gitlab", decides which token the row gets
	args     []string   // arguments of the plumber call under test
	setup    [][]string // plumber calls run first, in the same work dir and home (not compared)
	inputs   []string   // paths under testdata/inputs copied into the work dir
	clone    string     // e2e: branch of the provider's fixture repo to clone; the row runs inside it
	env      []string   // extra environment, e.g. a bad token
	wantExit int
	files    []string // files the call writes, compared with the golden
}

// onGitHub returns an e2e row that gets a GitHub token.
func onGitHub(name string, exit int, args ...string) cliCase {
	return cliCase{name: "github-" + name, mode: e2e, provider: "github", args: args, wantExit: exit}
}

// onGitLab returns an e2e row that gets a GitLab token.
func onGitLab(name string, exit int, args ...string) cliCase {
	return cliCase{name: "gitlab-" + name, mode: e2e, provider: "gitlab", args: args, wantExit: exit}
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

// withEnv adds KEY=value pairs to the environment of the call.
func (c cliCase) withEnv(kv ...string) cliCase {
	c.env = append(c.env, kv...)
	return c
}

// in runs the row inside a clone of the given branch of the fixture repo.
func (c cliCase) in(branch string) cliCase {
	c.clone = branch
	return c
}

// after runs `plumber args...` before the call under test.
func (c cliCase) after(args ...string) cliCase {
	c.setup = append(c.setup, args)
	return c
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
	build := exec.Command("go", "build", "-buildvcs=false", "-o", plumberBin, "github.com/getplumber/plumber")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build plumber:", err)
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
			providerSlots[c.provider] <- struct{}{}
			defer func() { <-providerSlots[c.provider] }()
			got := runCase(t, c)
			compareGolden(t, filepath.Join("testdata", "golden", string(c.mode), c.name+".golden"), got)
		})
	}
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

// caseEnv returns the environment of a row. It skips a row with no token,
// and clones the fixture repo for a row that runs inside it, moving sb.work
// into the clone.
func caseEnv(t *testing.T, c cliCase, sb *sandbox) []string {
	t.Helper()
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + sb.home,
		"XDG_CACHE_HOME=" + filepath.Join(sb.home, ".cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(sb.home, ".config"),
		"GH_CONFIG_DIR=" + filepath.Join(sb.home, "gh"), // no `gh auth token` fallback
		"TMPDIR=" + sb.root,
		"TERM=dumb",
	}
	env = append(env, e2eEnv(t, c, sb)...)
	return append(env, c.env...)
}

// runCase runs the setup calls and the call under test in a fresh sandbox,
// and returns the normalized transcript: exit code, stdout, stderr and the
// files the call wrote.
func runCase(t *testing.T, c cliCase) string {
	t.Helper()
	sb := newSandbox(t, c)
	env := caseEnv(t, c, &sb)

	for _, args := range c.setup {
		// A setup call may fail on purpose (an analysis with findings exits 1);
		// only the call under test is compared.
		runPlumber(sb.work, env, args)
	}
	stdout, stderr, code := runRetrying(t, c, sb.work, env)
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
	// The CLI logs this line when a provider throttles a request (429) and it
	// retries. It depends on the provider, so normalize drops it.
	retryLine = regexp.MustCompile(`(?m)^time=\S+ level=warning msg="Retrying GitLab API request due to rate limit or error".*\n`)
)

// normalize replaces what changes from one run to the next: temp paths,
// timestamps and retried requests.
func normalize(s string, sb sandbox) string {
	cache := filepath.Join(sb.home, ".cache")
	if runtime.GOOS == "darwin" {
		cache = filepath.Join(sb.home, "Library", "Caches")
	}
	s = strings.NewReplacer(cache, "<CACHE>", sb.work, "<WORK>", sb.home, "<HOME>", sb.root, "<TMP>").Replace(s)
	s = timestamp.ReplaceAllString(s, "<TIME>")
	s = epochMs.ReplaceAllString(s, "<EPOCH>")
	s = urnUUID.ReplaceAllString(s, "urn:uuid:<UUID>")
	return retryLine.ReplaceAllString(s, "")
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
		t.Fatalf("no golden file %s: run `make test-e2e UPDATE=1` and review it", path)
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
