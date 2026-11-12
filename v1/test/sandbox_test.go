//go:build cli

package test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// closedPort refuses every connection. Rows send all their traffic there, so
// any request fails instead of reaching a backend.
const closedPort = "http://127.0.0.1:9"

// sandbox is the private file system of one row.
type sandbox struct {
	root string // parent of work and home, also TMPDIR
	work string // working directory of the plumber calls
	home string
}

// newSandbox creates the work dir and home of a row and copies its inputs
// into the work dir.
func newSandbox(t *testing.T, tt cliCase) *sandbox {
	t.Helper()
	root := t.TempDir()
	// macOS returns a symlinked temp dir; resolve it so normalize matches the
	// paths the CLI prints.
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	sb := &sandbox{root: root, work: filepath.Join(root, "work"), home: filepath.Join(root, "home")}
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
func (sb *sandbox) env() []string {
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

// readFiles reads the files at paths in the work dir of sb and returns their
// contents keyed by path. It returns nil when paths is empty.
func (sb *sandbox) readFiles(paths []string) (map[string]string, error) {
	var contents map[string]string
	for _, p := range paths {
		data, err := os.ReadFile(filepath.Join(sb.work, p))
		if err != nil {
			return nil, fmt.Errorf("read output file %s: %w", p, err)
		}
		if contents == nil {
			contents = make(map[string]string)
		}
		contents[p] = string(data)
	}
	return contents, nil
}

// runPlumber runs the built binary in the work dir of sb, with exactly the
// environment of sb. A run that could not start returns exit code -1 with the
// error appended to stderr.
func (sb *sandbox) runPlumber(ctx context.Context, args []string) (stdout, stderr string, code int) {
	cmd := exec.CommandContext(ctx, plumberBin, args...)
	cmd.Dir, cmd.Env = sb.work, sb.env()
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
func (sb *sandbox) normalize(s string) string {
	cache := filepath.Join(sb.home, ".cache")
	if runtime.GOOS == "darwin" {
		cache = filepath.Join(sb.home, "Library", "Caches")
	}
	s = strings.NewReplacer(cache, "<CACHE>", sb.work, "<WORK>", sb.home, "<HOME>", sb.root, "<TMP>").Replace(s)
	s = timestamp.ReplaceAllString(s, "<TIME>")
	s = epochMs.ReplaceAllString(s, "<EPOCH>")
	return urnUUID.ReplaceAllString(s, "urn:uuid:<UUID>")
}

// newGolden returns the golden of a call of tt that printed stdout and
// stderr and exited with code, with the files it wrote, normalized.
func (sb *sandbox) newGolden(tt cliCase, command, stdout, stderr string, code int) (*golden, error) {
	files, err := sb.readFiles(tt.outputFiles)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}
	for p, data := range files {
		files[p] = sb.normalize(data)
	}
	return &golden{
		Command: sb.normalize(command),
		Exit:    code,
		Stdout:  sb.normalize(stdout),
		Stderr:  sb.normalize(stderr),
		Files:   files,
	}, nil
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
