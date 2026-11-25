//go:build cli && e2e

package e2e

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

// sandbox is the private file system of one row.
type sandbox struct {
	root string   // parent of work and home, also TMPDIR
	work string   // working directory of the plumber calls
	home string   // HOME of the plumber calls
	envs []string // variables added to the environment: the provider token
}

// newSandbox creates the work dir and home of the row tt of provider, copies
// its inputs from testdata/<provider>/inputs into the work dir, and adds envs
// to the environment of its calls.
func newSandbox(t *testing.T, provider string, tt e2eCase, envs ...string) *sandbox {
	t.Helper()
	root := t.TempDir()
	// macOS returns a symlinked temp dir; resolve it so normalize matches the
	// paths the CLI prints.
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	sb := &sandbox{root: root, work: filepath.Join(root, "work"), home: filepath.Join(root, "home"), envs: envs}
	if err := os.Mkdir(sb.home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sb.work, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, in := range tt.inputs {
		data, err := os.ReadFile(filepath.Join("testdata", provider, "inputs", in))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sb.work, in), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return sb
}

// passedOn are the variables of the user's environment a row keeps when they
// are set: unlike the local suite, the network is open, so a proxy or a
// custom CA must still work.
var passedOn = []string{
	"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
	"ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// env returns the environment of a row: a private home and cache, no gh
// config, the proxy and CA variables of passedOn that are set, and the
// variables of sb.envs.
func (sb *sandbox) env() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + sb.home,
		"XDG_CACHE_HOME=" + filepath.Join(sb.home, ".cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(sb.home, ".config"),
		"GH_CONFIG_DIR=" + filepath.Join(sb.home, "gh"), // no `gh auth token` fallback
		"TMPDIR=" + sb.root,
		"TERM=dumb",
	}
	for _, k := range passedOn {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, sb.envs...)
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
	epochMs   = regexp.MustCompile(`\b1[78]\d{11}\b`) // epoch milliseconds, 2023-2033
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
	return epochMs.ReplaceAllString(s, "<EPOCH>")
}

// newGolden returns the golden of a call of tt that exited with code: the
// call and the report.json it wrote, normalized.
func (sb *sandbox) newGolden(tt e2eCase, code int) (*golden, error) {
	command := plumberCall(tt.args)
	report, err := readReport(filepath.Join(sb.work, "report.json"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}
	return &golden{
		Command: sb.normalize(command),
		Exit:    code,
		Report:  sb.normalize(report),
	}, nil
}
