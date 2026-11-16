//go:build cli && e2e

package e2e

import (
	"cmp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// e2eCase is one row of a test: one plumber call on a fixture branch. The
// call must write report.json (-o report.json).
type e2eCase struct {
	name   string   // row name, and the golden file testdata/<provider>/golden/<Test>/<name>.yaml
	args   []string // arguments of the plumber call under test
	inputs []string // files of testdata/<provider>/inputs copied into the work dir
}

// runE2E compares a run of tt on provider with
// testdata/<provider>/golden/<Test>/<row>.yaml, named after the subtest.
func runE2E(t *testing.T, provider string, tt e2eCase) {
	t.Helper()
	path := filepath.Join("testdata", provider, "golden", t.Name()+".yaml")
	want, err := readGolden(path)
	if err != nil {
		t.Fatal(err)
	}
	got := run(t, provider, tt)
	if diff := want.cmp(got); diff != "" {
		t.Errorf("%s: output differs from %s:\n%s", got.Command, path, diff)
	}
}

// run runs tt on provider in a fresh sandbox, with the exported token (see
// token), and returns the normalized result: the call, its exit code and the
// report it wrote.
func run(t *testing.T, provider string, tt e2eCase) *golden {
	t.Helper()
	sb := newSandbox(t, provider, tt, token(t, provider))

	stdout, stderr, code := runRetrying(t, sb, provider, tt.args)

	got, err := sb.newGolden(tt, code)
	if err != nil {
		t.Fatalf("%v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	return got
}

// plumberCall returns how a plumber call with args reads in messages and
// golden files.
func plumberCall(args []string) string {
	return "plumber " + strings.Join(args, " ")
}

// providerToken is the token of one provider, read once from what the user
// exports.
type providerToken struct {
	name    string        // the provider's name in messages
	read    func() string // the exported token, or ""
	export  string        // what to export, for the error message
	plumber string        // the variable plumber reads it from
	missing atomic.Bool   // a test already failed for want of it
}

// tokens has the token of each provider.
var tokens = map[string]*providerToken{
	providerGitHub: {
		name:    "GitHub",
		read:    sync.OnceValue(func() string { return cmp.Or(os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN")) }),
		export:  "GITHUB_TOKEN (or GH_TOKEN)",
		plumber: "GITHUB_TOKEN",
	},
	providerGitLab: {
		name:    "GitLab",
		read:    sync.OnceValue(func() string { return os.Getenv("GITLAB_TOKEN") }),
		export:  "GITLAB_TOKEN",
		plumber: "GITLAB_TOKEN",
	},
}

// token returns the token plumber needs for provider, as the variable plumber
// reads (GITHUB_TOKEN=… or GITLAB_TOKEN=…). An e2e row can't run without
// it, even on a public fixture repository: the first test without it fails
// and says what to export, and the provider's next tests are skipped, so a
// missing token shows as one failure.
func token(t *testing.T, provider string) string {
	t.Helper()
	tok, ok := tokens[provider]
	if !ok {
		t.Fatalf("unknown provider %q", provider)
	}
	if v := tok.read(); v != "" {
		return tok.plumber + "=" + v
	}
	if tok.missing.Swap(true) {
		t.Skipf("no %s token: see the first failure", tok.name)
	}
	t.Fatalf("the %s e2e tests need a token: export %s", tok.name, tok.export)
	return ""
}
