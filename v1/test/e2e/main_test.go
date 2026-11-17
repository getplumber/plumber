//go:build cli && e2e

// Package e2e holds the e2e CLI suite of the refactoring
// (getplumber/monorepo#651): one test per ISSUE code, run against a branch
// of the plumber-cli-e2e fixture repository of each provider.
//
// github_test.go and gitlab_test.go have the tests, TestGitHubIssue<number>
// and TestGitLabIssue<number>, each with one row per configuration. A row
// analyzes branch issue-<number> and is compared on its report.json with
// testdata/<provider>/golden/<Test>/<row>.yaml (golden_test.go). run_test.go
// runs a row, sandbox_test.go holds the sandbox it runs in and
// retry_test.go reruns a throttled call. The sandbox is a copy of the one in
// v1/test/local: test files can't be imported by another package.
//
// The tests run one at a time, never in parallel: gitlab.com throttles (429)
// as soon as two analyses run at once.
//
// Every file has the `e2e` build tag: the tests need an exported token and
// the network. The fixtures are the issue-<number> branches of the fixture
// repositories, edited there.
package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The providers, as runE2E takes them and testdata/<provider> names them.
const (
	providerGitHub = "github"
	providerGitLab = "gitlab"
)

// The fixture repositories, one branch per ISSUE code.
const (
	githubTarget = "github.com/getplumber-examples/plumber-cli-e2e"
	gitlabTarget = "gitlab.com/getplumber/examples/plumber-cli-e2e"
)

var plumberBin string

func TestMain(m *testing.M) {
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
