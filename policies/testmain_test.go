package policies_test

import (
	"fmt"
	"os"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestMain short-circuits the collector's GitHub API enrichment
// globally for the test suite. Unit tests drive the collector on
// temp fixtures that reference public actions like `actions/
// checkout@v4` — we do not want each fixture to trigger live API
// calls. Production binaries ignore this env var.
//
// It also installs the identity harness observer for the duration of the
// run: every finding every test emits is recorded (see
// identity_harness_test.go). After the suite passes, verifyIdentityEmissions
// checks the accumulated recording against finding/identity's declarations
// table -- containment (every declared field was actually carried by some
// emission) and witness (every declared code was emitted at least once) --
// and fails the run if either check reports a gap. Both checks have
// whole-suite union semantics (see verifyIdentityEmissions' doc comment for
// why, with two confirmed examples), so a filtered run
// (`go test ./policies/ -run <pattern>`) skips the entire check rather than
// report on a subset it cannot evaluate correctly; TestMain prints a
// one-line stderr notice instead, so the skip is visible, never silent. When
// PLUMBER_DUMP_IDENTITY is set, the (historical, v3-only) measurement dump
// also runs; see dumpMeasuredIdentity.
func TestMain(m *testing.M) {
	if err := os.Setenv("PLUMBER_DISABLE_GITHUB_API", "1"); err != nil {
		panic(err)
	}
	opaengine.FindingsObserver = recordEmissions
	code := m.Run()
	opaengine.FindingsObserver = nil
	if code == 0 {
		if suiteWasFiltered() {
			fmt.Fprintln(os.Stderr, "identity harness skipped: filtered run (-run); the full suite is the enforcement point")
		} else if report := verifyIdentityEmissions(); report != "" {
			fmt.Fprintf(os.Stderr, "identity harness failed:\n%s", report)
			code = 1
		}
	}
	if path := os.Getenv("PLUMBER_DUMP_IDENTITY"); path != "" && code == 0 {
		if err := dumpMeasuredIdentity(path); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}
