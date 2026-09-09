package configuration

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var updateIDs = flag.Bool("update-ids", false, "rewrite testdata/control_ids_golden.txt from the registry")

// Every control carries a CTRL-XXX id: the rename-stable key the platform
// can hang durable state on (#458). Format and uniqueness are pinned here;
// the id-to-name pairing is frozen by the golden below.
func TestControlIDsAreWellFormedAndUnique(t *testing.T) {
	idPattern := regexp.MustCompile(`^CTRL-\d{3}$`)
	seen := map[string]string{}
	for _, e := range ControlsCatalog() {
		if !idPattern.MatchString(e.ID) {
			t.Errorf("control %q has id %q, want CTRL-XXX", e.Name, e.ID)
		}
		if prev, dup := seen[e.ID]; dup {
			t.Errorf("id %s assigned to both %q and %q", e.ID, prev, e.Name)
		}
		seen[e.ID] = e.Name
	}
}

// The id-to-name pairing is immutable: a control rename shows up as a
// reviewable diff of this golden file (update it deliberately with
// -update-ids); an id CHANGE for an existing name is the contract break
// this test exists to catch. See docs/superpowers/specs/
// 2026-09-08-catalog-source-of-truth-design.md.
func TestControlIDsMatchGolden(t *testing.T) {
	var lines []string
	for _, e := range ControlsCatalog() {
		lines = append(lines, fmt.Sprintf("%s %s", e.ID, e.Name))
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"

	const golden = "testdata/control_ids_golden.txt"
	if *updateIDs {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update-ids once to seed it): %v", err)
	}
	if got != string(want) {
		t.Errorf("control id table diverged from golden.\nIf you RENAMED a control, update the golden deliberately (go test ./configuration/ -run TestControlIDsMatchGolden -update-ids) and say so in the commit.\nIf an ID changed for an existing name, that is a contract break: restore the id.\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}
