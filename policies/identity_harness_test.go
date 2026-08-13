package policies_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// emissionRecord accumulates what the whole test suite observed one ISSUE
// code emit. It is the evidence base for the harness verification
// (containment + witness, see verifyIdentityEmissions) that runs after
// m.Run() in TestMain, and was historically also the evidence base for the
// one-time measurement dump that seeded the v4 declarations (see
// dumpMeasuredIdentity).
type emissionRecord struct {
	// DataKeys is the union of Data keys seen across every emission.
	DataKeys map[string]bool
	// Count is how many findings of this code the suite emitted.
	Count   int
	SawStep bool
	SawFile bool
	SawJob  bool
}

var (
	emissionsMu sync.Mutex
	emissions   = map[string]*emissionRecord{}
)

func recordEmissions(fs []opaengine.Finding) {
	emissionsMu.Lock()
	defer emissionsMu.Unlock()
	for _, f := range fs {
		if f.Code == "" {
			continue
		}
		rec := emissions[f.Code]
		if rec == nil {
			rec = &emissionRecord{DataKeys: map[string]bool{}}
			emissions[f.Code] = rec
		}
		rec.Count++
		for k := range f.Data {
			rec.DataKeys[k] = true
		}
		if _, ok := f.Data["step"].(string); ok {
			rec.SawStep = true
		}
		if f.File != "" {
			rec.SawFile = true
		}
		if f.Job != "" {
			rec.SawJob = true
		}
	}
}

// dumpMeasuredIdentity writes the per-code measurement to the path in
// PLUMBER_DUMP_IDENTITY. It was the generation step for the v4 declarations
// table: run once against recipe v3, transliterate, then correct (see
// finding/identity/declarations.go's package doc, and
// docs/superpowers/plans/2026-08-12-identity-measured.json for that one
// historical run's output).
//
// It refuses to run under recipe v4+. v4's Of derives Fields.Selected from
// the declarations table itself, so measuring a v4 run would not observe
// anything independent of the table: it would read the table back through
// itself and write the result over the v3 evidence the table was built
// from, silently turning a measurement into a tautology (a code can never
// again show a v3-style conflict once its own declaration is the thing
// generating the "measurement"). This function is kept, guarded, only so
// the one-time step it performed stays documented in place; it is not a
// live tool under the current recipe.
func dumpMeasuredIdentity(path string) error {
	if identity.RecipeVersion > 3 {
		return fmt.Errorf("dumpMeasuredIdentity: recipe v%d is active; this dump was a one-time v3 measuring instrument and refuses to run under v4+ (it would overwrite the historical measurement at docs/superpowers/plans/2026-08-12-identity-measured.json with declaration-derived data, not an independent measurement)", identity.RecipeVersion)
	}
	emissionsMu.Lock()
	defer emissionsMu.Unlock()
	type row struct {
		DataKeys  []string `json:"dataKeys"`
		SawStep   bool     `json:"sawStep"`
		SawFile   bool     `json:"sawFile"`
		SawJob    bool     `json:"sawJob"`
		Emissions int      `json:"emissions"`
	}
	out := map[string]row{}
	for code, rec := range emissions {
		keys := make([]string, 0, len(rec.DataKeys))
		for k := range rec.DataKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out[code] = row{DataKeys: keys, SawStep: rec.SawStep, SawFile: rec.SawFile,
			SawJob: rec.SawJob, Emissions: rec.Count}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity measurement: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write identity measurement: %w", err)
	}
	fmt.Fprintf(os.Stderr, "identity measurement: %d codes -> %s\n", len(out), path)
	return nil
}

// witnessedOutsidePolicies lists codes emitted by Go collectors rather than
// Rego policies, so the policy suite cannot witness them. Every entry must
// name the test that covers its emission; an entry without a real covering
// test is a lie the harness cannot catch, so review these in PRs the same
// way as declarations.
var witnessedOutsidePolicies = map[string]string{
	// e.g. "ISSUE-901": "cmd/analyze_gitlab_test.go: TestComputeGitLabCompliance_CiInvalid",
	//
	// Empty by design: the Task 1 measurement (go test ./policies/, dumped to
	// docs/superpowers/plans/2026-08-12-identity-measured.json) shows all 66
	// registered codes emitted by the policy suite itself, so nothing needs
	// an outside-the-suite excuse today. If a future control's detection
	// moves into a Go collector the policy suite cannot exercise, add its
	// entry here naming the real covering test -- an entry without one is a
	// gap this harness cannot see.
}

// suiteWasFiltered reports whether this run only exercised a subset of the
// package's tests: `go test -run <pattern>` (any non-empty pattern,
// including one that also narrows to a `/subtest`) translates to
// `-test.run` on the compiled binary, which the testing package registers
// as the flag named "test.run". Must be read after m.Run() returns:
// (*testing.M).Run parses flags internally as part of starting, so the
// value is unset before that point regardless of what was passed on the
// command line (verified empirically: flag.Parsed() is false beforehand).
// TestMain only calls this after m.Run() has already returned, so that
// precondition always holds at its one call site; it gates whether
// verifyIdentityEmissions runs at all -- see that function's doc comment
// for why a filtered run skips the whole check rather than part of it.
func suiteWasFiltered() bool {
	f := flag.Lookup("test.run")
	return f != nil && f.Value.String() != ""
}

// verifyIdentityEmissions is the harness: containment (every recorded
// emission carries its declared fields) and witness (every declared code was
// seen, or is explicitly excused with a covering test named). Returns a
// non-empty report when the catalog fails.
//
// TestMain calls this ONLY on a full, unfiltered run (guarded by
// suiteWasFiltered; a filtered run gets a one-line stderr skip notice
// instead of a call here at all). Both checks have whole-suite union
// semantics, which makes this function meaningful only over the complete
// suite, never a subset:
//
//   - Witness needs every declared code to have been emitted by SOME test,
//     anywhere in the package. A `-run` pattern that only exercises, say,
//     TestIssue108_ActionArchivedRepo makes every OTHER declared code look
//     unwitnessed -- a property of the invocation, not a fact about the
//     catalog.
//   - Containment evaluates "recorded Data ⊇ declared keys" against the
//     UNION of every emission of a code across the entire suite (the
//     package doc's "key union across the suite, not per-emission" design),
//     not any single test's fixture. Two structurally different,
//     empirically confirmed mechanisms show this is just as filter-fragile
//     as witness, not merely "narrows what gets checked" as it might look
//     at a glance:
//   - A code whose full declared key set is deliberately split across
//     more than one test function. ISSUE-402's `uses`/`step` pair comes
//     from TestIssue323_FindingsCarryStructuredEvidence and its
//     `includePath` from the separate
//     TestIssue402_AmbiguousIncludeIdentifiesOnTheIncludePath; a `-run`
//     selecting one of those two functions but not the other makes
//     containment misreport the key only the other supplies as
//     dropped.
//   - A code whose Rego rule fires incidentally on a fixture built for
//     a *different* test. artipacked.rego (ISSUE-307) denies any
//     `actions/checkout@...` action lacking `persist-credentials:
//     false`, with no other precondition, so any fixture anywhere in
//     this file that uses a bare checkout collaterally produces an
//     ISSUE-307 finding. `go test ./policies/ -run
//     TestIssue108_ActionArchivedRepo` (which targets ISSUE-702, not
//     307) used to report `ISSUE-307: declares "step" but no emission
//     ... carried it`: that function's own checkout fixtures never set
//     Line/Name (they were never meant to test ISSUE-307's step
//     resolution), so the collateral emissions they contribute lack
//     it, and the filter excluded every test whose checkout fixture
//     does carry it.
//
// A harness that is red on a legitimate, narrowly-filtered run teaches
// developers to ignore red -- worse than losing the (already partial, per
// the above) dev-loop signal a filtered run could otherwise offer. CI runs
// `go test ./policies/` with no `-run` and is the actual enforcement point.
func verifyIdentityEmissions() string {
	emissionsMu.Lock()
	defer emissionsMu.Unlock()
	var b strings.Builder

	for code, rec := range emissions {
		decl, ok := identity.Declared(code)
		if !ok {
			fmt.Fprintf(&b, "%s: emitted by the suite but has no declaration\n", code)
			continue
		}
		for _, key := range decl {
			switch key {
			case "file", "job", "message":
				continue // canonical fields, always present on the finding
			default:
				if !rec.DataKeys[key] {
					fmt.Fprintf(&b, "%s: declares %q but no emission in the suite carried it\n", code, key)
				}
			}
		}
	}

	for _, code := range identity.DeclaredCodes() {
		if _, seen := emissions[code]; seen {
			continue
		}
		if why, excused := witnessedOutsidePolicies[code]; excused {
			_ = why
			continue
		}
		fmt.Fprintf(&b, "%s: declared but never witnessed by any policy test; add a fixture that emits it or excuse it in witnessedOutsidePolicies with its covering test\n", code)
	}
	return b.String()
}
