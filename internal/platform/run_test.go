package platform

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) *time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return &ts
}

// TestNilRunContextIsStandalone pins the default: every accessor on a nil
// *RunContext must answer "no platform" without panicking, because nil IS
// the standalone mode the CLI runs in by default.
func TestNilRunContextIsStandalone(t *testing.T) {
	var r *RunContext
	if r.Active() {
		t.Fatal("a nil RunContext is standalone mode")
	}
	if got := r.Policies(); got != nil {
		t.Fatalf("Policies: %v", got)
	}
	if snap := r.Snapshot(); snap.CollectedAt != nil || snap.Data != nil {
		t.Fatalf("Snapshot: %+v", snap)
	}
	if yaml, ok := r.MergedYAML(); ok || yaml != "" {
		t.Fatalf("MergedYAML: (%q, %v)", yaml, ok)
	}
	if got := r.UnavailableReason(); got != "" {
		t.Fatalf("UnavailableReason: %q", got)
	}
	if got := r.SnapshotCollectedAt(); got != "" {
		t.Fatalf("SnapshotCollectedAt: %q", got)
	}
	if got := r.MissingSnapshotFields(); got != nil {
		t.Fatalf("MissingSnapshotFields: %v", got)
	}
	if inc, ok := r.Includes(); ok || inc != nil {
		t.Fatalf("Includes: (%v, %v)", inc, ok)
	}
	if r.ConfigIsSnapshot() {
		t.Fatal("ConfigIsSnapshot: a nil RunContext evaluates no document at all")
	}
	if got := r.Describe(); got != nil {
		t.Fatalf("Describe: %v", got)
	}
}

func TestRunContext_MergedYAMLAndReason(t *testing.T) {
	t.Run("available config is returned", func(t *testing.T) {
		r := &RunContext{Config: &ConfigResolution{Source: SourceSnapshot, MergedYAML: "a: 1\n"}}
		yaml, ok := r.MergedYAML()
		if !ok || yaml != "a: 1\n" {
			t.Fatalf("got (%q, %v)", yaml, ok)
		}
		if got := r.UnavailableReason(); got != "" {
			t.Fatalf("an available config has no unavailability reason, got %q", got)
		}
	})

	t.Run("unavailable config yields no yaml and a reason", func(t *testing.T) {
		r := &RunContext{Config: &ConfigResolution{Source: SourceUnavailable, Reason: ReasonResolverBusy}}
		yaml, ok := r.MergedYAML()
		if ok || yaml != "" {
			t.Fatalf("got (%q, %v)", yaml, ok)
		}
		if got := r.UnavailableReason(); got != ReasonResolverBusy {
			t.Fatalf("reason: %q", got)
		}
	})

	t.Run("an unavailable config with no reason still names one", func(t *testing.T) {
		r := &RunContext{Config: &ConfigResolution{Source: SourceUnavailable}}
		if got := r.UnavailableReason(); got != ReasonResolutionUnavailable {
			t.Fatalf("a not_evaluable finding must always carry a reason, got %q", got)
		}
	})
}

func TestRunContext_MissingSnapshotFields(t *testing.T) {
	t.Run("no snapshot means every lane is missing", func(t *testing.T) {
		r := &RunContext{Context: &ProjectContext{}}
		got := r.MissingSnapshotFields()
		want := []string{"branch_protection", "merged_yaml", "mr_approvals", "variables"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("a full snapshot reports nothing missing", func(t *testing.T) {
		r := &RunContext{Context: &ProjectContext{Snapshot: Snapshot{Data: &SnapshotData{
			BranchProtection: json.RawMessage(`{"protections":[]}`),
			MergedYaml:       "a: 1\n",
			MrApprovals:      json.RawMessage(`{"rules":[]}`),
			Variables:        json.RawMessage(`{"items":[]}`),
		}}}}
		if got := r.MissingSnapshotFields(); len(got) != 0 {
			t.Fatalf("want nothing missing, got %v", got)
		}
	})

	t.Run("a partial snapshot names only the absent lanes", func(t *testing.T) {
		r := &RunContext{Context: &ProjectContext{Snapshot: Snapshot{Data: &SnapshotData{
			MergedYaml: "a: 1\n",
			Variables:  json.RawMessage(`{"items":[]}`),
		}}}}
		got := r.MissingSnapshotFields()
		want := []string{"branch_protection", "mr_approvals"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func TestRunContext_SnapshotCollectedAtIsRFC3339UTC(t *testing.T) {
	r := &RunContext{Context: &ProjectContext{Snapshot: Snapshot{
		CollectedAt: mustTime(t, "2026-08-24T07:57:30.32668Z"),
	}}}
	if got := r.SnapshotCollectedAt(); got != "2026-08-24T07:57:30Z" {
		t.Fatalf("got %q", got)
	}
}

// TestDescribe_ReportsTheFactsTheRunObserved covers the operator-facing
// output for each config source. These lines are how a user learns which
// configuration their verdict came from, so each one must name the source
// and, when it degraded, why.
func TestDescribe_ReportsTheFactsTheRunObserved(t *testing.T) {
	base := func(cfg *ConfigResolution) *RunContext {
		return &RunContext{
			Endpoint: "https://platform.example.com",
			Context: &ProjectContext{
				Policies: []Policy{
					{ID: "3333", Name: "Baseline", Enforcement: EnforcementReport},
					{ID: "4444", Name: "Blocking", Enforcement: EnforcementBlock},
				},
				Snapshot: Snapshot{
					CollectedAt: mustTime(t, "2026-08-24T07:57:30Z"),
					Data:        &SnapshotData{MergedYaml: "a: 1\n", BranchProtection: json.RawMessage(`{}`), MrApprovals: json.RawMessage(`{}`), Variables: json.RawMessage(`{}`)},
				},
			},
			Config: cfg,
		}
	}

	cases := []struct {
		name        string
		cfg         *ConfigResolution
		contains    []string
		notContains []string
	}{
		{
			name: "digest match uses the snapshot",
			cfg: &ConfigResolution{
				Source: SourceSnapshot, Digest: DigestMatch, Valid: true,
				LocalDigest: "aaaaaaaaaaaabbbbbbbb", DigestVersion: "1", AnchorSha: "cafebabecafebabe", AnchorRef: "main",
			},
			contains: []string{"matches the snapshot anchor", "digest: aaaaaaaaaaaabbbbbbbb (v1)", "ci config source: platform snapshot", "on main"},
		},
		{
			name: "divergence names both digests",
			cfg: &ConfigResolution{
				Source: SourceResolved, Digest: DigestDiverged, Valid: true,
				LocalDigest: "aaaaaaaaaaaabbbb", DigestVersion: "1", AnchorDigest: "ccccccccccccdddd", ResolvedSha: "1234567890abcdef",
			},
			contains: []string{"diverges from the snapshot anchor", "local:  aaaaaaaaaaaabbbb", "anchor: ccccccccccccdddd", "platform resolve endpoint, resolved at"},
		},
		{
			// The operator reading this line is deciding whether the three
			// include controls should have run. "resolve endpoint" alone
			// used to mean they could not; it no longer does.
			name: "a resolved config that carried attribution says so",
			cfg: &ConfigResolution{
				Source: SourceResolved, Digest: DigestDiverged, Valid: true,
				LocalDigest: "a", DigestVersion: "1", AnchorDigest: "b", ResolvedSha: "s",
				Includes: []json.RawMessage{json.RawMessage(`{"location":"gitlab.com/c/x@1.0.0","type":"component"}`)},
			},
			contains: []string{"platform resolve endpoint", "includes served"},
		},
		{
			// The divergence case above leaves Includes nil incidentally;
			// this case pins that on purpose so an inverted or dropped
			// condition on c.Includes cannot slip the string in here too.
			name: "a resolved config with no attribution does not say includes served",
			cfg: &ConfigResolution{
				Source: SourceResolved, Digest: DigestDiverged, Valid: true,
				LocalDigest: "a", DigestVersion: "1", AnchorDigest: "b", ResolvedSha: "s",
				Includes: nil,
			},
			contains:    []string{"platform resolve endpoint, resolved at"},
			notContains: []string{"includes served"},
		},
		{
			name: "a cache hit says so",
			cfg: &ConfigResolution{
				Source: SourceResolved, Digest: DigestDiverged, Valid: true, FromCache: true,
				LocalDigest: "a", DigestVersion: "1", AnchorDigest: "b", ResolvedSha: "s",
			},
			contains: []string{"served from the platform cache"},
		},
		{
			name: "an INVALID merge is called out",
			cfg: &ConfigResolution{
				Source: SourceResolved, Digest: DigestDiverged, Valid: false,
				LocalDigest: "a", DigestVersion: "1", AnchorDigest: "b", ResolvedSha: "s",
			},
			contains: []string{"reports this config as INVALID"},
		},
		{
			name: "an aborted digest names the abort reason",
			cfg: &ConfigResolution{
				Source: SourceResolved, Digest: DigestNotComputed, Valid: true, DigestAbortReason: "overflow", ResolvedSha: "s",
			},
			contains: []string{"not computed (overflow)", "treated as divergent"},
		},
		{
			name: "unavailability names the reason and the consequence",
			cfg: &ConfigResolution{
				Source: SourceUnavailable, Digest: DigestDiverged, Reason: ReasonResolverBusy,
				LocalDigest: "a", DigestVersion: "1", AnchorDigest: "b",
			},
			contains: []string{"UNAVAILABLE (resolver_busy)", "not_evaluable"},
		},
		{
			name: "no anchor to compare against",
			cfg: &ConfigResolution{
				Source: SourceResolved, Digest: DigestNoAnchor, Valid: true, LocalDigest: "aaaa", DigestVersion: "1", ResolvedSha: "s",
			},
			contains: []string{"carries no anchor to compare against", "local:  aaaa"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := strings.Join(base(tc.cfg).Describe(), "\n")
			for _, want := range tc.contains {
				if !strings.Contains(out, want) {
					t.Fatalf("Describe() missing %q:\n%s", want, out)
				}
			}
			for _, unwanted := range tc.notContains {
				if strings.Contains(out, unwanted) {
					t.Fatalf("Describe() unexpectedly contains %q:\n%s", unwanted, out)
				}
			}
			// The policy set and snapshot age are reported on every path.
			for _, always := range []string{"policies: 2 resolved", "Baseline [report]", "Blocking [block]", "snapshot collected_at: 2026-08-24T07:57:30Z"} {
				if !strings.Contains(out, always) {
					t.Fatalf("Describe() missing %q:\n%s", always, out)
				}
			}
		})
	}
}

// TestDescribe_DerivedDefaultPolicyIsNotShownAsAnID: the fallback policy
// carries the nil uuid. Printing it would suggest a real policy row exists.
func TestDescribe_DerivedDefaultPolicyIsNotShownAsAnID(t *testing.T) {
	r := &RunContext{
		Endpoint: "https://p.example.com",
		Context: &ProjectContext{Policies: []Policy{
			{ID: NilUUID, Name: "[Plumber default]", Enforcement: EnforcementReport},
		}},
		Config: &ConfigResolution{Source: SourceSnapshot, Digest: DigestMatch, Valid: true},
	}
	out := strings.Join(r.Describe(), "\n")
	if strings.Contains(out, NilUUID) {
		t.Fatalf("the nil uuid must never be shown as a policy id:\n%s", out)
	}
	if !strings.Contains(out, "(derived default, no id)") {
		t.Fatalf("the derived fallback must be labelled as such:\n%s", out)
	}
	if !strings.Contains(out, "snapshot: none cached for this project yet") {
		t.Fatalf("an absent snapshot must be stated, not omitted:\n%s", out)
	}
}

// TestDescribe_FailedContextFetchIsStated: a platform that could not be
// reached must produce a line saying so. Silence would let an operator
// believe policies were applied when none were fetched.
func TestDescribe_FailedContextFetchIsStated(t *testing.T) {
	r := &RunContext{
		Endpoint:   "https://p.example.com",
		ContextErr: errors.New("403 Forbidden: not the attributed project"),
	}
	out := strings.Join(r.Describe(), "\n")
	if !strings.Contains(out, "context: NOT fetched") || !strings.Contains(out, "not the attributed project") {
		t.Fatalf("a failed context fetch must be reported with its cause:\n%s", out)
	}
}

func TestShortDigest(t *testing.T) {
	cases := map[string]string{
		"":                  "none",
		"   ":               "none",
		"short":             "short",
		"exactly12chr":      "exactly12chr",
		"abcdefghijklmnopq": "abcdefghijkl...",
	}
	for in, want := range cases {
		if got := shortDigest(in); got != want {
			t.Fatalf("shortDigest(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEngaged_RequiresAFetchedContext pins the distinction that decides
// whether the lane split applies. --platform alone is not enough: with no
// context the CLI never learned which lanes the platform owns, and
// assuming them would blank a scan because a third party was briefly down.
func TestEngaged_RequiresAFetchedContext(t *testing.T) {
	var nilRC *RunContext
	if nilRC.Active() || nilRC.Engaged() {
		t.Fatal("standalone is neither active nor engaged")
	}

	failed := &RunContext{Endpoint: "https://p.example.com", ContextErr: errors.New("403")}
	if !failed.Active() {
		t.Fatal("--platform was set, so the run is active")
	}
	if failed.Engaged() {
		t.Fatal("a context that was never fetched must not engage the lane split")
	}

	// Once the platform answers, its lanes apply — including when the
	// answer is 'no configuration available'.
	answered := &RunContext{
		Endpoint: "https://p.example.com",
		Context:  &ProjectContext{},
		Config:   &ConfigResolution{Source: SourceUnavailable, Reason: ReasonResolutionUnavailable},
	}
	if !answered.Engaged() {
		t.Fatal("a fetched context engages the lanes even when it carries no config")
	}
}

// TestDescribe_InFlightResolution: while the early-fired resolve is still in
// flight, the describe lines say so honestly instead of blocking the pre-run
// output on the platform's answer or printing an outcome nothing has
// established yet.
func TestDescribe_InFlightResolution(t *testing.T) {
	pending := &ConfigResolution{
		Digest:        DigestDiverged,
		LocalDigest:   strings.Repeat("1", 64),
		DigestVersion: "1",
		AnchorDigest:  strings.Repeat("2", 64),
		done:          make(chan struct{}), // never closed: still in flight
	}
	rc := &RunContext{Endpoint: "https://plat", ProjectPath: "org/repo",
		Context: &ProjectContext{}, Config: pending}
	lines := strings.Join(rc.Describe(), "\n")
	if !strings.Contains(lines, "in flight") {
		t.Fatalf("pending resolution must describe itself as in flight, got:\n%s", lines)
	}
	if strings.Contains(lines, "UNAVAILABLE") {
		t.Fatalf("a pending resolution is not an unavailable one, got:\n%s", lines)
	}
}

// TestDescribe_AnchorShaNote: outside CI a divergent checkout resolves at
// the snapshot anchor's commit (there is no local commit to name), so the
// run evaluates the project's remote state. The describe output must say
// that next to the "diverges" line, or an operator with uncommitted CI
// edits reads the two lines as contradicting each other.
func TestDescribe_AnchorShaNote(t *testing.T) {
	c := &ConfigResolution{
		Digest:        DigestDiverged,
		LocalDigest:   strings.Repeat("1", 64),
		DigestVersion: "1",
		AnchorDigest:  strings.Repeat("2", 64),
		Source:        SourceResolved,
		ResolvedSha:   "beef",
		Valid:         true,
		ShaFromAnchor: true,
	}
	rc := &RunContext{Endpoint: "https://plat", Context: &ProjectContext{}, Config: c}
	lines := strings.Join(rc.Describe(), "\n")
	if !strings.Contains(lines, "remote state") {
		t.Fatalf("anchor-sha fallback must be explained, got:\n%s", lines)
	}
	// Without the fallback the note must not appear.
	c.ShaFromAnchor = false
	lines = strings.Join(rc.Describe(), "\n")
	if strings.Contains(lines, "remote state") {
		t.Fatalf("note printed without the anchor-sha fallback:\n%s", lines)
	}
}

// TestLaneMissingCoversEveryServedLane pins LaneMissing's answer for each
// lane identifier it knows.
//
// The question it answers is "did this lane carry no data at all", which
// the caller pairs with lanesWhoseAbsenceIsAFailure to decide whether an
// absence is a real answer or a collection that never completed. A lane the
// switch does not name falls through to false, which reads as "the lane is
// present", so an unhandled lane is certified served on every run that
// lacks it - the direction worth pinning.
//
// The table is hand-maintained and cannot notice a lane nobody added to it:
// it pins the six answers that exist today, and a new lane needs its own
// row here as much as its own case in the switch.
func TestLaneMissingCoversEveryServedLane(t *testing.T) {
	id := 7
	full := &SnapshotData{
		SchemaVersion:         SnapshotSchemaV2,
		BranchProtection:      json.RawMessage(`{"protections":[]}`),
		MergedYaml:            "stages: [build]",
		MrApprovals:           json.RawMessage(`{"rules":[]}`),
		Variables:             json.RawMessage(`{"items":[]}`),
		ProjectDetails:        &ProjectDetails{DefaultBranch: "main"},
		SecurityPolicyProject: &SecurityPolicyProject{Known: true, ID: &id},
	}

	for _, tc := range []struct {
		lane  string
		empty func(*SnapshotData)
	}{
		{DegradedFieldBranchProtection, func(d *SnapshotData) { d.BranchProtection = nil }},
		{DegradedFieldMergedYaml, func(d *SnapshotData) { d.MergedYaml = "" }},
		{DegradedFieldMrApprovals, func(d *SnapshotData) { d.MrApprovals = nil }},
		{DegradedFieldVariables, func(d *SnapshotData) { d.Variables = nil }},
		{DegradedFieldProjectDetails, func(d *SnapshotData) { d.ProjectDetails = nil }},
		{DegradedFieldSecurityPolicyProject, func(d *SnapshotData) { d.SecurityPolicyProject = nil }},
	} {
		t.Run(tc.lane, func(t *testing.T) {
			served := *full
			rc := &RunContext{Context: &ProjectContext{Snapshot: Snapshot{Data: &served}}}
			if rc.LaneMissing(tc.lane) {
				t.Errorf("%s is served in this snapshot and must not read as missing", tc.lane)
			}

			absent := *full
			tc.empty(&absent)
			rc = &RunContext{Context: &ProjectContext{Snapshot: Snapshot{Data: &absent}}}
			if !rc.LaneMissing(tc.lane) {
				t.Errorf("%s carried nothing and must read as missing", tc.lane)
			}
		})
	}

	// No snapshot at all: every lane is missing, including the two added
	// for the merge settings and the security-policy linkage.
	none := &RunContext{Context: &ProjectContext{}}
	for _, lane := range []string{DegradedFieldProjectDetails, DegradedFieldSecurityPolicyProject} {
		if !none.LaneMissing(lane) {
			t.Errorf("%s must read as missing when there is no snapshot", lane)
		}
	}

	// Standalone mode has no lanes to be missing: answering true there
	// would report a platform gap on a run that never asked for one.
	var standalone *RunContext
	if standalone.LaneMissing(DegradedFieldProjectDetails) {
		t.Error("a nil RunContext is standalone mode; no lane is missing")
	}
}

// TestRunContextAccessorsJoinPendingResolution: the outcome accessors must
// wait for the early-fired request rather than reading half-written state.
func TestRunContextAccessorsJoinPendingResolution(t *testing.T) {
	pending := &ConfigResolution{Digest: DigestDiverged, done: make(chan struct{})}
	rc := &RunContext{Context: &ProjectContext{}, Config: pending}
	got := make(chan bool, 1)
	go func() {
		_, available := rc.MergedYAML()
		got <- available
	}()
	select {
	case <-got:
		t.Fatal("MergedYAML answered before the resolution settled")
	case <-time.After(50 * time.Millisecond):
	}
	pending.Source = SourceResolved
	pending.MergedYAML = "yaml"
	pending.Valid = true
	close(pending.done)
	select {
	case available := <-got:
		if !available {
			t.Fatal("a settled resolved config must be available")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("MergedYAML never answered after the resolution settled")
	}
}

// TestDescribeConfig_ForkPipelineNamesTheReason: a run on a merge request
// from a fork has no commit the platform can resolve against the target
// project (customer report 2026-11-05, innersource instances live on fork
// merge requests). The source line says so in words, beside the reason
// code, so a reader does not go looking for a platform outage.
func TestDescribeConfig_ForkPipelineNamesTheReason(t *testing.T) {
	rc := &RunContext{Config: &ConfigResolution{Source: SourceUnavailable, Reason: ReasonForkPipeline, Digest: DigestDiverged, LocalDigest: "abc", DigestVersion: "1"}}
	out := strings.Join(rc.describeConfig(), "\n")
	if !strings.Contains(out, "UNAVAILABLE ("+ReasonForkPipeline+")") {
		t.Fatalf("the reason code is missing:\n%s", out)
	}
	if !strings.Contains(out, "merge request from a fork") {
		t.Fatalf("the fork note is missing:\n%s", out)
	}
}

// TestDescribe_NamesCarriedSnapshotLanes encodes platform ruling R1,
// 2026-11-06 (carried snapshot lanes): when GitLab refuses one lane of a
// nightly snapshot, the platform keeps that lane's previous value for up to
// two days and dates it in carried_fields. Controls keep evaluating on the
// carried data; the banner must say which lanes are older than
// collected_at, and from when. A snapshot without the member must render
// exactly as before.
func TestDescribe_NamesCarriedSnapshotLanes(t *testing.T) {
	describe := func(t *testing.T, body string) []string {
		t.Helper()
		var d SnapshotData
		if err := json.Unmarshal([]byte(body), &d); err != nil {
			t.Fatalf("decode: %v", err)
		}
		r := &RunContext{
			Endpoint: "https://platform.example.com",
			Context: &ProjectContext{
				Policies: []Policy{{ID: "3333", Name: "Baseline", Enforcement: EnforcementReport}},
				Snapshot: Snapshot{CollectedAt: mustTime(t, "2026-11-06T03:00:00Z"), Data: &d},
			},
			Config: &ConfigResolution{Source: SourceSnapshot, Digest: DigestMatch, Valid: true},
		}
		return r.Describe()
	}
	const lanes = `"merged_yaml":"a: 1\n","branch_protection":{},"mr_approvals":{},"variables":{}`
	baseline := describe(t, `{"schema_version":"2",`+lanes+`,"degraded_fields":["includes_jobs"]}`)

	t.Run("one carried lane names its own pass", func(t *testing.T) {
		out := strings.Join(describe(t, `{"schema_version":"2",`+lanes+`,"carried_fields":{"mr_approvals":"2026-11-05T03:00:00Z"}}`), "\n")
		want := "snapshot lanes carried from 2026-11-05T03:00:00Z: mr_approvals"
		if !strings.Contains(out, want) {
			t.Fatalf("Describe() missing %q:\n%s", want, out)
		}
	})

	// Same pass time on every lane isolates the sort from the oldest-time
	// logic; the keys arrive in reverse order and map iteration is random,
	// so a dropped sort fails here almost every run.
	t.Run("carried lanes are named in sorted order whatever their input order", func(t *testing.T) {
		out := strings.Join(describe(t, `{"schema_version":"2",`+lanes+`,"carried_fields":{`+
			`"variables":"2026-11-05T05:00:00+02:00","mr_approvals":"2026-11-05T05:00:00+02:00","branch_protection":"2026-11-05T05:00:00+02:00"}}`), "\n")
		want := "snapshot lanes carried from 2026-11-05T03:00:00Z: branch_protection, mr_approvals, variables"
		if !strings.Contains(out, want) {
			t.Fatalf("Describe() missing %q:\n%s", want, out)
		}
	})

	// The oldest pass belongs to the alphabetically LAST lane, so taking the
	// first sorted lane's time instead of the minimum would fail here.
	t.Run("two carried lanes name the oldest pass and the sorted lanes", func(t *testing.T) {
		out := describe(t, `{"schema_version":"2",`+lanes+`,"degraded_fields":["includes_jobs"],`+
			`"carried_fields":{"branch_protection":"2026-11-05T03:00:00Z","variables":"2026-11-04T03:00:00+02:00"}}`)
		want := "snapshot lanes carried from 2026-11-04T01:00:00Z: branch_protection, variables"
		idx := -1
		for i, l := range out {
			if l == want {
				idx = i
			}
		}
		if idx < 1 || idx+1 >= len(out) {
			t.Fatalf("Describe() missing %q:\n%s", want, strings.Join(out, "\n"))
		}
		if !strings.HasPrefix(out[idx-1], "snapshot collected_at: ") {
			t.Fatalf("the carried line must follow collected_at, got %q before it", out[idx-1])
		}
		if !strings.HasPrefix(out[idx+1], "snapshot degraded lanes: ") {
			t.Fatalf("the carried line must precede the degraded lanes, got %q after it", out[idx+1])
		}
		// Reporting only: removing the line gives back today's output.
		rest := append(append([]string(nil), out[:idx]...), out[idx+1:]...)
		if strings.Join(rest, "\n") != strings.Join(baseline, "\n") {
			t.Fatalf("carried_fields must only add one line:\n%s\nvs\n%s", strings.Join(rest, "\n"), strings.Join(baseline, "\n"))
		}
	})

	t.Run("member absent prints no carried line", func(t *testing.T) {
		out := strings.Join(baseline, "\n")
		if strings.Contains(out, "carried") {
			t.Fatalf("no carried_fields must mean no carried line:\n%s", out)
		}
		want := strings.Join([]string{
			"platform: https://platform.example.com",
			"policies: 1 resolved",
			"  - Baseline [report] 3333",
			"snapshot collected_at: 2026-11-06T03:00:00Z",
			"snapshot degraded lanes: includes_jobs (collection failed; these report not_evaluable)",
		}, "\n")
		if !strings.HasPrefix(out, want) {
			t.Fatalf("output without carried_fields changed:\n%s", out)
		}
	})

	t.Run("member present but empty prints no carried line", func(t *testing.T) {
		out := describe(t, `{"schema_version":"2",`+lanes+`,"degraded_fields":["includes_jobs"],"carried_fields":{}}`)
		if strings.Join(out, "\n") != strings.Join(baseline, "\n") {
			t.Fatalf("an empty carried_fields must render as its absence:\n%s", strings.Join(out, "\n"))
		}
	})
}
