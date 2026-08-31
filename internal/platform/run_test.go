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
		name     string
		cfg      *ConfigResolution
		contains []string
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
