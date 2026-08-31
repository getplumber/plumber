package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/platform"
)

// strictConfigYAML enables one GitLab control, so a config using it
// produces a different verdict from one that enables nothing.
const strictConfigYAML = `version: "2.0"
gitlab:
  controls:
    branchMustBeProtected:
      enabled: true
      defaultMustBeProtected: true
      namePatterns:
        - main
`

// runContextWith builds a platform run context carrying a resolved policy
// set, as /context would have returned it.
func runContextWith(policies ...platform.Policy) *platform.RunContext {
	return &platform.RunContext{
		Endpoint: "https://platform.example.com",
		Context:  &platform.ProjectContext{Policies: policies},
		Config:   &platform.ConfigResolution{Source: platform.SourceSnapshot, Digest: platform.DigestMatch, Valid: true},
	}
}

// confWithPolicies builds a Configuration in platform mode with the given
// resolved policy set and a minimal usable Plumber config.
func confWithPolicies(t *testing.T, policies ...platform.Policy) *configuration.Configuration {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte("version: \"2.0\"\n"), "test")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return &configuration.Configuration{PlumberConfig: pc, PlatformRun: runContextWith(policies...)}
}

// TestBuildPolicyResults_OneEntryPerPolicy is the contract: the results
// array carries one entry per resolved policy, never a merged one.
func TestBuildPolicyResults_OneEntryPerPolicy(t *testing.T) {
	conf := confWithPolicies(t,
		platform.Policy{ID: "33333333-3333-3333-3333-333333330001", Name: "Baseline", Enforcement: platform.EnforcementReport},
		platform.Policy{ID: "44444444-4444-4444-4444-444444440002", Name: "Blocking", Enforcement: platform.EnforcementBlock},
	)

	got := buildPolicyResults(testProvider(t), conf, &control.AnalysisResult{}, nil, ".plumber.yaml")

	if len(got) != 2 {
		t.Fatalf("want one entry per policy (2), got %d", len(got))
	}
	if got[0].Policy != "Baseline" || got[1].Policy != "Blocking" {
		t.Fatalf("entries must be named after their policies: %q, %q", got[0].Policy, got[1].Policy)
	}
	if got[0].PolicyID != "33333333-3333-3333-3333-333333330001" || got[1].PolicyID != "44444444-4444-4444-4444-444444440002" {
		t.Fatalf("each entry must carry its own policy id: %q, %q", got[0].PolicyID, got[1].PolicyID)
	}
}

// TestBuildPolicyResults_SharedConfigIsEvaluatedOnce pins the cost rule: a
// control shared by several policies under the SAME configuration is
// evaluated once, and the verdict feeds every policy requiring it.
func TestBuildPolicyResults_SharedConfigIsEvaluatedOnce(t *testing.T) {
	var evaluations int
	restore := configForPolicy
	t.Cleanup(func() { configForPolicy = restore })
	configForPolicy = func(_ string, conf *configuration.Configuration, _ platform.Policy) *configuration.PlumberConfig {
		evaluations++ // counts RESOLUTIONS; the cache below is what bounds EVALUATIONS
		return conf.PlumberConfig
	}

	conf := confWithPolicies(t,
		platform.Policy{ID: "1111", Name: "A", Enforcement: platform.EnforcementReport},
		platform.Policy{ID: "2222", Name: "B", Enforcement: platform.EnforcementReport},
		platform.Policy{ID: "3333", Name: "C", Enforcement: platform.EnforcementBlock},
	)

	got := buildPolicyResults(testProvider(t), conf, &control.AnalysisResult{}, nil, ".plumber.yaml")

	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	// All three share one configuration, so all three share one verdict.
	first, _ := json.Marshal(got[0].Findings)
	for i, r := range got[1:] {
		other, _ := json.Marshal(r.Findings)
		if string(first) != string(other) {
			t.Fatalf("policies sharing a configuration must share the verdict; entry %d differs", i+1)
		}
	}
}

// TestBuildPolicyResults_DifferentConfigsProduceIndependentVerdicts is the
// stated acceptance criterion: two policies configuring a control
// differently produce two artifacts whose verdicts are independent. It
// drives the seam per-policy configuration will arrive through, which is
// what makes the multi-policy machinery real rather than a shape.
func TestBuildPolicyResults_DifferentConfigsProduceIndependentVerdicts(t *testing.T) {
	// One config disables every control; the other enables branch
	// protection. The verdicts must differ.
	lax, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte("version: \"2.0\"\n"), "lax")
	if err != nil {
		t.Fatalf("load lax: %v", err)
	}
	strict, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(strictConfigYAML), "strict")
	if err != nil {
		t.Fatalf("load strict: %v", err)
	}

	restore := configForPolicy
	t.Cleanup(func() { configForPolicy = restore })
	configForPolicy = func(_ string, _ *configuration.Configuration, pol platform.Policy) *configuration.PlumberConfig {
		if pol.Name == "Strict" {
			return strict
		}
		return lax
	}

	conf := confWithPolicies(t,
		platform.Policy{ID: "1111", Name: "Lax", Enforcement: platform.EnforcementReport},
		platform.Policy{ID: "2222", Name: "Strict", Enforcement: platform.EnforcementBlock},
	)

	got := buildPolicyResults(testProvider(t), conf, &control.AnalysisResult{}, nil, ".plumber.yaml")

	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	laxFindings, _ := json.Marshal(got[0].Findings)
	strictFindings, _ := json.Marshal(got[1].Findings)
	if string(laxFindings) == string(strictFindings) {
		t.Fatalf("two policies with different control configurations must produce independent verdicts, both gave:\n%s", laxFindings)
	}
	// And each entry reports the configuration it actually ran.
	if string(got[0].EffectiveConfig) == string(got[1].EffectiveConfig) {
		t.Fatal("each entry must carry its OWN effective_config, not a shared one")
	}
}

// TestBuildPolicyResults_DerivedDefaultIsPushedNameOnly: the platform's
// fallback policy carries the nil uuid, which names no policies row.
// Sending it would key the run to a policy that does not exist.
func TestBuildPolicyResults_DerivedDefaultIsPushedNameOnly(t *testing.T) {
	conf := confWithPolicies(t, platform.Policy{
		ID: platform.NilUUID, Name: "[Plumber default]", Enforcement: platform.EnforcementReport,
	})

	got := buildPolicyResults(testProvider(t), conf, &control.AnalysisResult{}, nil, ".plumber.yaml")

	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].PolicyID != "" {
		t.Fatalf("the derived default must be pushed name-only, got policy_id %q", got[0].PolicyID)
	}
	if got[0].Policy != "[Plumber default]" {
		t.Fatalf("policy name: %q", got[0].Policy)
	}

	// And on the wire the key must be ABSENT, never the all-zero uuid.
	body, err := json.Marshal(platformPush{SchemaVersion: 1, Results: got})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), platform.NilUUID) {
		t.Fatalf("the all-zero uuid must never reach the wire:\n%s", body)
	}
	var raw struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := raw.Results[0]["policy_id"]; present {
		t.Fatalf("policy_id must be an ABSENT key, not an empty value: %v", raw.Results[0])
	}
}

// TestBuildPolicyResults_StandaloneFallsBackToTheLocalPolicy: with no
// platform context there is no policy set to key on, so the CLI pushes the
// single locally-named entry it always has. This is the default path and
// must not change.
func TestBuildPolicyResults_StandaloneFallsBackToTheLocalPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf *configuration.Configuration
	}{
		{"nil conf", nil},
		{"no platform run", &configuration.Configuration{}},
		{"platform run whose context fetch failed", &configuration.Configuration{
			PlatformRun: &platform.RunContext{Endpoint: "https://p.example.com"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := buildPolicyResults(testProvider(t), tc.conf, &control.AnalysisResult{}, nil, "team.plumber.yaml")
			if len(got) != 1 {
				t.Fatalf("want the single local entry, got %d", len(got))
			}
			if got[0].Policy != "team" {
				t.Fatalf("policy name must come from the config file, got %q", got[0].Policy)
			}
			if got[0].PolicyID != "" {
				t.Fatalf("a standalone push carries no policy id, got %q", got[0].PolicyID)
			}
		})
	}
}

func TestConfigFingerprint(t *testing.T) {
	a, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte("version: \"2.0\"\n"), "a")
	if err != nil {
		t.Fatalf("load a: %v", err)
	}
	b, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte("version: \"2.0\"\n"), "b")
	if err != nil {
		t.Fatalf("load b: %v", err)
	}
	c, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(
		"version: \"2.0\"\ngitlab:\n  branchMustBeProtected:\n    enabled: true\n"), "c")
	if err != nil {
		t.Fatalf("load c: %v", err)
	}

	if configFingerprint(a) != configFingerprint(b) {
		t.Fatal("identical config text must fingerprint equal, so the two policies share one evaluation")
	}
	if configFingerprint(a) == configFingerprint(c) {
		t.Fatal("different config text must fingerprint differently, or two policies would wrongly share a verdict")
	}
	if configFingerprint(nil) == configFingerprint(a) {
		t.Fatal("a nil config must not collide with a real one")
	}
	// A nil config must not silently collide with a config whose raw text
	// is empty either: both are "no controls configured" but they arrive by
	// different routes, and merging them would make two policies share an
	// evaluation they were never shown to agree on.
	empty := &configuration.PlumberConfig{}
	if configFingerprint(nil) == configFingerprint(empty) {
		t.Fatal("a nil config and an empty one must fingerprint differently")
	}
}

// TestPlatformCollectionFor_SnapshotProvenance: the push's collection block
// records which snapshot read produced the verdict and which lanes carried
// nothing, so a partial collection is never read as a complete one.
func TestPlatformCollectionFor_SnapshotProvenance(t *testing.T) {
	t.Run("standalone carries no snapshot fields", func(t *testing.T) {
		got := platformCollectionFor(&configuration.Configuration{}, &control.AnalysisResult{})
		if got.SnapshotCollectedAt != "" || got.MissingFields != nil {
			t.Fatalf("a standalone run has no snapshot to describe: %+v", got)
		}
	})

	t.Run("platform mode names the missing lanes", func(t *testing.T) {
		conf := &configuration.Configuration{PlatformRun: &platform.RunContext{
			Context: &platform.ProjectContext{Snapshot: platform.Snapshot{
				Data: &platform.SnapshotData{MergedYaml: "a: 1\n"},
			}},
		}}
		got := platformCollectionFor(conf, &control.AnalysisResult{})
		want := "branch_protection,mr_approvals,variables"
		if strings.Join(got.MissingFields, ",") != want {
			t.Fatalf("missing fields: got %v, want %s", got.MissingFields, want)
		}
	})

	t.Run("degraded collection is reported", func(t *testing.T) {
		got := platformCollectionFor(&configuration.Configuration{}, &control.AnalysisResult{DataCollectionDegraded: true})
		if !got.Degraded {
			t.Fatal("a degraded collection must be flagged")
		}
	})
}
