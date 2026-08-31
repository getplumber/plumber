package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/platform"
	"gopkg.in/yaml.v2"
)

func treePolicy(name string, controls ...platform.PolicyControl) platform.Policy {
	return platform.Policy{
		ID:           "11111111-1111-1111-1111-111111111111",
		Name:         name,
		Enforcement:  platform.EnforcementReport,
		Requirements: []platform.PolicyRequirement{{Name: "R", Controls: controls}},
	}
}

func localConf(t *testing.T) *configuration.Configuration {
	t.Helper()
	enabled := true
	return &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
		Version: "2.0",
		GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &enabled},
		}},
	}}
}

// The #368 shape: two policies declaring the SAME control_type with
// DIFFERENT parameters must each evaluate under their own. Reading one
// policy's config and reporting it under the other's name is the bug the
// control tree exists to end, so this asserts the two configs differ AND
// that each carries its own value rather than merely "not the local one".
func TestConfigForPolicyUsesEachPolicysOwnConfig(t *testing.T) {
	conf := localConf(t)
	strict := treePolicy("Strict", platform.PolicyControl{
		ControlType: "branchMustBeProtected",
		Config:      []byte(`{"enabled":true,"minMergeAccessLevel":40}`),
	})
	lenient := treePolicy("Lenient", platform.PolicyControl{
		ControlType: "branchMustBeProtected",
		Config:      []byte(`{"enabled":true,"minMergeAccessLevel":30}`),
	})

	sc := configForPolicy("gitlab", conf, strict)
	lc := configForPolicy("gitlab", conf, lenient)
	if sc == nil || lc == nil {
		t.Fatal("both policies must resolve a config")
	}

	got := func(c *configuration.PlumberConfig) int {
		b := c.ControlsFor("gitlab").BranchMustBeProtected
		if b == nil || b.MinMergeAccessLevel == nil {
			t.Fatal("branchMustBeProtected must be present in the assembled config with its minMergeAccessLevel")
		}
		return *b.MinMergeAccessLevel
	}
	if got(sc) != 40 {
		t.Errorf("Strict minMergeAccessLevel = %d, want 40", got(sc))
	}
	if got(lc) != 30 {
		t.Errorf("Lenient minMergeAccessLevel = %d, want 30", got(lc))
	}

	// Distinct configs must not collapse into one cached evaluation.
	if configFingerprint(sc) == configFingerprint(lc) {
		t.Fatal("two policies with different parameters must not share an evaluation")
	}
}

// A policy with no stored tree (the derived [Plumber default], or a real
// policy an admin has not configured) must fall back to the local config.
// Evaluating it against an empty ruleset would report a clean pass for a
// policy that simply has not been filled in yet.
func TestConfigForPolicyFallsBackWhenTreeIsEmpty(t *testing.T) {
	conf := localConf(t)
	for _, pol := range []platform.Policy{
		{ID: platform.NilUUID, Name: "[Plumber default]", Enforcement: platform.EnforcementReport},
		{ID: "abc", Name: "Unconfigured", Requirements: []platform.PolicyRequirement{}},
		{ID: "def", Name: "EmptyRequirement", Requirements: []platform.PolicyRequirement{{Name: "R"}}},
	} {
		t.Run(pol.Name, func(t *testing.T) {
			if got := configForPolicy("gitlab", conf, pol); got != conf.PlumberConfig {
				t.Fatal("a policy declaring no controls must fall back to the local configuration")
			}
		})
	}
}

// Only the controls the policy declares are configured. A control it does
// not mention must not leak in from the local config, or the policy's
// verdict would include checks it never asked for.
func TestConfigForPolicyOmitsUndeclaredControls(t *testing.T) {
	conf := localConf(t)
	pol := treePolicy("OnlyVariables", platform.PolicyControl{
		ControlType: "cicdVariablesMustBeMasked",
		Config:      []byte(`{"enabled":true}`),
	})
	cfg := configForPolicy("gitlab", conf, pol)
	controls := cfg.ControlsFor("gitlab")
	if controls.CicdVariablesMustBeMasked == nil || !controls.CicdVariablesMustBeMasked.IsEnabled() {
		t.Fatal("the declared control must be configured")
	}
	if controls.BranchMustBeProtected != nil {
		t.Fatal("a control the policy never declared must not be inherited from the local config")
	}
}

// The platform serves config as raw stored bytes so a large integer is not
// rounded. The CLI splices those bytes into YAML rather than decoding and
// re-encoding them, so the value has to survive to the typed config.
func TestConfigForPolicyPreservesLargeIntegers(t *testing.T) {
	conf := localConf(t)
	pol := treePolicy("Big", platform.PolicyControl{
		ControlType: "projectMustHaveSecurityPolicySource",
		Config:      []byte(`{"enabled":true,"expectedProjectId":9007199254740993}`),
	})
	cfg := configForPolicy("gitlab", conf, pol)
	sp := cfg.ControlsFor("gitlab").ProjectMustHaveSecurityPolicySource
	if sp == nil || sp.ExpectedProjectId == nil {
		t.Fatal("the control must be configured with its expectedProjectId")
	}
	if *sp.ExpectedProjectId != 9007199254740993 {
		t.Fatalf("large integer was rounded: got %d, want 9007199254740993", *sp.ExpectedProjectId)
	}
}

// Malformed config must not silently evaluate the policy under someone
// else's parameters without saying so. The run continues on the local
// config; the point here is that it does not panic and does not produce a
// half-applied tree.
func TestConfigForPolicyToleratesMalformedConfig(t *testing.T) {
	conf := localConf(t)
	pol := treePolicy("Broken", platform.PolicyControl{
		ControlType: "branchMustBeProtected",
		Config:      []byte(`{"enabled":`), // truncated
	})
	got := configForPolicy("gitlab", conf, pol)
	if got != conf.PlumberConfig {
		t.Fatal("a policy whose tree cannot be applied must fall back to the local configuration")
	}
}

// A control_type the CLI does not know must not break the whole tree: the
// controls it DOES know still apply. Forward tolerance is the contract.
func TestConfigForPolicyIgnoresUnknownControlType(t *testing.T) {
	conf := localConf(t)
	pol := treePolicy("Mixed",
		platform.PolicyControl{ControlType: "someFutureControl", Config: []byte(`{"enabled":true}`)},
		platform.PolicyControl{ControlType: "branchMustBeProtected", Config: []byte(`{"enabled":true,"minMergeAccessLevel":40}`)},
	)
	cfg := configForPolicy("gitlab", conf, pol)
	if cfg == conf.PlumberConfig {
		t.Fatal("a tree with one unknown control must still be applied, not abandoned")
	}
	b := cfg.ControlsFor("gitlab").BranchMustBeProtected
	if b == nil || b.MinMergeAccessLevel == nil || *b.MinMergeAccessLevel != 40 {
		t.Fatal("the known control must still take effect alongside an unknown one")
	}
}

// One control the CLI cannot read must cost the policy that control, not
// its whole tree. Falling back to the local configuration over a single bad
// entry evaluates the policy under someone else's parameters and reports it
// under this policy's name, which is the confusion the tree exists to end.
func TestPolicyConfigFromTreeSkipsUnusableControls(t *testing.T) {
	conf := localConf(t)

	// A blank name alongside a real control: the real one still applies.
	cfg, err := policyConfigFromTree("gitlab", conf, treePolicy("Mixed",
		platform.PolicyControl{ControlType: "  ", Config: []byte(`{"enabled":true}`)},
		platform.PolicyControl{ControlType: "branchMustBeProtected", Config: []byte(`{"enabled":true,"minMergeAccessLevel":40}`)},
	))
	if err != nil {
		t.Fatalf("a blank control name must be skipped, not error: %v", err)
	}
	b := cfg.ControlsFor("gitlab").BranchMustBeProtected
	if b == nil || b.MinMergeAccessLevel == nil || *b.MinMergeAccessLevel != 40 {
		t.Fatal("the usable control must still take effect alongside an unusable one")
	}

	// A truncated config alongside a real control: same rule. Failing the
	// whole tree over one control would send the policy back to the local
	// configuration and report it under someone else's parameters.
	cfg, err = policyConfigFromTree("gitlab", conf, treePolicy("Truncated",
		platform.PolicyControl{ControlType: "cicdVariablesMustBeMasked", Config: []byte(`{"enabled":`)},
		platform.PolicyControl{ControlType: "branchMustBeProtected", Config: []byte(`{"enabled":true}`)},
	))
	if err != nil {
		t.Fatalf("one unreadable control must not cost the policy its others: %v", err)
	}
	if cfg.ControlsFor("gitlab").BranchMustBeProtected == nil {
		t.Fatal("the readable control must still be applied")
	}
	if cfg.ControlsFor("gitlab").CicdVariablesMustBeMasked != nil {
		t.Fatal("the unreadable control must not be applied from guessed bytes")
	}
}

// A control declared with NO config is one enabled at its defaults, which
// is a legitimate policy shape - not a broken tree. json.Compact reports
// "unexpected end of JSON input" for zero bytes, so without this the whole
// policy would fall back to the local configuration over a control the
// platform served perfectly well.
func TestPolicyConfigFromTreeTreatsAnAbsentConfigAsDefaults(t *testing.T) {
	conf := localConf(t)
	cfg, err := policyConfigFromTree("gitlab", conf, treePolicy("Bare",
		platform.PolicyControl{ControlType: "branchMustBeProtected"},
	))
	if err != nil {
		t.Fatalf("a control with no config must assemble, not error: %v", err)
	}
	if cfg.ControlsFor("gitlab").BranchMustBeProtected == nil {
		t.Fatal("a control declared with no parameters must still be present in the tree")
	}
}

// A tree in which nothing at all could be read is a tree that did not
// arrive. Assembling an empty ruleset from it would push a verdict in which
// the policy checked nothing; the error routes the caller to the same
// local-config fallback a policy with no tree takes.
func TestPolicyConfigFromTreeRefusesAnEntirelyUnreadableTree(t *testing.T) {
	conf := localConf(t)
	if _, err := policyConfigFromTree("gitlab", conf, treePolicy("Empty",
		platform.PolicyControl{ControlType: "  ", Config: []byte(`{"enabled":true}`)},
	)); err == nil {
		t.Fatal("a tree with nothing usable in it must not assemble to an empty ruleset")
	}
}

// The provider section has to be the one being analysed. Assembling a
// GitHub policy under `gitlab:` marks every GitHub control skipped, and the
// push then reports a run in which nothing was checked.
func TestPolicyConfigFromTreeUsesTheAnalysedProviderSection(t *testing.T) {
	conf := localConf(t)
	cfg, err := policyConfigFromTree("github", conf, treePolicy("GH",
		platform.PolicyControl{ControlType: "actionsMustBePinnedByCommitSha", Config: []byte(`{"enabled":true}`)},
	))
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if cfg.ControlsFor("github").ActionsMustBePinnedByCommitSha == nil {
		t.Fatal("a GitHub policy must assemble under the github section")
	}
	if cfg.ControlsFor("gitlab").BranchMustBeProtected != nil {
		t.Fatal("a GitHub policy must not write into the gitlab section")
	}
}

func TestPolicyConfigFromTreeKeepsConfigVersion(t *testing.T) {
	conf := localConf(t)
	conf.PlumberConfig.Version = "2.0"
	cfg, err := policyConfigFromTree("gitlab", conf, treePolicy("V", platform.PolicyControl{
		ControlType: "branchMustBeProtected", Config: []byte(`{"enabled":true}`),
	}))
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if !strings.HasPrefix(cfg.Version, "2") {
		t.Fatalf("assembled config version = %q, want the run's own 2.x", cfg.Version)
	}
}

// The raw-bytes splice rests on "JSON is a subset of YAML", which holds
// except at three code points. NEL (U+0085), LINE SEPARATOR (U+2028) and
// PARAGRAPH SEPARATOR (U+2029) are ordinary string characters to JSON and
// LINE BREAKS to YAML, and libyaml folds a line break inside a quoted
// scalar to a space.
//
// A control parameter carrying one - a trustedUrls entry or an allowlist
// pattern pasted out of a document - would then be evaluated against a
// value that differs from the one the platform stored, and silently stop
// matching. Nothing else in the pipeline would report a discrepancy: the
// splice is valid YAML either way.
func TestPolicyControlValueSurvivesYAMLLineBreaks(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"NEL", "{\"pattern\":\"a\\u0085b\"}"},
		{"line separator", "{\"pattern\":\"a\\u2028b\"}"},
		{"paragraph separator", "{\"pattern\":\"a\\u2029b\"}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Decode the escapes so the value carries the LITERAL code
			// point, which is what the platform serves: json.Compact does
			// not escape them and JSON permits them unescaped.
			var decoded map[string]string
			if err := json.Unmarshal([]byte(tc.raw), &decoded); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			literal, err := json.Marshal(decoded)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			want := decoded["pattern"]

			value, err := policyControlValue(literal)
			if err != nil {
				t.Fatalf("policyControlValue: %v", err)
			}

			// Round-trip it exactly as the assembled document does.
			var out struct {
				Controls map[string]map[string]string `yaml:"controls"`
			}
			doc := "controls:\n  c: " + value + "\n"
			if err := yaml.Unmarshal([]byte(doc), &out); err != nil {
				t.Fatalf("the spliced value is not valid YAML: %v\n%s", err, doc)
			}
			if got := out.Controls["c"]["pattern"]; got != want {
				t.Errorf("value changed across the splice:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// A control declared with no config at all must splice to an empty mapping,
// not abort the policy. json.Compact reports "unexpected end of JSON input"
// for zero bytes, which is not a broken tree - it is a control enabled at
// its defaults.
func TestPolicyControlValueTreatsAbsentConfigAsEmptyMapping(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage(""), json.RawMessage("  ")} {
		value, err := policyControlValue(raw)
		if err != nil {
			t.Fatalf("an absent config must not error: %v", err)
		}
		if value != "{}" {
			t.Errorf("absent config spliced as %q, want an empty mapping", value)
		}
	}
}
