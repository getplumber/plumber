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

// The #368 shape: two policies declaring the SAME control_type with
// DIFFERENT parameters must each evaluate under their own. Reading one
// policy's config and reporting it under the other's name is the bug the
// control tree exists to end, so this asserts the two configs differ AND
// that each carries its own value.
func TestConfigForPolicyUsesEachPolicysOwnConfig(t *testing.T) {
	strict := treePolicy("Strict", platform.PolicyControl{
		ControlType: "branchMustBeProtected",
		Config:      []byte(`{"enabled":true,"minMergeAccessLevel":40}`),
	})
	lenient := treePolicy("Lenient", platform.PolicyControl{
		ControlType: "branchMustBeProtected",
		Config:      []byte(`{"enabled":true,"minMergeAccessLevel":30}`),
	})

	sc, _, sr := configForPlatformPolicy("gitlab", strict)
	lc, _, lr := configForPlatformPolicy("gitlab", lenient)
	if sc == nil || lc == nil {
		t.Fatalf("both policies must resolve a config, got reasons %q / %q", sr, lr)
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

// R2: a REAL policy with no stored tree declares an empty set, and that is
// what it is evaluated under. Falling back to the local configuration would
// report a verdict the policy never asked for, under this policy's name -
// the same confusion the control tree exists to end - so the honest answer
// is an empty configuration plus the reason.
func TestConfigForPlatformPolicy_NoTreeIsEmptySet(t *testing.T) {
	for _, pol := range []platform.Policy{
		{ID: "abc", Name: "Unconfigured", Requirements: []platform.PolicyRequirement{}},
		{ID: "def", Name: "EmptyRequirement", Requirements: []platform.PolicyRequirement{{Name: "R"}}},
	} {
		t.Run(pol.Name, func(t *testing.T) {
			cfg, derived, reason := configForPlatformPolicy("gitlab", pol)
			if cfg == nil || derived {
				t.Fatalf("a real policy declaring no controls must resolve an empty config, got cfg=%v derived=%v", cfg, derived)
			}
			if reason != reasonNoControls {
				t.Fatalf("reason = %q, want %q", reason, reasonNoControls)
			}
			controls := cfg.ControlsFor("gitlab")
			if controls == nil {
				t.Fatal("an empty configuration must still answer with a controls block")
			}
			if controls.BranchMustBeProtected != nil || controls.CicdVariablesMustBeMasked != nil {
				t.Fatalf("the empty set must enable no control at all: %+v", controls)
			}
		})
	}
}

// Only the controls the policy declares are configured. Nothing else may
// appear, or the policy's verdict would include checks it never asked for.
func TestConfigForPolicyOmitsUndeclaredControls(t *testing.T) {
	pol := treePolicy("OnlyVariables", platform.PolicyControl{
		ControlType: "cicdVariablesMustBeMasked",
		Config:      []byte(`{"enabled":true}`),
	})
	cfg, _, _ := configForPlatformPolicy("gitlab", pol)
	controls := cfg.ControlsFor("gitlab")
	if controls.CicdVariablesMustBeMasked == nil || !controls.CicdVariablesMustBeMasked.IsEnabled() {
		t.Fatal("the declared control must be configured")
	}
	if controls.BranchMustBeProtected != nil {
		t.Fatal("a control the policy never declared must not appear in its configuration")
	}
}

// The platform serves config as raw stored bytes so a large integer is not
// rounded. The CLI splices those bytes into YAML rather than decoding and
// re-encoding them, so the value has to survive to the typed config.
func TestConfigForPolicyPreservesLargeIntegers(t *testing.T) {
	pol := treePolicy("Big", platform.PolicyControl{
		ControlType: "projectMustHaveSecurityPolicySource",
		Config:      []byte(`{"enabled":true,"expectedProjectId":9007199254740993}`),
	})
	cfg, _, _ := configForPlatformPolicy("gitlab", pol)
	sp := cfg.ControlsFor("gitlab").ProjectMustHaveSecurityPolicySource
	if sp == nil || sp.ExpectedProjectId == nil {
		t.Fatal("the control must be configured with its expectedProjectId")
	}
	if *sp.ExpectedProjectId != 9007199254740993 {
		t.Fatalf("large integer was rounded: got %d, want 9007199254740993", *sp.ExpectedProjectId)
	}
}

// One malformed control costs the policy that control and nothing else: the
// rest of the tree still applies. Dropping the whole policy over a single
// unreadable entry would leave it unevaluated and absent from the push, and
// falling back to the local configuration would evaluate it under parameters
// it never asked for.
func TestConfigForPlatformPolicy_MalformedControlIsDropped_OthersApply(t *testing.T) {
	pol := treePolicy("Broken",
		platform.PolicyControl{ControlType: "cicdVariablesMustBeMasked", Config: []byte(`{"enabled":`)}, // truncated
		platform.PolicyControl{ControlType: "branchMustBeProtected", Config: []byte(`{"enabled":true,"minMergeAccessLevel":40}`)},
	)

	cfg, _, reason := configForPlatformPolicy("gitlab", pol)

	if cfg == nil {
		t.Fatalf("one bad control must not cost the policy its tree, got reason %q", reason)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want none: the tree WAS applied", reason)
	}
	controls := cfg.ControlsFor("gitlab")
	if controls.BranchMustBeProtected == nil || controls.BranchMustBeProtected.MinMergeAccessLevel == nil ||
		*controls.BranchMustBeProtected.MinMergeAccessLevel != 40 {
		t.Fatal("the readable control must still take effect alongside the unreadable one")
	}
	if controls.CicdVariablesMustBeMasked != nil {
		t.Fatal("the unreadable control must not be applied from guessed bytes")
	}
}

// A control_type the CLI does not know must not break the whole tree: the
// controls it DOES know still apply. Forward tolerance is the contract.
func TestConfigForPolicyIgnoresUnknownControlType(t *testing.T) {
	pol := treePolicy("Mixed",
		platform.PolicyControl{ControlType: "someFutureControl", Config: []byte(`{"enabled":true}`)},
		platform.PolicyControl{ControlType: "branchMustBeProtected", Config: []byte(`{"enabled":true,"minMergeAccessLevel":40}`)},
	)
	cfg, _, reason := configForPlatformPolicy("gitlab", pol)
	if cfg == nil {
		t.Fatalf("a tree with one unknown control must still be applied, not abandoned: %q", reason)
	}
	b := cfg.ControlsFor("gitlab").BranchMustBeProtected
	if b == nil || b.MinMergeAccessLevel == nil || *b.MinMergeAccessLevel != 40 {
		t.Fatal("the known control must still take effect alongside an unknown one")
	}
}

// One control the CLI cannot read must cost the policy that control, not
// its whole tree. Dropping the whole tree over a single bad entry leaves the
// policy unevaluated and absent from the push entirely.
func TestPolicyConfigFromTreeSkipsUnusableControls(t *testing.T) {
	// A blank name alongside a real control: the real one still applies.
	cfg, err := policyConfigFromTree("gitlab", treePolicy("Mixed",
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
	cfg, err = policyConfigFromTree("gitlab", treePolicy("Truncated",
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
	cfg, err := policyConfigFromTree("gitlab", treePolicy("Bare",
		platform.PolicyControl{ControlType: "branchMustBeProtected"},
	))
	if err != nil {
		t.Fatalf("a control with no config must assemble, not error: %v", err)
	}
	if cfg.ControlsFor("gitlab").BranchMustBeProtected == nil {
		t.Fatal("a control declared with no parameters must still be present in the tree")
	}
}

// R3: a tree in which nothing at all could be read is a tree that did not
// arrive. Assembling an empty ruleset from it would push a verdict in which
// the policy checked nothing, so the policy is NOT APPLIED: no configuration,
// a reason, and (buildPolicyResults) no entry in the push at all.
func TestPolicyConfigFromTreeRefusesAnEntirelyUnreadableTree(t *testing.T) {
	pol := treePolicy("Empty", platform.PolicyControl{ControlType: "  ", Config: []byte(`{"enabled":true}`)})

	if _, err := policyConfigFromTree("gitlab", pol); err == nil {
		t.Fatal("a tree with nothing usable in it must not assemble to an empty ruleset")
	}

	cfg, derived, reason := configForPlatformPolicy("gitlab", pol)
	if cfg != nil || derived {
		t.Fatalf("an unreadable tree must resolve no configuration, got cfg=%v derived=%v", cfg, derived)
	}
	if !strings.HasPrefix(reason, reasonTreeNotApplied) {
		t.Fatalf("reason = %q, want the not-applied reason", reason)
	}
}

// The provider section has to be the one being analysed. Assembling a
// GitHub policy under `gitlab:` marks every GitHub control skipped, and the
// push then reports a run in which nothing was checked.
func TestPolicyConfigFromTreeUsesTheAnalysedProviderSection(t *testing.T) {
	cfg, err := policyConfigFromTree("github", treePolicy("GH",
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

// R4: the assembled version is the schema constant, never read off the run's
// local file. In platform mode the policy's tree IS the configuration, and a
// file the policy has nothing to do with must not decide how its controls
// parse - not even by supplying a version number.
func TestPolicyConfigFromTreeKeepsConfigVersion(t *testing.T) {
	cfg, err := policyConfigFromTree("gitlab", treePolicy("V", platform.PolicyControl{
		ControlType: "branchMustBeProtected", Config: []byte(`{"enabled":true}`),
	}))
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if cfg.Version != policyConfigVersion {
		t.Fatalf("assembled config version = %q, want the schema constant %q", cfg.Version, policyConfigVersion)
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
