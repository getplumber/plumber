package control

import (
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// TestDisabledControlNames_MatchesCatalogSkipFlags is the parity the old
// hand-written if-chain never had: every control the catalog reports as
// Skipped on a given config must be in DisabledControlNames for that config,
// and vice versa. The chain silently lacked a branch for
// actionRefsMustExistUpstream from the day the control was added, so a
// config that disabled it still let its Critical ISSUE-707 findings through
// FilterFindingsByEnabledControls into SARIF, GLSAST, PBOM and the score.
func TestDisabledControlNames_MatchesCatalogSkipFlags(t *testing.T) {
	cases := map[string]*configuration.PlumberConfig{
		"empty config, everything off": {},
		"one control on": {
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				ActionRefsMustExistUpstream: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
			}},
			GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				ActionRefsMustExistUpstream: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
			}},
		},
	}
	for name, pc := range cases {
		t.Run(name, func(t *testing.T) {
			for _, provider := range []string{"gitlab", "github"} {
				c := pc.ControlsFor(provider)
				var entries []ControlEntry
				if provider == "gitlab" {
					entries = GitLabControls(pc)
				} else {
					entries = GitHubControls(pc)
				}
				disabled := DisabledControlNames(c)
				for _, e := range entries {
					if e.Skipped != disabled[e.ControlName] {
						t.Errorf("%s/%s: catalog Skipped=%v but DisabledControlNames=%v", provider, e.ControlName, e.Skipped, disabled[e.ControlName])
					}
				}
			}
		})
	}
}

// TestDisabledControlNames_CoversEveryConfigField pins the derivation
// against the struct it derives from: one entry per ControlsConfig field
// when every field is nil, keyed by the field's yaml name, and every field
// type answers IsEnabled so the derivation never has to guess.
func TestDisabledControlNames_CoversEveryConfigField(t *testing.T) {
	disabled := DisabledControlNames(&configuration.ControlsConfig{})
	typ := reflect.TypeOf(configuration.ControlsConfig{})
	enabler := reflect.TypeOf((*interface{ IsEnabled() bool })(nil)).Elem()
	want := 0
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		want++
		if !disabled[name] {
			t.Errorf("field %s (yaml %q) is nil and must be reported disabled", f.Name, name)
		}
		if !f.Type.Implements(enabler) {
			t.Errorf("field %s: type %s does not implement IsEnabled(); the derivation needs it", f.Name, f.Type)
		}
	}
	if len(disabled) != want {
		t.Errorf("DisabledControlNames on an empty config has %d entries, want one per field (%d)", len(disabled), want)
	}
	if !disabled["actionRefsMustExistUpstream"] {
		t.Error("actionRefsMustExistUpstream nil must be disabled (the branch the hand-written chain never had)")
	}
}

// TestDisabledControlNames_SecurityJobsSubChecks keeps the one special case
// the derivation carries: the parent is on but every sub-check is off, so
// there is nothing to check and the control is skipped.
func TestDisabledControlNames_SecurityJobsSubChecks(t *testing.T) {
	off := &configuration.SecurityJobsSubControlToggle{Enabled: boolPtr(false)}
	c := &configuration.ControlsConfig{
		SecurityJobsMustNotBeWeakened: &configuration.SecurityJobsWeakenedControlConfig{
			Enabled:                 boolPtr(true),
			AllowFailureMustBeFalse: off,
			RulesMustNotBeRedefined: off,
			WhenMustNotBeManual:     off,
		},
	}
	if !DisabledControlNames(c)["securityJobsMustNotBeWeakened"] {
		t.Error("parent on with every sub-check off is skipped, and must read as disabled")
	}
	c.SecurityJobsMustNotBeWeakened.WhenMustNotBeManual = nil // absent sub-check defaults to on
	if DisabledControlNames(c)["securityJobsMustNotBeWeakened"] {
		t.Error("one sub-check left on (absent means on) keeps the control enabled")
	}
}
