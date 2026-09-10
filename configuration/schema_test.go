package configuration

import (
	"reflect"
	"testing"
)

// The schema STRUCTURE is reflected from the real config structs so it can
// never drift from the code (#458): field names come from yaml tags, types
// from Go types, optionality from pointers/omitempty. Three representative
// controls pin the walker: flat bool-only, flat with arrays, and nested.
func TestReflectControlSchemas(t *testing.T) {
	schemas := reflectControlSchemas()

	t.Run("every ControlsConfig control field yields a schema", func(t *testing.T) {
		typ := reflect.TypeOf(ControlsConfig{})
		for i := 0; i < typ.NumField(); i++ {
			name := yamlName(typ.Field(i))
			if name == "" {
				continue
			}
			if _, ok := schemas[name]; !ok {
				t.Errorf("control %q has no reflected schema", name)
			}
		}
	})

	t.Run("enabled-only control is a single optional bool", func(t *testing.T) {
		s := schemas["cicdVariablesMustBeProtected"]
		if len(s.Fields) != 1 {
			t.Fatalf("fields = %+v, want exactly [enabled]", s.Fields)
		}
		f := s.Fields[0]
		if f.Name != "enabled" || f.Type != "bool" || !f.Optional {
			t.Errorf("enabled field = %+v, want optional bool named enabled", f)
		}
	})

	t.Run("forbidden-tags control carries its array field", func(t *testing.T) {
		s := schemas["containerImageMustNotUseForbiddenTags"]
		var found bool
		for _, f := range s.Fields {
			if f.Type == "array" {
				found = true
				if f.Elem == nil || f.Elem.Type != "string" {
					t.Errorf("array field %q Elem = %+v, want string items", f.Name, f.Elem)
				}
			}
		}
		if !found {
			t.Errorf("no array field reflected: %+v", s.Fields)
		}
	})

	// mergeRequestSettingsMustBeCompliant (MRSettingsControlConfig) is flat:
	// every field is a string/bool/int scalar, no nested struct. The real
	// example of "struct recurses into object Fields" in ControlsConfig is
	// securityJobsMustNotBeWeakened (SecurityJobsWeakenedControlConfig),
	// whose AllowFailureMustBeFalse / RulesMustNotBeRedefined /
	// WhenMustNotBeManual fields are each a *SecurityJobsSubControlToggle
	// struct. Swapped in per the brief's note: keep the invariant (structs
	// recurse into object Fields), not the specific control name.
	t.Run("nested structs become object fields with members", func(t *testing.T) {
		s := schemas["securityJobsMustNotBeWeakened"]
		var found bool
		for _, f := range s.Fields {
			if f.Type == "object" && len(f.Fields) > 0 {
				found = true
			}
		}
		if !found {
			t.Errorf("expected at least one object field with members, got %+v", s.Fields)
		}
	})
}

// controlBlockGuardFixture stands in for a ControlsConfig that has drifted: every control block
// is a pointer to a struct today, and the two other shapes below are what a future field could
// look like. Reflection cannot be type-checked at compile time, so the guard needs a fixture
// that actually has the wrong shapes.
type controlBlockGuardFixture struct {
	Block *struct {
		Enabled *bool `yaml:"enabled"`
	} `yaml:"blockControl"`
	Count *int `yaml:"countControl"`
	Plain int  `yaml:"plainControl"`
}

// TestStructPointerField_OnlyAcceptsAPointerToStruct pins the guard IsUnconfigured depends on:
// the value it gets back is dereferenced and walked with NumField, which panics on a pointer to
// anything that is not a struct. "No block" is the honest answer for a field of any other shape,
// and it is the answer that makes the control fall through to "asserts something" rather than
// taking the process down.
func TestStructPointerField_OnlyAcceptsAPointerToStruct(t *testing.T) {
	fixture := reflect.ValueOf(&controlBlockGuardFixture{}).Elem()

	got := structPointerField(fixture, "blockControl")
	if !got.IsValid() || got.Kind() != reflect.Ptr || got.Type().Elem().Kind() != reflect.Struct {
		t.Fatalf("blockControl = %v, want the pointer-to-struct field itself", got)
	}

	for _, name := range []string{"countControl", "plainControl", "noSuchControl"} {
		if got := structPointerField(fixture, name); got.IsValid() {
			t.Errorf("%s = %v, want an invalid Value: only a pointer to a struct can be walked", name, got)
		}
	}
}
