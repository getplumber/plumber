package configuration

import "testing"

// RequiresConfig is authored truth (#458, the requiresConfig amendment):
// true only when enabling the control with no further configuration
// asserts nothing (the inert getplumber/plumber#459 shape). A control
// that claims RequiresConfig must actually have configurable surface to
// require: it needs a reflected config schema, and that schema needs at
// least one field beyond `enabled` (a control whose only knob is
// enabled/disabled cannot meaningfully "require" configuration).
func TestRequiresConfigImpliesConfigSchema(t *testing.T) {
	schemas := reflectControlSchemas()
	for _, e := range ControlsCatalog() {
		if !e.RequiresConfig {
			continue
		}
		schema, ok := schemas[e.Name]
		if !ok {
			t.Errorf("control %q: RequiresConfig is true but has no config schema", e.Name)
			continue
		}
		hasSubstantiveField := false
		for _, f := range schema.Fields {
			if f.Name != "enabled" {
				hasSubstantiveField = true
				break
			}
		}
		if !hasSubstantiveField {
			t.Errorf("control %q: RequiresConfig is true but its schema has no field beyond enabled", e.Name)
		}
	}
}

// The field must not silently regress to all-false: at least a couple of
// controls are genuinely inert without configuration (the #459 shape), so
// a wholesale reset of the registry (or a copy-paste that drops the
// RequiresConfig: true lines) shows up here instead of shipping quietly.
func TestAtLeastTwoControlsRequireConfig(t *testing.T) {
	count := 0
	for _, e := range ControlsCatalog() {
		if e.RequiresConfig {
			count++
		}
	}
	if count < 2 {
		t.Errorf("expected at least 2 controls with RequiresConfig true, got %d", count)
	}
}
