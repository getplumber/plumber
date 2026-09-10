package configuration

import (
	"testing"

	"gopkg.in/yaml.v2"
)

// TestIsUnconfigured pins #459: a RequiresConfig control enabled with no substantive field is
// unconfigured; one substantive field, a non-RequiresConfig control, a disabled control and a
// nil block are not.
func TestIsUnconfigured(t *testing.T) {
	requires := firstRequiresConfigControl(t) // helper: first ControlsCatalog() entry with RequiresConfig, plus its provider
	pcBare := plumberConfigWith(t, requires.Provider, requires.Name, map[string]interface{}{"enabled": true})
	if !IsUnconfigured(pcBare, requires.Provider, requires.Name) {
		t.Errorf("#459: %s with enabled:true only must be unconfigured", requires.Name)
	}
	pcSet := plumberConfigWith(t, requires.Provider, requires.Name, substantiveExample(t, requires.Name))
	if IsUnconfigured(pcSet, requires.Provider, requires.Name) {
		t.Errorf("#459: %s with a substantive field set must not be unconfigured", requires.Name)
	}
	plain := firstControlWhere(t, func(e ControlMeta) bool { return !e.RequiresConfig })
	pcPlain := plumberConfigWith(t, plain.Provider, plain.Name, map[string]interface{}{"enabled": true})
	if IsUnconfigured(pcPlain, plain.Provider, plain.Name) {
		t.Errorf("#459: a control that asserts something unconfigured is never unconfigured")
	}
	pcOff := plumberConfigWith(t, requires.Provider, requires.Name, map[string]interface{}{"enabled": false})
	if IsUnconfigured(pcOff, requires.Provider, requires.Name) {
		t.Error("#459: a disabled control is skipped, not unconfigured")
	}
	if IsUnconfigured(&PlumberConfig{}, requires.Provider, requires.Name) {
		t.Error("#459: an absent block is skipped, not unconfigured")
	}
}

// TestIsUnconfigured_NestedToggleSettingOnlyItsOwnEnabledIsNotSubstantive pins the nested-struct
// half of #459: a sub-control toggle block that sets nothing but its OWN `enabled` field turns no
// sub-check on, so it does not make the parent control substantive either, matching the same
// reading a bare top-level `enabled: true` gets. securityJobsMustNotBeWeakened is the one control
// with a pointer-to-struct field beyond `enabled` in the catalog, which is why it is used here.
func TestIsUnconfigured_NestedToggleSettingOnlyItsOwnEnabledIsNotSubstantive(t *testing.T) {
	pc := plumberConfigWith(t, "gitlab", "securityJobsMustNotBeWeakened", map[string]interface{}{
		"enabled": true,
		"allowFailureMustBeFalse": map[string]interface{}{
			"enabled": false,
		},
	})
	if !IsUnconfigured(pc, "gitlab", "securityJobsMustNotBeWeakened") {
		t.Error("#459: a sub-control toggle setting only its own enabled field turns nothing on and must be unconfigured")
	}

	pcSubstantive := plumberConfigWith(t, "gitlab", "securityJobsMustNotBeWeakened", map[string]interface{}{
		"enabled":             true,
		"securityJobPatterns": []interface{}{"secret_scan"},
	})
	if IsUnconfigured(pcSubstantive, "gitlab", "securityJobsMustNotBeWeakened") {
		t.Error("#459: a securityJobPatterns entry is a substantive field and must not be unconfigured")
	}
}

// requiresConfigControl is a (name, provider) pair picked out of ControlsCatalog() for the test
// helpers below: enough to build a minimal .plumber.yaml fixture and call IsUnconfigured.
type requiresConfigControl struct {
	Name     string
	Provider string
}

// firstRequiresConfigControl returns the first catalog entry with RequiresConfig true, paired
// with one of the providers it applies to.
func firstRequiresConfigControl(t *testing.T) requiresConfigControl {
	t.Helper()
	return firstControlWhere(t, func(e ControlMeta) bool { return e.RequiresConfig })
}

// firstControlWhere returns the first catalog entry matching pred, paired with one of the
// providers it applies to.
func firstControlWhere(t *testing.T, pred func(ControlMeta) bool) requiresConfigControl {
	t.Helper()
	for _, e := range ControlsCatalog() {
		if pred(e.ControlMeta) && len(e.Providers) > 0 {
			return requiresConfigControl{Name: e.Name, Provider: e.Providers[0]}
		}
	}
	t.Fatal("no control matched the predicate")
	return requiresConfigControl{}
}

// plumberConfigWith builds a v2 PlumberConfig with a single control block, provider and control
// name given, its fields the ones supplied. Goes through the real YAML loader so the fixture is
// exercised the same way a user's .plumber.yaml would be.
func plumberConfigWith(t *testing.T, provider, controlName string, fields map[string]interface{}) *PlumberConfig {
	t.Helper()
	doc := map[string]interface{}{
		"version": "2.0",
		provider: map[string]interface{}{
			"controls": map[string]interface{}{
				controlName: fields,
			},
		},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	pc, _, _, err := LoadPlumberConfigFromBytes(data, "test")
	if err != nil {
		t.Fatalf("load fixture: %v\n%s", err, data)
	}
	return pc
}

// substantiveExample returns a control block (enabled, plus its first non-`enabled` field set to
// a non-zero value of its type) built from the control's own reflected schema, so the fixture can
// never drift from the real config struct.
func substantiveExample(t *testing.T, controlName string) map[string]interface{} {
	t.Helper()
	schema, ok := ConfigSchemaFor(controlName)
	if !ok {
		t.Fatalf("no config schema for %s", controlName)
	}
	for _, f := range schema.Fields {
		if f.Name == "enabled" {
			continue
		}
		return map[string]interface{}{
			"enabled": true,
			f.Name:    nonZeroValue(t, f),
		}
	}
	t.Fatalf("schema for %s has no field beyond enabled", controlName)
	return nil
}

// nonZeroValue builds a value of f's reflected type that is not its zero value. An object field
// with no fixed sub-fields (a map) gets a single synthetic key; an object field with sub-fields
// (a nested struct) recurses to its first leaf, since an empty object `{}` is itself zero.
func nonZeroValue(t *testing.T, f SchemaField) interface{} {
	t.Helper()
	switch f.Type {
	case "string":
		return "x"
	case "bool":
		return true
	case "integer", "number":
		return 1
	case "array":
		if f.Elem != nil {
			return []interface{}{nonZeroValue(t, *f.Elem)}
		}
		return []interface{}{"x"}
	case "object":
		if len(f.Fields) == 0 {
			if f.Elem != nil {
				return map[string]interface{}{"x": nonZeroValue(t, *f.Elem)}
			}
			return map[string]interface{}{"x": "x"}
		}
		for _, nf := range f.Fields {
			if nf.Name == "enabled" {
				continue
			}
			return map[string]interface{}{nf.Name: nonZeroValue(t, nf)}
		}
		t.Fatalf("object field %s has no non-enabled sub-field to set", f.Name)
		return nil
	default:
		return "x"
	}
}
