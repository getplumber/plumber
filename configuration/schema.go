package configuration

import (
	"reflect"
	"sort"
	"strings"
)

// SchemaField describes one field of a control's configuration: name and
// nesting from the yaml tags, type from the Go type, optionality from
// pointers/omitempty. Structure is REFLECTED from the real config structs
// so it can never drift from the code; Description/Enum/Default are welded
// on from the authored table in schema_docs.go (#458).
type SchemaField struct {
	Name        string        `json:"name,omitempty"`
	Type        string        `json:"type"`
	Optional    bool          `json:"optional"`
	Description string        `json:"description,omitempty"`
	Elem        *SchemaField  `json:"elem,omitempty"`
	Fields      []SchemaField `json:"fields,omitempty"`
	Enum        []string      `json:"enum,omitempty"`
	Default     string        `json:"default,omitempty"`
}

// ControlConfigSchema is the machine-readable shape of one control's
// .plumber.yaml block: what the platform renders config forms from and
// validates against, generated from the CLI's own structs (#458).
type ControlConfigSchema struct {
	Control string        `json:"control"`
	Fields  []SchemaField `json:"fields"`
}

// yamlName returns the effective yaml key of a struct field, or "" when the
// field is skipped (yaml:"-" or unexported).
func yamlName(f reflect.StructField) string {
	if f.PkgPath != "" {
		return ""
	}
	tag := f.Tag.Get("yaml")
	name := strings.Split(tag, ",")[0]
	if name == "-" {
		return ""
	}
	if name == "" {
		return strings.ToLower(f.Name[:1]) + f.Name[1:]
	}
	return name
}

func yamlOmitempty(f reflect.StructField) bool {
	for _, opt := range strings.Split(f.Tag.Get("yaml"), ",")[1:] {
		if opt == "omitempty" {
			return true
		}
	}
	return false
}

// reflectControlSchemas walks ControlsConfig: each control-pointer field
// becomes one schema keyed by its yaml name, its struct type walked
// recursively into fields.
func reflectControlSchemas() map[string]ControlConfigSchema {
	out := map[string]ControlConfigSchema{}
	typ := reflect.TypeOf(ControlsConfig{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := yamlName(f)
		if name == "" {
			continue
		}
		t := f.Type
		for t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			continue
		}
		out[name] = ControlConfigSchema{Control: name, Fields: structFields(t)}
	}
	return out
}

func structFields(t reflect.Type) []SchemaField {
	var fields []SchemaField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := yamlName(f)
		if name == "" {
			continue
		}
		sf := typeToField(f.Type)
		sf.Name = name
		if f.Type.Kind() == reflect.Ptr || yamlOmitempty(f) {
			sf.Optional = true
		}
		fields = append(fields, sf)
	}
	return fields
}

func typeToField(t reflect.Type) SchemaField {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return SchemaField{Type: "string"}
	case reflect.Bool:
		return SchemaField{Type: "bool"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return SchemaField{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return SchemaField{Type: "number"}
	case reflect.Slice, reflect.Array:
		elem := typeToField(t.Elem())
		return SchemaField{Type: "array", Elem: &elem}
	case reflect.Map:
		elem := typeToField(t.Elem())
		return SchemaField{Type: "object", Elem: &elem}
	case reflect.Struct:
		return SchemaField{Type: "object", Fields: structFields(t)}
	default:
		return SchemaField{Type: "string"}
	}
}

// ConfigSchemaFor returns the welded schema (reflected structure plus
// authored docs) for one control, and whether the control has a config
// block at all.
func ConfigSchemaFor(controlName string) (ControlConfigSchema, bool) {
	s, ok := reflectControlSchemas()[controlName]
	if !ok {
		return ControlConfigSchema{}, false
	}
	s.Fields = applyDocs(controlName, s.Fields)
	return s, true
}

// ConfigSchemas returns every control's welded schema, sorted by control
// name so output is deterministic.
func ConfigSchemas() []ControlConfigSchema {
	reflected := reflectControlSchemas()
	out := make([]ControlConfigSchema, 0, len(reflected))
	for name := range reflected {
		s, _ := ConfigSchemaFor(name)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Control < out[j].Control })
	return out
}

// IsUnconfigured reports whether controlName is enabled in pc but asserts nothing because none of
// its substantive fields is set (#459): the control is RequiresConfig in the catalog, applicable
// to provider, its block is present and enabled, and every field other than `enabled` is at its
// zero value (nil pointer, empty slice or map, "", 0, false; a nested struct is zero when all of
// its fields are). The field enumeration is the SAME reflection the catalog exports
// (reflectControlSchemas), so a field the schema shows is a field this check reads. False for a
// control that is not RequiresConfig, does not apply to provider, is disabled, or has no block:
// those are "asserts something" or "skipped", never "unconfigured".
func IsUnconfigured(pc *PlumberConfig, provider, controlName string) bool {
	if pc == nil {
		return false
	}
	meta, ok := ControlMetaFor(controlName)
	if !ok || !meta.RequiresConfig || !IsControlApplicableTo(controlName, provider) {
		return false
	}
	block := controlBlock(pc, provider, controlName)
	if !block.IsValid() || block.IsNil() {
		return false
	}
	en, ok := block.Interface().(interface{ IsEnabled() bool })
	if !ok || !en.IsEnabled() {
		return false
	}
	return substantiveFieldsAreZero(block.Elem())
}

// controlBlock returns the reflect.Value of controlName's config-struct pointer field on
// provider's ControlsConfig, or an invalid Value if there is no such field or it does not have
// the shape a control block has. Walks the same yamlName-keyed fields reflectControlSchemas does,
// so the two can never disagree about which field is which control's.
func controlBlock(pc *PlumberConfig, provider, controlName string) reflect.Value {
	cc := pc.ControlsFor(provider)
	v := reflect.ValueOf(cc)
	if !v.IsValid() || v.IsNil() {
		return reflect.Value{}
	}
	return structPointerField(v.Elem(), controlName)
}

// structPointerField returns the field of struct value v whose yaml name is name, provided it is
// a POINTER TO A STRUCT, and an invalid Value otherwise. Both halves of that condition are load
// bearing: the caller dereferences the result and walks it with NumField (substantiveFieldsAreZero),
// which panics on a pointer to anything else, and calls IsNil on it, which panics on a
// non-pointer. Every control block is a pointer to a struct today, so this only ever fires on a
// future field of a different shape - which then reads as "no block", the honest answer, instead
// of taking the process down.
func structPointerField(v reflect.Value, name string) reflect.Value {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if yamlName(t.Field(i)) != name {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() != reflect.Ptr || fv.Type().Elem().Kind() != reflect.Struct {
			return reflect.Value{}
		}
		return fv
	}
	return reflect.Value{}
}

// substantiveFieldsAreZero reports whether every field of the config struct v, other than the one
// yaml-named `enabled`, is at its zero value. A field that is itself a pointer-to-struct (a nested
// config block, e.g. SecurityJobsSubControlToggle) is walked with the SAME rule rather than judged
// by pointer-nilness alone: a non-nil pointer to a struct whose own fields are all zero once ITS
// `enabled` is excluded is zero here too. That matters because a nested block that sets nothing but
// its own `enabled` toggles nothing substantive: e.g.
// securityJobsMustNotBeWeakened: {enabled: true, allowFailureMustBeFalse: {enabled: false}} sets no
// SecurityJobPatterns and turns no sub-check on, so the control is still unconfigured, matching the
// same reading `enabled: true` alone gets at the top level.
func substantiveFieldsAreZero(v reflect.Value) bool {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := yamlName(f)
		if name == "" || name == "enabled" {
			continue
		}
		fv := v.Field(i)
		switch {
		case fv.Kind() == reflect.Ptr && fv.Type().Elem().Kind() == reflect.Struct:
			if !fv.IsNil() && !substantiveFieldsAreZero(fv.Elem()) {
				return false
			}
		case fv.Kind() == reflect.Struct:
			if !substantiveFieldsAreZero(fv) {
				return false
			}
		case fv.Kind() == reflect.Slice || fv.Kind() == reflect.Map:
			// reflect.Value.IsZero() on a Slice/Map is IsNil(): yaml.v2 decodes an explicit
			// `[]` / `{}` into a non-nil, zero-length value, so IsZero() alone would read that
			// as "set". Treat zero-length the same as nil here to match the doc comment above.
			if fv.Len() != 0 {
				return false
			}
		default:
			if !fv.IsZero() {
				return false
			}
		}
	}
	return true
}
