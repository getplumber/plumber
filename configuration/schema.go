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
