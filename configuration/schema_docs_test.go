package configuration

import (
	"strings"
	"testing"
)

// collectPaths returns every dotted field path of a schema
// ("control.field" and "control.parent.child" for nested objects).
func collectPaths(prefix string, fields []SchemaField, out map[string]bool) {
	for _, f := range fields {
		p := prefix + "." + f.Name
		out[p] = true
		if len(f.Fields) > 0 {
			collectPaths(p, f.Fields, out)
		}
		if f.Elem != nil && len(f.Elem.Fields) > 0 {
			collectPaths(p+"[]", f.Elem.Fields, out)
		}
	}
}

// The reflected structure and the authored prose are welded together: a
// struct field without a doc entry fails here, and a doc entry matching no
// struct field fails here, so the exported schema can never drift from the
// code in either direction (#458, same pattern as the identity parity test).
func TestFieldDocsParity(t *testing.T) {
	reflected := map[string]bool{}
	for name, s := range reflectControlSchemas() {
		collectPaths(name, s.Fields, reflected)
	}
	for path := range reflected {
		doc, ok := controlFieldDocs[path]
		if !ok {
			t.Errorf("field %s has no entry in controlFieldDocs; describe it in schema_docs.go", path)
			continue
		}
		if strings.TrimSpace(doc.Description) == "" {
			t.Errorf("field %s has an empty Description", path)
		}
	}
	for path := range controlFieldDocs {
		if !reflected[path] {
			t.Errorf("controlFieldDocs entry %s matches no reflected field; remove the stale entry", path)
		}
	}
}

// The public accessors serve the welded schema: structure from reflection,
// prose and constraints from the table.
func TestConfigSchemaAccessors(t *testing.T) {
	s, ok := ConfigSchemaFor("cicdVariablesMustBeProtected")
	if !ok {
		t.Fatal("known control has no schema")
	}
	if len(s.Fields) == 0 || s.Fields[0].Description == "" {
		t.Errorf("schema fields not welded with docs: %+v", s.Fields)
	}
	if _, ok := ConfigSchemaFor("noSuchControl"); ok {
		t.Error("unknown control must return ok=false")
	}
	all := ConfigSchemas()
	if len(all) == 0 {
		t.Fatal("ConfigSchemas returned nothing")
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Control >= all[i].Control {
			t.Errorf("ConfigSchemas not sorted: %q before %q", all[i-1].Control, all[i].Control)
		}
	}
}
