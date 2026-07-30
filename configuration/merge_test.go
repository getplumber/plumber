// configuration/merge_test.go
package configuration

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"
)

func mustMap(t *testing.T, s string) map[interface{}]interface{} {
	t.Helper()
	var m map[interface{}]interface{}
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func TestDeepMergeYAML(t *testing.T) {
	base := mustMap(t, `
a: 1
b:
  c: 2
  d: 3
list:
  - x
  - y
`)
	overlay := mustMap(t, `
b:
  d: 99
list:
  - z
new: true
`)
	got := deepMergeYAML(base, overlay)

	want := mustMap(t, `
a: 1
b:
  c: 2
  d: 99
list:
  - z
new: true
`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merge mismatch\n got: %#v\nwant: %#v", got, want)
	}

	// base must be untouched
	if base["b"].(map[interface{}]interface{})["d"] != 3 {
		t.Fatal("base was mutated")
	}
}

// TestDeepMergeYAML_NilOverlayValueInheritsBase is the regression guard for
// the "null overlay wipes inherited base subtree" bug: an overlay key with
// an empty body (e.g. everything under it commented out) parses as nil.
// That must be treated as "no override" -- the base subtree survives --
// rather than replacing the base value with nil. A real override on a
// sibling key must still apply.
func TestDeepMergeYAML_NilOverlayValueInheritsBase(t *testing.T) {
	base := mustMap(t, `
b:
  c: 2
  d: 3
e: 5
`)
	overlay := mustMap(t, `
b:
e: 99
`)
	// Sanity check on the test's own premise: "b:" with nothing under it
	// really does parse as a nil value in the overlay map.
	if v, ok := overlay["b"]; !ok || v != nil {
		t.Fatalf("test premise broken: overlay[\"b\"] = %#v, want nil", v)
	}

	got := deepMergeYAML(base, overlay)

	want := mustMap(t, `
b:
  c: 2
  d: 3
e: 99
`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nil overlay value must inherit base subtree, not wipe it\n got: %#v\nwant: %#v", got, want)
	}
}
