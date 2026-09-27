package gitlab

import (
	"encoding/json"
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"
)

// TestNormalizeYAMLValue pins the one shared normalizer every yaml.v2 value
// goes through before reaching a JSON encoder or the Rego engine: every
// nesting level of interface-keyed maps becomes string-keyed, a non-string
// key is rendered with fmt.Sprint rather than dropped, slices are walked,
// scalars pass through, and the result marshals to JSON.
func TestNormalizeYAMLValue(t *testing.T) {
	var parsed interface{}
	if err := yaml.Unmarshal([]byte(`
on: pushed
1: one
rules:
  - if: $CI_COMMIT_BRANCH
    when: always
  - when: manual
nested:
  deep:
    key: value
count: 3
`), &parsed); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if _, isInterfaceMap := parsed.(map[interface{}]interface{}); !isInterfaceMap {
		t.Fatalf("yaml.v2 decodes a mapping to map[interface{}]interface{}, got %T", parsed)
	}

	got := NormalizeYAMLValue(parsed)
	want := map[string]any{
		"true": "pushed", // yaml.v2 reads a bare `on` key as the boolean true
		"1":    "one",
		"rules": []any{
			map[string]any{"if": "$CI_COMMIT_BRANCH", "when": "always"},
			map[string]any{"when": "manual"},
		},
		"nested": map[string]any{"deep": map[string]any{"key": "value"}},
		"count":  3,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeYAMLValue mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("normalized value must marshal to JSON: %v", err)
	}
}

// TestNormalizeYAMLValue_LeavesStringKeyedInputAlone covers the shapes that
// arrive already normalized (a map[string]interface{} from JSON, a scalar):
// they come back equal, with nested interface-keyed maps still converted.
func TestNormalizeYAMLValue_LeavesStringKeyedInputAlone(t *testing.T) {
	in := map[string]interface{}{
		"a": map[interface{}]interface{}{"b": []interface{}{1, "x"}},
	}
	want := map[string]any{"a": map[string]any{"b": []any{1, "x"}}}
	if got := NormalizeYAMLValue(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for _, scalar := range []any{"s", 42, true, nil} {
		if got := NormalizeYAMLValue(scalar); got != scalar {
			t.Errorf("scalar %v must pass through, got %v", scalar, got)
		}
	}
}
