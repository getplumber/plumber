package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// decode is a helper: sanitize raw JSON and hand back the result as a map.
func decode(t *testing.T, in string) (map[string]any, bool) {
	t.Helper()
	out, changed := sanitizeProvenance(json.RawMessage(in))
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("sanitized output is not an object: %v\n%s", err, out)
	}
	return m, changed
}

// TestSanitize_DeclaredCIFileValueSurvives is the whole point of stamping
// provenance in the rules: a value the rule KNOWS came from the CI file,
// which lives in the repository, is safe to report and must reach the
// platform intact.
func TestSanitize_DeclaredCIFileValueSurvives(t *testing.T) {
	m, changed := decode(t, `{"code":"ISSUE-203","variableName":"CI_DEBUG_TRACE","value":"true","valueProvenance":"ci_file"}`)
	if changed {
		t.Fatal("a properly declared value must pass through untouched")
	}
	if m["value"] != "true" {
		t.Fatalf("value: %v", m["value"])
	}
	if _, redacted := m["valueRedacted"]; redacted {
		t.Fatal("a declared ci_file value must not be redacted")
	}
}

func TestSanitize_DeclaredSettingsPlainValueSurvives(t *testing.T) {
	m, changed := decode(t, `{"variableName":"LOG_LEVEL","value":"debug","valueProvenance":"settings_plain"}`)
	if changed || m["value"] != "debug" {
		t.Fatalf("settings_plain is an emittable tier: changed=%v value=%v", changed, m["value"])
	}
}

// TestSanitize_UndeclaredValueIsWithheld is the fail-safe rule: a value
// whose origin the CLI cannot vouch for is treated as sensitive. This is
// also what keeps the platform's 422 from ever firing, since the guard
// there only trips on a name+value pair.
func TestSanitize_UndeclaredValueIsWithheld(t *testing.T) {
	m, changed := decode(t, `{"code":"ISSUE-203","variableName":"SECRET_TOKEN","value":"glpat-supersecret123"}`)
	if !changed {
		t.Fatal("an undeclared value must be sanitized")
	}
	if _, present := m["value"]; present {
		t.Fatalf("the value key must be REMOVED, not rewritten: %v", m)
	}
	if m["valueRedacted"] != true {
		t.Fatalf("redaction must be stated: %v", m)
	}
	if !strings.Contains(m["valueRedactedReason"].(string), "no valueProvenance") {
		t.Fatalf("reason: %v", m["valueRedactedReason"])
	}
	// The variable NAME is not a secret and stays, so the finding is still
	// actionable.
	if m["variableName"] != "SECRET_TOKEN" {
		t.Fatalf("the variable name must survive: %v", m)
	}
	// Derived attributes describe the value without disclosing it.
	if m["valueLength"] != float64(len("glpat-supersecret123")) {
		t.Fatalf("valueLength: %v", m["valueLength"])
	}
	if m["valueCharClass"] != "lower+digit+symbol" {
		t.Fatalf("valueCharClass: %v", m["valueCharClass"])
	}
	for _, k := range []string{"valueRedacted", "valueLength", "valueCharClass"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing derived attribute %q", k)
		}
	}
	// And nothing that could reconstruct the value.
	blob, _ := json.Marshal(m)
	if strings.Contains(string(blob), "supersecret") {
		t.Fatalf("the withheld value leaked into the output: %s", blob)
	}
}

// TestSanitize_SettingsSecretIsWithheld: a value the CLI KNOWS is masked or
// hidden must never travel, and the reason must say so plainly.
func TestSanitize_SettingsSecretIsWithheld(t *testing.T) {
	m, changed := decode(t, `{"variableName":"DEPLOY_KEY","value":"AKIAIOSFODNN7EXAMPLE","valueProvenance":"settings_secret"}`)
	if !changed {
		t.Fatal("a settings_secret value must be sanitized")
	}
	if _, present := m["value"]; present {
		t.Fatal("a secret value must never be emitted")
	}
	if !strings.Contains(m["valueRedactedReason"].(string), "masked or hidden") {
		t.Fatalf("reason: %v", m["valueRedactedReason"])
	}
}

// TestSanitize_ProvenanceValueIsMatchedExactly mirrors the platform, which
// compares the provenance VALUE case-sensitively. A near-miss spelling is
// not a declaration, and treating it as one would send a value the platform
// then rejects.
func TestSanitize_ProvenanceValueIsMatchedExactly(t *testing.T) {
	for _, prov := range []string{"CI_FILE", "Ci_File", "cifile", "ci-file", "settings_Plain", "", "unknown_tier"} {
		t.Run(prov, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"variableName": "V", "value": "secret", "valueProvenance": prov})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			m, changed := decode(t, string(body))
			if !changed {
				t.Fatalf("provenance %q is not an exact match and must not be honoured", prov)
			}
			if _, present := m["value"]; present {
				t.Fatalf("value survived an inexact provenance %q", prov)
			}
		})
	}
}

// TestSanitize_ProvenanceKeyIsMatchedCaseInsensitively mirrors the other
// half of the platform's rule: the KEY is folded, only the value is exact.
func TestSanitize_ProvenanceKeyIsMatchedCaseInsensitively(t *testing.T) {
	for _, key := range []string{"valueProvenance", "valueprovenance", "VALUEPROVENANCE", "value_provenance", "Value_Provenance"} {
		t.Run(key, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"variableName": "V", "value": "keepme", key: "ci_file"})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			m, changed := decode(t, string(body))
			if changed {
				t.Fatalf("key spelling %q must be recognized", key)
			}
			if m["value"] != "keepme" {
				t.Fatalf("value withheld despite a valid declaration under %q", key)
			}
		})
	}
}

// TestSanitize_EveryValueShapedKeyIsGuarded pins parity with the platform's
// frozen deny-list. A key it treats as value-shaped but this guard misses
// would sail through here and 422 there, costing a whole run's results.
func TestSanitize_EveryValueShapedKeyIsGuarded(t *testing.T) {
	for key := range valueShapedKeys {
		t.Run(key, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"variable_name": "V", key: "secret"})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			m, changed := decode(t, string(body))
			if !changed {
				t.Fatalf("value-shaped key %q must be guarded", key)
			}
			if _, present := m[key]; present {
				t.Fatalf("value-shaped key %q survived undeclared", key)
			}
		})
	}
}

// TestSanitize_NameWithoutValueIsUntouched: the guard fires on a PAIR. A
// finding naming a variable but carrying no value is already safe, and
// rewriting it would add noise for nothing.
func TestSanitize_NameWithoutValueIsUntouched(t *testing.T) {
	m, changed := decode(t, `{"code":"ISSUE-209","variableName":"GITHUB_ENV","job":"build"}`)
	if changed {
		t.Fatal("a variable name with no value must pass through untouched")
	}
	if m["variableName"] != "GITHUB_ENV" {
		t.Fatalf("%v", m)
	}
}

// TestSanitize_ValueWithoutNameIsUntouched: the platform's guard requires
// both. A lone "value" key (a config knob, say) is not a variable value.
func TestSanitize_ValueWithoutNameIsUntouched(t *testing.T) {
	m, changed := decode(t, `{"code":"ISSUE-101","value":"docker.io/alpine:latest"}`)
	if changed {
		t.Fatal("a value with no variable name beside it must pass through")
	}
	if m["value"] != "docker.io/alpine:latest" {
		t.Fatalf("%v", m)
	}
}

// TestSanitize_GuardIsSameObjectOnly: a name and a value at different
// depths are not a pair, exactly as the platform reads it.
func TestSanitize_GuardIsSameObjectOnly(t *testing.T) {
	m, changed := decode(t, `{"variableName":"V","nested":{"value":"not-a-pair"}}`)
	if changed {
		t.Fatal("keys at different depths are not a same-object pair")
	}
	nested := m["nested"].(map[string]any)
	if nested["value"] != "not-a-pair" {
		t.Fatalf("%v", m)
	}
}

// TestSanitize_StringsAreLeaves: a merged YAML blob mentioning "value" and
// "variableName" as TEXT must never trip the guard. The platform does not
// walk into strings either.
func TestSanitize_StringsAreLeaves(t *testing.T) {
	yaml := "variables:\n  variableName: value\n  value: variableName\n"
	body, err := json.Marshal(map[string]any{"code": "ISSUE-401", "mergedYaml": yaml})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m, changed := decode(t, string(body))
	if changed {
		t.Fatal("text inside a string is not a key")
	}
	if m["mergedYaml"] != yaml {
		t.Fatal("the merged yaml must survive byte-identical")
	}
}

// TestSanitize_RecursesIntoNestedObjectsAndArrays: a value site anywhere in
// the document is guarded, because the platform walks the whole blob.
func TestSanitize_RecursesIntoNestedObjectsAndArrays(t *testing.T) {
	m, changed := decode(t, `{"findings":[{"variableName":"A","value":"leak-a"},{"variableName":"B","value":"keep-b","valueProvenance":"ci_file"}],"deep":{"inner":{"variableName":"C","value":"leak-c"}}}`)
	if !changed {
		t.Fatal("nested value sites must be guarded")
	}
	blob, _ := json.Marshal(m)
	s := string(blob)
	if strings.Contains(s, "leak-a") || strings.Contains(s, "leak-c") {
		t.Fatalf("an undeclared nested value leaked: %s", s)
	}
	if !strings.Contains(s, "keep-b") {
		t.Fatalf("a declared nested value was wrongly withheld: %s", s)
	}
}

// TestSanitize_OversizedDeclaredValueIsTruncated: the platform rejects the
// whole push over one oversized value, so trading a value's tail for the
// run's results is the right call.
func TestSanitize_OversizedDeclaredValueIsTruncated(t *testing.T) {
	long := strings.Repeat("x", maxEmittedValueBytes+500)
	body, err := json.Marshal(map[string]any{"variableName": "BIG", "value": long, "valueProvenance": "ci_file"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m, changed := decode(t, string(body))
	if !changed {
		t.Fatal("an oversized value must be truncated")
	}
	got := m["value"].(string)
	if len(got) > maxEmittedValueBytes {
		t.Fatalf("truncated value is still %d bytes, cap is %d", len(got), maxEmittedValueBytes)
	}
	if !strings.HasSuffix(got, truncationMarker) {
		t.Fatalf("truncation must be visible in the value: %q", got[len(got)-30:])
	}
	if m["valueTruncated"] != true {
		t.Fatal("truncation must be flagged")
	}
}

// TestSanitize_AtCapIsNotTruncated pins the boundary: exactly at the cap is
// accepted by the platform, so truncating it would lose data for nothing.
func TestSanitize_AtCapIsNotTruncated(t *testing.T) {
	exact := strings.Repeat("y", maxEmittedValueBytes)
	body, err := json.Marshal(map[string]any{"variableName": "BIG", "value": exact, "valueProvenance": "ci_file"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m, changed := decode(t, string(body))
	if changed {
		t.Fatal("a value exactly at the cap is within the limit")
	}
	if m["value"].(string) != exact {
		t.Fatal("an at-cap value must survive intact")
	}
}

// TestSanitize_NonStringUndeclaredValue: a number or object in a value slot
// is not a credential shape, but it still must not travel undeclared - the
// platform's guard does not care about the JSON type.
func TestSanitize_NonStringUndeclaredValue(t *testing.T) {
	m, changed := decode(t, `{"variableName":"COUNT","value":42}`)
	if !changed {
		t.Fatal("a non-string undeclared value must still be withheld")
	}
	if _, present := m["value"]; present {
		t.Fatal("value survived")
	}
	if m["valueKind"] != "number" {
		t.Fatalf("valueKind: %v", m["valueKind"])
	}
}

// TestSanitize_TruthinessIsPreservedForRedactedValues: for a debug-trace
// finding, "the value was truthy" is WHY the control fired. Keeping that
// one bit makes a redacted finding still explicable.
func TestSanitize_TruthinessIsPreservedForRedactedValues(t *testing.T) {
	m, _ := decode(t, `{"variableName":"CI_DEBUG_TRACE","value":"TRUE"}`)
	if m["valueIsTruthy"] != true {
		t.Fatalf("a redacted truthy value must still report its truthiness: %v", m)
	}
	m, _ = decode(t, `{"variableName":"CI_DEBUG_TRACE","value":"maybe"}`)
	if m["valueIsTruthy"] != false {
		t.Fatalf("%v", m)
	}
}

func TestSanitize_MalformedOrEmptyInputPassesThrough(t *testing.T) {
	for _, in := range []string{"", "not json", "[1,2,3", `"a bare string"`, "null"} {
		out, changed := sanitizeProvenance(json.RawMessage(in))
		if changed {
			t.Fatalf("input %q must pass through unchanged", in)
		}
		if string(out) != in {
			t.Fatalf("input %q rewritten to %q", in, out)
		}
	}
}

func TestCharClass(t *testing.T) {
	cases := map[string]string{
		"":            "empty",
		"abc":         "lower",
		"ABC":         "upper",
		"123":         "digit",
		"aB3":         "lower+upper+digit",
		"a b":         "lower+space",
		"a-b":         "lower+symbol",
		"glpat-xyz12": "lower+digit+symbol",
	}
	for in, want := range cases {
		if got := charClass(in); got != want {
			t.Fatalf("charClass(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSanitize_RealFindingShapeFromDebugTrace runs the guard over the exact
// shape debug_trace.rego now emits, proving the stamped rule and the guard
// agree and that the result is what the platform accepts.
func TestSanitize_RealFindingShapeFromDebugTrace(t *testing.T) {
	const raw = `{"code":"ISSUE-203","severity":"critical","message":"CI_DEBUG_TRACE = \"true\" (job \"build\")","job":"build","variableName":"CI_DEBUG_TRACE","value":"true","valueProvenance":"ci_file","location":"build"}`
	m, changed := decode(t, raw)
	if changed {
		t.Fatalf("the shape the rule emits must already be push-safe, got %v", m)
	}
	if m["value"] != "true" || m["valueProvenance"] != "ci_file" {
		t.Fatalf("%v", m)
	}
}

// TestSanitize_EveryValueShapedKeyInOneObjectIsWithheld pins a real leak:
// only the FIRST value-shaped key used to be redacted, so an object carrying
// two of them sent the second verbatim — and still paired with the variable
// name, which is also the exact shape the platform 422s on. The leak and the
// rejection arrived together.
func TestSanitize_EveryValueShapedKeyInOneObjectIsWithheld(t *testing.T) {
	m, changed := decode(t, `{"variableName":"AWS_SECRET_ACCESS_KEY","envValue":"aaa-secret-A","value":"bbb-secret-B"}`)
	if !changed {
		t.Fatal("undeclared values must be sanitized")
	}
	blob, _ := json.Marshal(m)
	for _, secret := range []string{"aaa-secret-A", "bbb-secret-B"} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("%s survived sanitization:\n%s", secret, blob)
		}
	}
	for _, k := range []string{"value", "envValue"} {
		if _, present := m[k]; present {
			t.Fatalf("value-shaped key %q must be removed, not just one of them", k)
		}
	}
}

// TestSanitize_TruncationRespectsTheByteCap: slicing raw bytes could split a
// multi-byte rune, and json.Marshal then replaces each orphan byte with
// U+FFFD (3 bytes each) — pushing the value BACK over the cap and causing the
// 422 the truncation exists to avoid.
func TestSanitize_TruncationRespectsTheByteCap(t *testing.T) {
	for _, tc := range []struct{ name, fill string }{
		{"ascii", "x"},
		{"multi-byte", "€"},
		{"4-byte", "𝄞"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			long := strings.Repeat(tc.fill, maxEmittedValueBytes)
			body, err := json.Marshal(map[string]any{"variableName": "BIG", "value": long, "valueProvenance": "ci_file"})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			m, _ := decode(t, string(body))
			got, _ := m["value"].(string)
			if len(got) > maxEmittedValueBytes {
				t.Fatalf("truncated value is %d bytes, over the %d cap", len(got), maxEmittedValueBytes)
			}
			if strings.ContainsRune(got, '�') {
				t.Fatalf("truncation cut mid-rune: replacement character present")
			}
		})
	}
}
