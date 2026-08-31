package cmd

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Value provenance tiers. A value the CLI emits alongside a variable name
// must declare where it came from, so the platform can decide whether it is
// safe to store.
//
// The vocabulary is the platform's and is matched EXACTLY (case-sensitive)
// on its side, so these constants must never be re-cased or aliased.
const (
	// provenanceCIFile: the value was read out of the CI configuration
	// file, which lives in the repository. Emittable.
	provenanceCIFile = "ci_file"
	// provenanceSettingsPlain: the value came from a CI/CD variable that
	// the git host reports as neither masked nor hidden. Emittable.
	provenanceSettingsPlain = "settings_plain"
	// provenanceSettingsSecret: the value came from a masked or hidden
	// CI/CD variable. NEVER emittable - the platform rejects a push
	// carrying one, and this CLI must never produce one in the first place.
	provenanceSettingsSecret = "settings_secret"
)

// maxEmittedValueBytes matches the platform's per-value cap. A longer value
// is truncated rather than sent whole, because the platform rejects the
// WHOLE push over one oversized value.
const maxEmittedValueBytes = 1 << 10

// variableNameKeys and valueShapedKeys mirror the platform's guard exactly.
// Its rule: an object carrying a variable-name key AND a value-shaped
// sibling must also carry a recognized provenance, or the entire push is
// rejected with a 422. Keys are compared case-insensitively on both sides.
//
// Keeping these lists identical to the platform's is what makes the guard
// below a true pre-flight check rather than an approximation. A key the
// platform treats as value-shaped but this list misses would sail through
// here and be rejected there, costing the operator a whole run's results.
var variableNameKeys = map[string]bool{
	"variablename":  true,
	"variable_name": true,
}

var valueShapedKeys = map[string]bool{
	"value":          true,
	"variablevalue":  true,
	"variable_value": true,
	"resolvedvalue":  true,
	"resolved_value": true,
	"envvalue":       true,
	"env_value":      true,
}

var provenanceKeys = map[string]bool{
	"valueprovenance":  true,
	"value_provenance": true,
}

// emittableProvenance is the set the platform accepts. Anything else -
// absent, misspelled, differently cased, or settings_secret - means the
// value must not travel.
var emittableProvenance = map[string]bool{
	provenanceCIFile:        true,
	provenanceSettingsPlain: true,
}

// sanitizeProvenance walks a finding's data (or a policy's effective
// config) and makes every variable value it carries safe to push.
//
// The rule it enforces is the fail-safe one: a value whose provenance is
// unknown is treated as SENSITIVE. It is removed and replaced with derived
// attributes - length and character class - which describe the value
// without disclosing it. A value with a declared, emittable provenance is
// kept, truncated to the platform's per-value cap.
//
// This is a SAFETY NET, not the primary mechanism: rules that read a value
// from a known source declare their provenance at the point of emission,
// where the source is actually known. This guard exists so that a rule
// which forgets - or a future rule reading a genuinely secret value - can
// never cost an operator their entire push, and can never leak a secret to
// the platform.
//
// Returns the sanitized JSON and whether anything was changed.
func sanitizeProvenance(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return raw, false
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		// Not JSON we can inspect. Passing it through unchanged is the
		// honest choice: rewriting bytes we could not parse would be
		// guessing at their meaning.
		return raw, false
	}
	sanitized, changed := sanitizeNode(doc)
	if !changed {
		return raw, false
	}
	out, err := json.Marshal(sanitized)
	if err != nil {
		return raw, false
	}
	return out, true
}

// sanitizeNode recurses through objects and arrays. Strings are leaves and
// are never walked - matching the platform's own traversal, so a merged
// YAML blob carrying the word "value" can never trip the guard.
func sanitizeNode(node any) (any, bool) {
	switch n := node.(type) {
	case map[string]any:
		return sanitizeObject(n)
	case []any:
		changed := false
		for i, item := range n {
			next, c := sanitizeNode(item)
			if c {
				n[i] = next
				changed = true
			}
		}
		return n, changed
	default:
		return node, false
	}
}

// sanitizeObject applies the guard to one object, then recurses into its
// children. The guard is SAME-OBJECT only: a variable name and a value in
// sibling keys is the shape that carries a value; the same keys at
// different depths are not.
func sanitizeObject(obj map[string]any) (any, bool) {
	changed := false

	nameKey, valueKeys, provKey := classifyKeys(obj)
	if nameKey != "" {
		// EVERY value-shaped key, not just the first. An object carrying
		// two of them ({variableName, envValue, value}) used to have only
		// one redacted, so the other reached the wire verbatim AND still
		// paired with the name — which is also exactly the shape the
		// platform 422s on, so the leak and the rejection arrived together.
		for _, valueKey := range valueKeys {
			if sanitizeValueSite(obj, valueKey, provKey) {
				changed = true
			}
		}
	}

	for k, v := range obj {
		next, c := sanitizeNode(v)
		if c {
			obj[k] = next
			changed = true
		}
	}
	return obj, changed
}

// classifyKeys finds this object's variable-name key, ALL of its
// value-shaped keys, and its provenance key, comparing key names
// case-insensitively as the platform does.
//
// valueKeys is a slice rather than a single key because an object may carry
// several ({variableName, envValue, value}) and every one of them holds a
// value. Keys are examined in sorted order so the result is stable across
// runs regardless of map iteration.
func classifyKeys(obj map[string]any) (nameKey string, valueKeys []string, provKey string) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		folded := strings.ToLower(k)
		switch {
		case variableNameKeys[folded]:
			if nameKey == "" {
				nameKey = k
			}
		case valueShapedKeys[folded]:
			valueKeys = append(valueKeys, k)
		case provenanceKeys[folded]:
			if provKey == "" {
				provKey = k
			}
		}
	}
	return nameKey, valueKeys, provKey
}

// sanitizeValueSite decides one variable-value site: keep the value
// (truncated to the cap) when its provenance is declared and emittable, or
// replace it with derived attributes when it is not.
func sanitizeValueSite(obj map[string]any, valueKey, provKey string) bool {
	prov, _ := obj[provKey].(string)
	if provKey != "" && emittableProvenance[prov] {
		return truncateValue(obj, valueKey)
	}

	// Unknown, absent, or explicitly secret provenance: the value does not
	// travel. Deleting the value-shaped key entirely is what keeps the
	// platform's guard from tripping at all - it only fires on a
	// name+value pair.
	original := obj[valueKey]
	delete(obj, valueKey)
	obj["valueRedacted"] = true
	obj["valueRedactedReason"] = redactionReason(prov, provKey)
	for k, v := range derivedAttributes(original) {
		obj[k] = v
	}
	return true
}

// redactionReason states why a value was withheld, so an operator reading
// the platform's record knows whether they are looking at a genuine secret
// or a rule that failed to declare itself.
func redactionReason(prov, provKey string) string {
	switch {
	case provKey == "":
		return "no valueProvenance declared; treated as sensitive"
	case prov == provenanceSettingsSecret:
		return "value comes from a masked or hidden CI/CD variable"
	default:
		return "unrecognized valueProvenance " + strconv.Quote(prov) + "; treated as sensitive"
	}
}

// truncateValue caps an emittable string value at the platform's per-value
// limit. Over the cap the platform rejects the whole push, so truncating
// here trades one value's tail for the entire run's results.
func truncateValue(obj map[string]any, valueKey string) bool {
	s, ok := obj[valueKey].(string)
	if !ok || len(s) <= maxEmittedValueBytes {
		return false
	}
	// Cut on a rune boundary. Slicing raw bytes can split a multi-byte rune,
	// and json.Marshal then replaces each orphan byte with U+FFFD (3 bytes
	// each) — a 1200-byte value of "€" came back at 1028 bytes, OVER the cap
	// this truncation exists to respect, causing the very 422 it prevents.
	budget := maxEmittedValueBytes - len(truncationMarker)
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	obj[valueKey] = s[:cut] + truncationMarker
	obj["valueTruncated"] = true
	return true
}

const truncationMarker = "...[truncated]"

// derivedAttributes describes a withheld value without disclosing it:
// enough for an operator to recognize a change or spot an obviously wrong
// setting, never enough to reconstruct a secret.
func derivedAttributes(v any) map[string]any {
	s, ok := v.(string)
	if !ok {
		// A non-string value (a number, a bool, an object) is not a
		// credential shape. Report only that it was present and what kind.
		return map[string]any{"valueKind": kindOf(v)}
	}
	return map[string]any{
		"valueKind":       "string",
		"valueLength":     len(s),
		"valueCharClass":  charClass(s),
		"valueIsTruthy":   isTruthyLiteral(s),
		"valueIsEmptyStr": s == "",
	}
}

func kindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

// charClass summarizes which character families a value draws on, in a
// fixed order so two runs over the same value always produce the same
// string. It distinguishes "looks like a flag" from "looks like a token"
// without revealing either.
func charClass(s string) string {
	var hasLower, hasUpper, hasDigit, hasSpace, hasOther bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsSpace(r):
			hasSpace = true
		default:
			hasOther = true
		}
	}
	var parts []string
	for _, c := range []struct {
		on   bool
		name string
	}{
		{hasLower, "lower"}, {hasUpper, "upper"}, {hasDigit, "digit"},
		{hasSpace, "space"}, {hasOther, "symbol"},
	} {
		if c.on {
			parts = append(parts, c.name)
		}
	}
	if len(parts) == 0 {
		return "empty"
	}
	return strings.Join(parts, "+")
}

// isTruthyLiteral reports whether a withheld value is one of the truthy
// spellings the debug-trace control matches on. It is the one semantic fact
// worth preserving about a redacted value: it says WHY the control fired
// without saying what the value was.
func isTruthyLiteral(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}
