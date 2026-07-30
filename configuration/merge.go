// configuration/merge.go
package configuration

// deepMergeYAML returns a new map with overlay applied onto base.
// Nested maps merge recursively; scalars and lists in overlay replace
// the base value wholesale. base is never mutated.
//
// A nil overlay value (an overlay key whose body is empty, e.g. every
// line under it commented out) is treated as "no override": the
// inherited base value for that key is kept as-is rather than being
// replaced with nil. This matters for the "extends + list only what you
// change" workflow, where commenting out everything under a section
// must not silently delete the whole inherited subtree.
func deepMergeYAML(base, overlay map[interface{}]interface{}) map[interface{}]interface{} {
	out := make(map[interface{}]interface{}, len(base))
	for k, v := range base {
		out[k] = v
	}
	for k, ov := range overlay {
		if ov == nil {
			// Nil overlay value: inherit the base value unchanged (or
			// add nothing when the key doesn't exist in base either).
			continue
		}
		bv, exists := out[k]
		if exists {
			bm, bok := bv.(map[interface{}]interface{})
			om, ook := ov.(map[interface{}]interface{})
			if bok && ook {
				out[k] = deepMergeYAML(bm, om)
				continue
			}
		}
		out[k] = ov
	}
	return out
}
