package ir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

type overrideEntry struct {
	Name string         `json:"name"`
	Keys map[string]any `json:"keys"`
}

// OverrideFingerprint is the canonical digest of an include's override content:
// the overridden jobs sorted by name, each with its overridden keys and their values as
// the user's own job block declares them. encoding/json sorts map keys, so the bytes are
// stable across runs and machines; the digest is the first 16 hex characters of SHA-256,
// the width every other CLI fingerprint uses. Empty when nothing is overridden.
//
// Canonical form: the jobs sorted by name, each marshalled as
// {"name": <name>, "keys": {<key>: <value>, ...}} with the keys sorted, the whole array
// marshalled as JSON with no indentation, sha256 of those bytes, first 16 hex characters.
// A value change, a key change or a job change moves the fingerprint; the order in which
// the collector discovered the jobs does not.
func OverrideFingerprint(jobs []OverriddenJob) string {
	if len(jobs) == 0 {
		return ""
	}
	entries := make([]overrideEntry, 0, len(jobs))
	for _, j := range jobs {
		keys := make(map[string]any, len(j.Keys))
		for _, k := range j.Keys {
			keys[k] = j.Values[k]
		}
		entries = append(entries, overrideEntry{Name: j.Name, Keys: keys})
	}
	sort.Slice(entries, func(i, k int) bool { return entries[i].Name < entries[k].Name })
	raw, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}
