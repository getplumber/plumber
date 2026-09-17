package ir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

type overrideEntry struct {
	Name    string         `json:"name"`
	Content map[string]any `json:"content"`
}

// OverrideFingerprint is the canonical digest of an include's override content:
// the overridden jobs sorted by name, each carrying the WHOLE local job block as the
// user's own configuration declares it. encoding/json sorts map keys, so the bytes are
// stable across runs and machines; the digest is the first 16 hex characters of SHA-256,
// the width every other CLI fingerprint uses. Empty when nothing is overridden.
//
// Canonical form: the jobs sorted by name, each marshalled as
// {"name": <name>, "content": <the local job block>} with every map's keys sorted, the
// whole array marshalled as JSON with no indentation, sha256 of those bytes, first 16 hex
// characters.
//
// The digest covers the block as a whole rather than a projection of the keys the
// override regex matched: ANY change to the overriding job moves it, nested or not,
// forbidden keyword or not (a keyword that only ever appears under another key, an
// unmatched key, a value several levels down). A projection of the matched keys would
// hash a null for a keyword the job never declares at its top level and let its content
// change unnoticed. The order in which the collector discovered the jobs does not move
// the digest.
func OverrideFingerprint(jobs []OverriddenJob) string {
	if len(jobs) == 0 {
		return ""
	}
	entries := make([]overrideEntry, 0, len(jobs))
	for _, j := range jobs {
		entries = append(entries, overrideEntry{Name: j.Name, Content: j.Values})
	}
	sort.Slice(entries, func(i, k int) bool { return entries[i].Name < entries[k].Name })
	raw, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}
