package control

import (
	"regexp"

	"github.com/getplumber/plumber/configuration"
)

// issueCodeRegex matches the ISSUE-XXX literals that policies emit
// in their finding maps (e.g. `"code": "ISSUE-410"`). The regex is
// deliberately loose — it picks up any ISSUE-N reference in the
// file, which is exactly what we want: if a file references at least
// one non-benched control's issue code, the file must load so that
// control's findings survive.
var issueCodeRegex = regexp.MustCompile(`ISSUE-\d+`)

// IsRegoFileBenchedForProvider returns true when every ISSUE-XXX
// referenced in content maps to a control name that is currently
// benched for the given provider (see configuration.IsBenched). When
// true, the engine should skip loading the file entirely — the
// policy never executes, no cycles wasted.
//
// Returns false (i.e. "load this file") in any of:
//   - the file references no ISSUE codes (helper modules, placeholders);
//   - the file references at least one code mapping to a control
//     that is NOT benched for this provider;
//   - any ISSUE code is unknown to errorCodeRegistry (defensive: an
//     unknown code is treated as not-bench so the rule still runs and
//     surfaces — better noisy than silently dropped).
//
// The decision is made entirely from existing data: errorCodeRegistry
// (issue code → control name) and configuration.benchedControls
// ({provider, control} → benched). No separate file→package mapping
// lives anywhere; the rego file's own issue-code references are the
// link.
func IsRegoFileBenchedForProvider(content []byte, provider string) bool {
	matches := issueCodeRegex.FindAll(content, -1)
	if len(matches) == 0 {
		return false
	}
	seen := map[string]struct{}{}
	for _, m := range matches {
		seen[string(m)] = struct{}{}
	}
	for code := range seen {
		info := LookupCode(ErrorCode(code))
		if info == nil || info.ControlName == "" {
			return false
		}
		if !configuration.IsBenched(provider, info.ControlName) {
			return false
		}
	}
	return true
}
