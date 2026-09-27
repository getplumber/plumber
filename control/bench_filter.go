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

// emittedCodeRegex matches the codes a policy EMITS, the `"code": "ISSUE-N"`
// literal of a finding map, and nothing else. issueCodeRegex is deliberately
// looser (any ISSUE-N in the file, comments included), which is safe when the
// only consequence is loading a file, and wrong here: a policy's header
// comment routinely cites other controls' codes to explain its threat model,
// and a failure must not mark those controls not evaluable.
var emittedCodeRegex = regexp.MustCompile(`"code"\s*:\s*"(ISSUE-\d+)"`)

// controlsDeclaredBy returns the distinct control names behind the ISSUE-XXX
// codes a policy source emits, in first-seen order. A failed policy's
// controls are marked not evaluable through it (#489).
func controlsDeclaredBy(content []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range emittedCodeRegex.FindAllSubmatch(content, -1) {
		info := LookupCode(ErrorCode(m[1]))
		if info == nil || info.ControlName == "" || seen[info.ControlName] {
			continue
		}
		seen[info.ControlName] = true
		out = append(out, info.ControlName)
	}
	return out
}
