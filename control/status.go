package control

import (
	"sort"
	"strings"
)

// Per-control evaluation statuses. `passed` and `failed` mean the control
// genuinely evaluated (real data, real check); `skipped` means it never ran
// (disabled in .plumber.yaml or excluded via --controls/--skip-controls);
// `error` means it could not be trusted to have fully evaluated — an empty
// findings list in that state is "could not tell", not "compliant".
const (
	StatusPassed  = "passed"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
	StatusError   = "error"
)

// degradedReasonIsBranchProtection classifies a DegradedReasons entry as
// the branch-protection fetch failure. Both providers build their reason
// string from degradedReasonBranchProtectionPrefix (degraded.go /
// task.go), so the prefix is the stable classifier.
func degradedReasonIsBranchProtection(reason string) bool {
	return strings.HasPrefix(reason, degradedReasonBranchProtectionPrefix)
}

// StatusFor derives a control's evaluation status for a run.
//
// Order matters: findings trump degradation — when a control found real
// violations, `failed` is accurate and actionable regardless of whether
// the run was complete. The `error` state only guards the opposite case:
// an EMPTY findings list that cannot be trusted, because the control had
// nothing real to evaluate (missing/invalid CI config) or its data
// collection failed mid-run. Presenting that as `passed` is the silent
// false-green this field exists to eliminate (#220, and the "how do I
// tell passed from not-evaluated" integration feedback on #353).
//
// branchMustBeProtected is the one repo-level control: it evaluates
// against the provider's protection API, not the CI configuration, so
// CiMissing/CiValid do not apply to it — only its own collection
// signals do (a failed protection fetch, or protection details a token
// scope could not read). Every other control reads the CI configuration
// and inherits the CI-level signals.
//
// Run-wide Warnings ("could not verify" messages, e.g. a skipped
// known-CVE lookup) deliberately do NOT flip a control to error in this
// version: they are surfaced separately in every output and gated by
// --fail-warnings. Folding them in per-control would require parsing
// which control each warning string belongs to.
func StatusFor(e ControlEntry, result *AnalysisResult, findingCount int) string {
	if e.Skipped {
		return StatusSkipped
	}
	if findingCount > 0 {
		return StatusFailed
	}
	if result == nil {
		return StatusPassed
	}
	if e.ControlName == "branchMustBeProtected" {
		for _, r := range result.DegradedReasons {
			if degradedReasonIsBranchProtection(r) {
				return StatusError
			}
		}
		if result.GitHubStats != nil {
			// GitHub run (GitHubStats is always set on that path). The
			// protection enrichment runs independently of workflows, and
			// any fetch error surfaces as a degraded reason (caught
			// above); the remaining partial mode is a token whose scope
			// could read the branch list but not the protection details.
			if result.GitHubStats.BranchesProtectionDetailsUnknown > 0 {
				return StatusError
			}
			return StatusPassed
		}
		// GitLab run: ProtectionData is only set after the protection
		// collection actually ran and succeeded (task.go). It stays nil
		// on every early-return path (limited analysis, collection
		// network failures) and on ANY protection-fetch error —
		// including non-network ones (401/403), which leave no degraded
		// reason at all. A nil here means the control never truly
		// evaluated: zero branches, rego abstained, and an empty
		// findings list that must not read as a pass.
		if result.ProtectionData == nil {
			return StatusError
		}
		return StatusPassed
	}
	if result.CiMissing || !result.CiValid {
		return StatusError
	}
	for _, r := range result.DegradedReasons {
		if !degradedReasonIsBranchProtection(r) {
			return StatusError
		}
	}
	return StatusPassed
}

// CodesForControl returns every ISSUE code registered to a control name,
// sorted for deterministic output. Empty for an unknown control name.
func CodesForControl(controlName string) []ErrorCode {
	var out []ErrorCode
	for code, info := range errorCodeRegistry {
		if info.ControlName == controlName {
			out = append(out, code)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
