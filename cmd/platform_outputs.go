package cmd

import (
	"math"
	"strconv"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/pbom"
	providerPkg "github.com/getplumber/plumber/provider"
)

// This file turns the evaluated policy runs and the platform's verdict into
// what each artifact writer needs (spec s5). Every one of them reads the SAME
// runs the sections printed and the push reported, so the terminal, the
// files, the badge and the comment cannot disagree about what a policy found.
//
// None of them ever falls back to a locally computed score: where the
// platform returned nothing, the artifact says so and carries nothing.

// policyNames lists a run's policy names in /context order.
func policyNames(run policyRun) []string {
	names := make([]string, 0, len(run.Policies))
	for _, p := range run.Policies {
		names = append(names, p.Name)
	}
	return names
}

// finalPointsOf rounds a run's final points the same way the push does
// (platformScoreFrom), so the badge, the comment and the record agree to the
// point. ok is false for a run that evaluated nothing.
func finalPointsOf(run policyRun) (points int, ok bool) {
	if !run.Applied || run.Score == nil {
		return 0, false
	}
	return int(math.Round(run.Score.FinalPoints)), true
}

// platformPostSummary builds the badge and merge-request comment's view of
// the run: the platform's global score and one line per resolved policy, with
// the platform's own per-policy blocking answer.
func platformPostSummary(runs []policyRun, v *platformVerdict) *control.PlatformPostSummary {
	out := &control.PlatformPostSummary{}
	if v != nil && v.GlobalScore != nil {
		out.HasGlobal = true
		out.GlobalLetter = v.GlobalScore.Letter
		out.GlobalPoints = v.GlobalScore.Points
	}
	blocking := blockingPolicyKeys(v)
	for _, run := range runs {
		letter := ""
		points, scored := finalPointsOf(run)
		if scored {
			letter = run.Score.Score
		}
		for _, pol := range run.Policies {
			out.Policies = append(out.Policies, control.PlatformPolicyLine{
				Name:        pol.Name,
				Enforcement: string(pol.Enforcement),
				Letter:      letter,
				FinalPoints: points,
				Blocking:    blocking["id:"+pol.ID] || blocking["name:"+pol.Name],
			})
		}
	}
	return out
}

// blockingPolicyKeys indexes the gate's blocking policies by id AND by name.
// The platform keys its gate on ids, but the derived "[Plumber default]"
// placeholder has none that may be used (realPolicyID), so the name is the
// only handle for it; the two prefixes keep an id from ever matching a name.
func blockingPolicyKeys(v *platformVerdict) map[string]bool {
	keys := map[string]bool{}
	if v == nil || v.Gate == nil {
		return keys
	}
	for _, gp := range v.Gate.Policies {
		if !gp.Blocking {
			continue
		}
		if gp.ID != "" {
			keys["id:"+gp.ID] = true
		}
		if gp.Name != "" {
			keys["name:"+gp.Name] = true
		}
	}
	return keys
}

// platformPBOMSummary builds the PBOM and CycloneDX platform block: one entry
// per resolved policy plus the platform's global score when the push returned
// one. Returns nil outside platform mode, which is what keeps a standalone
// document byte-identical.
func platformPBOMSummary(runs []policyRun, v *platformVerdict) *pbom.PlatformSummary {
	if len(runs) == 0 {
		return nil
	}
	out := &pbom.PlatformSummary{}
	if v != nil && v.GlobalScore != nil {
		out.GlobalScore = &pbom.PlatformGlobalScore{Letter: v.GlobalScore.Letter, Points: v.GlobalScore.Points}
	}
	for _, run := range runs {
		letter := ""
		var final *int
		if points, scored := finalPointsOf(run); scored {
			letter, final = run.Score.Score, &points
		}
		for _, pol := range run.Policies {
			out.Policies = append(out.Policies, pbom.PolicyScore{
				Name:        pol.Name,
				Enforcement: string(pol.Enforcement),
				Score:       letter,
				FinalPoints: final,
				Applied:     run.Applied,
				Reason:      run.Reason,
			})
		}
	}
	return out
}

// outputControlEntries returns the control entries the per-control artifacts
// (CSV, OCSF) describe, and, in platform mode, the policies each control was
// evaluated under.
//
// Outside platform mode this is the run's own catalog, unchanged. In platform
// mode the local catalog is never consulted: the entries are the union of the
// APPLIED runs' own catalogs, keeping only the controls a policy actually
// enables, in /context order. A control no policy declares is absent rather
// than listed as skipped, because "skipped" is a statement about this run's
// configuration and there is no such configuration here.
func outputControlEntries(p providerPkg.Provider, conf *configuration.Configuration, runs []policyRun) ([]control.ControlEntry, map[string][]string) {
	if len(runs) == 0 {
		return providerControlEntries(p, conf), nil
	}
	var entries []control.ControlEntry
	seen := map[string]bool{}
	policies := map[string][]string{}
	for _, run := range runs {
		if !run.Applied || run.Config == nil {
			continue
		}
		names := policyNames(run)
		for _, e := range p.Controls(run.Config) {
			if e.Skipped {
				continue
			}
			if !seen[e.ControlName] {
				seen[e.ControlName] = true
				entries = append(entries, e)
			}
			policies[e.ControlName] = appendMissing(policies[e.ControlName], names)
		}
	}
	return entries, policies
}

// imageComplianceControls are the controls whose findings drive the PBOM's
// per-image booleans (forbiddenTag / authorized). They are derived from the
// codes BuildImageComplianceData consumes, through the codes registry, so a
// code moving to another control cannot leave this list stale.
func imageComplianceControls() map[string]bool {
	out := map[string]bool{}
	for _, code := range []control.ErrorCode{
		control.CodeImageForbiddenTag,
		control.CodeImageNotPinnedByDigest,
		control.CodeImageUnauthorizedSource,
	} {
		if info := control.LookupCode(code); info != nil && info.ControlName != "" {
			out[info.ControlName] = true
		}
	}
	return out
}

// platformImageControlsEvaluated reports whether any applied policy actually
// enables the image controls.
//
// The PBOM's per-image booleans are a POSITIVE claim: an image absent from
// every finding is published as authorized with no forbidden tag. That is only
// true of an image a control judged, so in platform mode it may be said only
// when a policy asked for those controls; otherwise the writers omit the
// booleans and the image is reported as inventory alone.
func platformImageControlsEvaluated(p providerPkg.Provider, runs []policyRun) bool {
	wanted := imageComplianceControls()
	for _, run := range runs {
		if !run.Applied || run.Config == nil {
			continue
		}
		for _, e := range p.Controls(run.Config) {
			if !e.Skipped && wanted[e.ControlName] {
				return true
			}
		}
	}
	return false
}

// platformUnionResult returns the result the security-report writers (SARIF,
// the GitLab SAST report) render in platform mode: the same run, with its
// findings replaced by the union of every APPLIED policy run's findings,
// deduplicated by fingerprint and each tagged with the policies that reported
// it.
//
// The union, not one report per policy: both formats feed a single dashboard
// that dedups on its own identity key, so emitting the same finding once per
// covering policy would either double-count it or have the consumer silently
// merge the entries and lose the policy dimension anyway. Tagging one entry
// with every policy keeps both facts.
//
// The collected result is copied, never mutated: it is still what the JSON
// report and the PBOM are written from, and its findings are the frozen
// objects the platform hashes (#467).
func platformUnionResult(result *control.AnalysisResult, runs []policyRun) *control.AnalysisResult {
	if result == nil {
		return nil
	}
	union := *result
	union.Findings = nil
	// The collected result's not-evaluable marks are the LOCAL evaluation's,
	// and the CSV and OCSF feeds turn them into a per-control status. Replace
	// them with the runs' own marks (any run's mark wins, so a control one
	// policy could not evaluate is never reported as a clean pass).
	union.NotEvaluable = nil
	index := map[string]int{}
	for _, run := range runs {
		if !run.Applied || run.Result == nil {
			continue
		}
		names := policyNames(run)
		for controlName, reason := range run.Result.NotEvaluable {
			if union.NotEvaluable == nil {
				union.NotEvaluable = map[string]string{}
			}
			if _, seen := union.NotEvaluable[controlName]; !seen {
				union.NotEvaluable[controlName] = reason
			}
		}
		for _, f := range run.Result.Findings {
			key := unionFindingKey(f)
			if at, seen := index[key]; seen {
				union.Findings[at].Policies = appendMissing(union.Findings[at].Policies, names)
				continue
			}
			entry := f
			entry.Policies = appendMissing(nil, names)
			index[key] = len(union.Findings)
			union.Findings = append(union.Findings, entry)
		}
	}
	return &union
}

// unionFindingKey is the identity two policy runs are deduplicated on: the
// stamped fingerprint, which is exactly what every consumer of these reports
// tracks a finding by, PLUS the line.
//
// The line is what makes this a report identity rather than the fingerprint's:
// the fingerprint is deliberately line-independent (that is what makes a
// dismissal survive an edit above the finding), so two occurrences of the same
// subject on two different lines share it. They are two alerts, and collapsing
// them would silently drop one from the security report.
//
// Findings that were never stamped (codeless ones, or an unstamped caller)
// fall back to their canonical fields rather than collapsing into one entry
// under the empty string.
func unionFindingKey(f opaengine.Finding) string {
	if f.Fingerprint != "" {
		return "fp:" + f.Fingerprint + "|" + strconv.Itoa(f.Line)
	}
	return "raw:" + f.Code + "|" + f.File + "|" + strconv.Itoa(f.Line) + "|" + f.Job + "|" + f.Message
}

// appendMissing appends the names not already present, preserving order.
func appendMissing(existing []string, names []string) []string {
	for _, n := range names {
		found := false
		for _, e := range existing {
			if e == n {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, n)
		}
	}
	return existing
}
