package cmd

import (
	"fmt"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/platform"
	providerPkg "github.com/getplumber/plumber/provider"
)

// policyHeader renders "== Policy: A, B  [report]" or "[block, min_points
// 80]". When the group's policies differ in enforcement or min_points, each
// policy gets its own bracket after its name: one bracket for the whole
// group would state the wrong enforcement for half of it.
func policyHeader(r policyRun) string {
	if len(r.Policies) == 0 {
		return "== Policy:"
	}
	same := true
	for _, p := range r.Policies[1:] {
		if p.Enforcement != r.Policies[0].Enforcement || !equalMinPoints(p.MinPoints, r.Policies[0].MinPoints) {
			same = false
		}
	}
	if same {
		return fmt.Sprintf("== Policy: %s  %s", r.Names(), enforcementBracket(r.Policies[0]))
	}
	parts := make([]string, 0, len(r.Policies))
	for _, p := range r.Policies {
		parts = append(parts, p.Name+" "+enforcementBracket(p))
	}
	return "== Policy: " + strings.Join(parts, ", ")
}

func enforcementBracket(p platform.Policy) string {
	if p.MinPoints != nil {
		return fmt.Sprintf("[%s, min_points %d]", p.Enforcement, *p.MinPoints)
	}
	return fmt.Sprintf("[%s]", p.Enforcement)
}

func equalMinPoints(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// renderPolicySections prints one section per evaluated run (spec s3): the
// header, the control blocks today's report prints (passed, skipped, not
// evaluated, failed), the issues table, and the run's own score banner. A run
// that was not applied prints its reason and no banner: an empty verdict
// would read as a policy that found nothing wrong.
//
// Everything a section prints comes from the RUN (r.Result, r.Config,
// r.Score), never from conf's local configuration: that separation is the
// whole point of the mode (spec s2). conf is read for the one run-level fact
// that outranks the policies, --no-controls, which is a request for no
// verdict at all and must not be turned into a scored, published section
// (see providerControlEntries).
func renderPolicySections(p providerPkg.Provider, conf *configuration.Configuration, runs []policyRun, controlsFilterList, skipControlsList []string) {
	noControls := conf != nil && conf.NoControls
	for _, r := range runs {
		fmt.Println()
		fmt.Println(policyHeader(r))
		if r.Derived {
			fmt.Println("  (the platform has no policy for this project: the embedded default configuration is evaluated under this name)")
		}
		if !r.Applied {
			fmt.Printf("  %s, nothing evaluated\n", r.Reason)
			continue
		}
		if r.Reason == reasonNoControls {
			fmt.Println("  declares no controls, nothing evaluated")
		}
		var controls []controlSummary
		var groups []findingGroup
		// Under --no-controls nothing was selected, so listing every
		// control as "skipped" is noise that reads like a
		// misconfiguration, and the banner is withheld rather than
		// stamping a perfect score on a run that evaluated nothing.
		if !noControls {
			controls, groups = buildProviderControlSummariesAndGroups(p, r.Result, r.Config, controlsFilterList, skipControlsList)
		}
		renderFindingGroups(filterGroupsForDegraded(groups, r.Result.DataCollectionDegraded))
		if n := countNotEvaluated(groups); n > 0 {
			fmt.Printf("  %s⚠️  %d control(s) could not be evaluated, the score below is computed over the rest%s\n\n", colorYellow, n, colorReset)
		}
		// On a degraded run an empty issues table would imply a clean
		// pipeline we never evaluated (#220), and under --no-controls it
		// would read as a clean scan.
		if (!r.Result.DataCollectionDegraded || len(r.Result.Findings) > 0) && !noControls {
			printIssuesTable(controls)
			fmt.Println()
		}
		printSummaryScoreBanner(r.Score, !noControls, r.Result.DataCollectionDegraded)
	}
}

// renderPlatformVerdict prints the block built from the push response (spec
// s3): one line per policy the platform gated, with the reason rendered from
// the policy's enforcement, its min_points and this run's own final points,
// then the platform's global score, then the exit line. The exit code is the
// platform's verdict, never a local recomputation, so exitErr (what
// evaluatePlatformGate returned) is what decides the last line.
func renderPlatformVerdict(runs []policyRun, v *platformVerdict, exitErr error) {
	fmt.Println()
	if v == nil || v.Gate == nil {
		// Invariant 5: no usable gate lets the run through, and says so
		// in plain words rather than passing silently.
		reason := "no push"
		if v != nil && v.Unavailable != "" {
			reason = v.Unavailable
		}
		fmt.Printf("Platform verdict: unavailable (%s), fail-open, exit 0\n", reason)
		return
	}
	fmt.Println("== Platform verdict")
	width := 0
	for _, gp := range v.Gate.Policies {
		if len(gp.Name) > width {
			width = len(gp.Name)
		}
	}
	blocking := make([]string, 0, len(v.Gate.Policies))
	for _, gp := range v.Gate.Policies {
		status := "not blocking"
		if gp.Blocking {
			status = "BLOCKING" + blockingReason(runs, gp)
			blocking = append(blocking, gp.Name)
		}
		fmt.Printf("  %-*s   %-6s   %s\n", width, gp.Name, gp.Enforcement, status)
	}
	if v.GlobalScore != nil {
		fmt.Printf("  Global score (platform): %s  %d / 100 pts\n", v.GlobalScore.Letter, v.GlobalScore.Points)
	}
	if exitErr != nil {
		// The top-level Blocking flag is the platform's decision and does
		// not structurally guarantee a non-empty per-policy subset (a
		// run-level reason, or a shape this CLI predates). With no name to
		// print, the line falls back to the gate's own reason through the
		// same chain the job-log line uses, rather than rendering a bare
		// "Exit 1:  blocks" that says nothing at all.
		if len(blocking) == 0 {
			fmt.Printf("  Exit 1: %s\n", platformGateDetail(nil, v.Gate.Reason))
			return
		}
		fmt.Printf("  Exit 1: %s blocks\n", strings.Join(blocking, ", "))
		return
	}
	fmt.Println("  Exit 0")
}

// blockingReason renders " (66 < min_points 80)" for a policy the platform
// gates on a threshold, and " (N live failures)" otherwise. The points are
// this run's own recomputed final points for that policy, which is what the
// sections above printed: the line explains the platform's verdict in the
// numbers the reader just saw.
func blockingReason(runs []policyRun, gp platformGatePolicy) string {
	for _, r := range runs {
		for _, p := range r.Policies {
			if p.ID != gp.ID {
				continue
			}
			if p.MinPoints != nil && r.Score != nil {
				return fmt.Sprintf(" (%.0f < min_points %d)", r.Score.FinalPoints, *p.MinPoints)
			}
		}
	}
	return fmt.Sprintf(" (%d live failures)", gp.LiveFailCount)
}

// renderNothingEvaluated is the whole report of a platform-mode run that
// resolved no policy (unreachable platform, or none assigned): one line
// (spec s3). It never prints a score or a status, because nothing was
// evaluated and a verdict here would be invented.
func renderNothingEvaluated(rc *platform.RunContext) {
	reason := "no policy assigned"
	if rc != nil && rc.ContextErr != nil {
		reason = rc.ContextErr.Error()
	}
	endpoint, project := "", ""
	if rc != nil {
		endpoint, project = rc.Endpoint, rc.ProjectPath
	}
	fmt.Printf("  linked to %s: no policy resolved for %s (%s), nothing evaluated, exit 0\n", endpoint, project, reason)
}
