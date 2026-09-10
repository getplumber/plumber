package cmd

import (
	"fmt"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	"github.com/getplumber/plumber/internal/platform"
	providerPkg "github.com/getplumber/plumber/provider"
)

// policyRun is one evaluated control configuration and every resolved policy
// that shares it (platform mode, spec 2026-09-10-cli-platform-mode-policies-
// only s2). It is THE product of a platform-mode run: the log renderer, the
// artifact writers, the badge and MR comment, and the push all read it, so
// they can never disagree about what a policy found.
type policyRun struct {
	// Policies is every resolved policy in this fingerprint group, in
	// /context order.
	Policies []platform.Policy

	// Config is the configuration that was evaluated, nil when Applied is
	// false.
	Config *configuration.PlumberConfig

	// Result is the scoped result (findings, not-evaluable marks) and Score
	// the formula over it. Both nil when Applied is false: a run that was
	// not evaluated has no verdict, and inventing an empty one would read
	// as a clean pass.
	Result *control.AnalysisResult
	Score  *control.PlumberScoreResult

	// Applied is false when nothing was evaluated for this group; Reason
	// then says why. Reason is also set on an APPLIED run when the empty
	// set is what was evaluated (reasonNoControls), which is a fact about
	// the policy rather than a failure.
	Applied bool
	Reason  string

	// Derived marks the "[Plumber default]" placeholder, evaluated under the
	// embedded default configuration (R1). It is not a real policies row, so
	// it is pushed name-only.
	Derived bool
}

// Names joins the group's policy names in /context order, for the section
// header.
func (r policyRun) Names() string {
	names := make([]string, 0, len(r.Policies))
	for _, p := range r.Policies {
		names = append(names, p.Name)
	}
	return strings.Join(names, ", ")
}

// The reasons a policy run carries. They are operator-facing prose, and the
// two "not applied" ones are also what keeps such a policy out of the push:
// a policy the CLI could not evaluate is absent from the results array,
// never a clean entry.
const (
	reasonNoControls     = "declares no controls"
	reasonNoPipeline     = "no pipeline retained for re-evaluation"
	reasonTreeNotApplied = "control tree could not be applied"
)

// evaluatePlatformPolicies evaluates the collected result once per distinct
// control configuration among the resolved policies. It never reads a local
// configuration: a real policy's tree is the configuration (R2: no tree means
// an empty set), the derived placeholder evaluates the embedded default (R1),
// an unreadable tree is not evaluated (R3), and a result with no retained IR
// cannot be re-evaluated (R6).
//
// Standalone mode resolves no policies, so this evaluates nothing and the
// push keeps its own single locally-named entry (buildPlatformPush).
func evaluatePlatformPolicies(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult) []policyRun {
	policies := platformRunOf(conf).Policies()
	if len(policies) == 0 {
		return nil
	}

	groups := map[string]*policyRun{}
	order := []*policyRun{}
	for _, pol := range policies {
		cfg, derived, reason := configForPlatformPolicy(p.Name(), pol)
		// Policies are grouped by what they EVALUATE, so two policies
		// agreeing on a configuration are evaluated once and can never
		// disagree about the answer. A policy that resolved no
		// configuration groups by its reason instead, which keeps two
		// unrelated failures from being reported as one.
		key := "reason:" + reason
		switch {
		case derived:
			key = "derived-default"
		case cfg != nil:
			key = configFingerprint(cfg)
		}
		if run, ok := groups[key]; ok {
			run.Policies = append(run.Policies, pol)
			continue
		}

		run := &policyRun{Policies: []platform.Policy{pol}, Config: cfg, Derived: derived, Reason: reason}
		if cfg != nil {
			scoped, score, ok := control.ReEvaluateForConfig(result, conf, p.Name(), cfg)
			if !ok {
				// No retained IR: there is nothing to evaluate this
				// configuration against, and an empty verdict would read
				// as a policy that found nothing wrong.
				run.Config, run.Reason = nil, reasonNoPipeline
			} else {
				// ReEvaluateForConfig already stamps fingerprints, marks
				// platform-dismissed findings and marks unconfigured
				// controls on the scoped result. Source-location
				// annotation is the one step of the run-level path it does
				// not repeat, and the per-policy render prints locations,
				// so annotate here (same linker, same order).
				newLocationLinker(conf, scoped, p.Name()).Annotate(scoped.Findings)
				run.Result, run.Score, run.Applied = scoped, &score, true
			}
		}
		groups[key] = run
		order = append(order, run)
	}

	out := make([]policyRun, 0, len(order))
	for _, r := range order {
		out = append(out, *r)
	}
	return out
}

// configForPlatformPolicy resolves the configuration one resolved policy is
// evaluated under, with no local fallback anywhere:
//   - the derived placeholder (not a real policies row): the embedded default
//     configuration, derived=true (R1);
//   - a real policy with no declared control: an empty v2 configuration,
//     reason "declares no controls" (R2). An empty set is what the policy
//     says, and evaluating it honestly is the answer - reading the local
//     file instead would report a verdict the policy never asked for;
//   - a real policy whose tree cannot be applied: nil, with the reason (R3).
func configForPlatformPolicy(provider string, pol platform.Policy) (cfg *configuration.PlumberConfig, derived bool, reason string) {
	if !pol.IsReal() {
		pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "embedded default")
		if err != nil {
			return nil, true, fmt.Sprintf("%s (%v)", reasonTreeNotApplied, err)
		}
		return pc, true, ""
	}
	if !pol.DeclaresAnyControl() {
		pc, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(emptyPolicyConfigYAML), "empty policy")
		if err != nil {
			return nil, false, fmt.Sprintf("%s (%v)", reasonTreeNotApplied, err)
		}
		return pc, false, reasonNoControls
	}
	pc, err := policyConfigFromTree(provider, pol)
	if err != nil {
		return nil, false, fmt.Sprintf("%s (%v)", reasonTreeNotApplied, err)
	}
	return pc, false, ""
}

// emptyPolicyConfigYAML is the configuration a policy declaring no control is
// evaluated under: the schema version and nothing else. It is a real
// configuration rather than a nil one, so the run is applied and reports an
// honest empty verdict.
const emptyPolicyConfigYAML = "version: \"" + policyConfigVersion + "\"\n"
