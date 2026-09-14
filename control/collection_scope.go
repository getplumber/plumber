package control

import "github.com/getplumber/plumber/configuration"

// collectionConfigs returns the control configurations this run has to
// collect data for.
//
// In platform mode the answer is not the run's own configuration: the
// platform serves one control tree per policy, every policy is evaluated
// over the SAME collected data, and a control a policy enables therefore
// needs its lane collected even when the local file (or the embedded
// default on a zero-config run) switches that control off. Collection is
// driven by the union of those trees and still happens once (platform
// decision row 62).
//
// Outside platform mode, and on any path that resolved no policy, the list
// is empty and the run's own configuration is the only one, which is
// exactly the behaviour every gate had before.
func collectionConfigs(conf *configuration.Configuration) []*configuration.PlumberConfig {
	if conf == nil {
		return nil
	}
	if len(conf.CollectionConfigs) > 0 {
		return conf.CollectionConfigs
	}
	return []*configuration.PlumberConfig{conf.PlumberConfig}
}

// anyCollectionConfig reports whether gate holds for at least ONE of the
// configurations this run collects for: a control is collected when any
// resolved policy enables it.
//
// The Configuration is copied shallowly and its PlumberConfig swapped, the
// same seam ReEvaluateForConfig uses for the per-policy evaluation, so each
// gate keeps reading every other field of the run (the control filters, the
// platform run context) exactly as it does today and the caller's
// Configuration is never mutated.
func anyCollectionConfig(conf *configuration.Configuration, gate func(*configuration.Configuration) bool) bool {
	if conf == nil {
		return false
	}
	for _, pc := range collectionConfigs(conf) {
		scoped := *conf
		scoped.PlumberConfig = pc
		if gate(&scoped) {
			return true
		}
	}
	return false
}

// The gated data collections. Each is a collection this run performs only
// when some control needs it, which is exactly why a control whose lane was
// never collected must not report a verdict.
const (
	laneGitLabProtection     = "gitlab_protection"
	laneGitLabVariables      = "gitlab_variables"
	laneGitLabSecurityPolicy = "gitlab_security_policy"
	laneGitHubBranches       = "github_branches"
	laneGitHubActionSource   = "github_action_source"
)

// markLaneCollected records that a gated collection ran this run.
func (r *AnalysisResult) markLaneCollected(lane string) {
	if r == nil {
		return
	}
	if r.CollectedLanes == nil {
		r.CollectedLanes = map[string]bool{}
	}
	r.CollectedLanes[lane] = true
}

// markGitHubLanes records which of GitHub's two gated collections this run
// performed, so a later not-evaluable path can tell a lane that never ran from
// one that ran and found nothing (platform decision row 62).
//
// Both entry points assemble their result late, after the collections they
// gate have already happened, so the booleans are computed at the gates and
// carried here rather than re-derived.
// projectPath is the path the enrichment was actually called with, which is
// conf.ProjectPath on the local path and owner/repo on the remote one: the
// lane record has to judge the same path the fetch addressed.
func markGitHubLanes(result *AnalysisResult, conf *configuration.Configuration, projectPath string, scanMutableExec bool, branchScope *configuration.PlumberConfig) {
	if scanMutableExec {
		result.markLaneCollected(laneGitHubActionSource)
	}
	if branchLaneCollected(conf, projectPath, branchScope) {
		result.markLaneCollected(laneGitHubBranches)
	}
}

// collectionBranchProtectionConfig returns the configuration GitHub's
// branch-protection enrichment must collect for.
//
// This lane is the one place where a gate is not enough: the fetch reads the
// control's own fields to decide WHICH branches to ask about (namePatterns,
// and the default branch when defaultMustBeProtected is on), so collecting
// for one policy's scope would leave another policy's branches unfetched and
// its control passing over branches nobody looked at. The union of the
// scopes is assembled once, here, and the collector is called once with it
// (platform decision row 62).
//
// Only this one control is merged: everything else about the returned
// configuration is irrelevant to the fetch. With a single collection config
// (every standalone run) the config itself is returned untouched. Nil means
// no collection config enables the control at all, which enrichGitHubBranches
// already treats as nothing to do.
func collectionBranchProtectionConfig(conf *configuration.Configuration) *configuration.PlumberConfig {
	configs := collectionConfigs(conf)
	if len(configs) == 1 {
		return configs[0]
	}
	merged := &configuration.BranchProtectionControlConfig{}
	enabled, defaultRequired := false, false
	seen := map[string]bool{}
	for _, pc := range configs {
		cfg := pc.ControlsFor(configuration.ProviderGitHub).BranchMustBeProtected
		if cfg == nil || !cfg.IsEnabled() {
			continue
		}
		enabled = true
		for _, pattern := range cfg.NamePatterns {
			if pattern == "" || seen[pattern] {
				continue
			}
			seen[pattern] = true
			merged.NamePatterns = append(merged.NamePatterns, pattern)
		}
		if cfg.DefaultMustBeProtected != nil && *cfg.DefaultMustBeProtected {
			defaultRequired = true
		}
	}
	if !enabled {
		return nil
	}
	merged.Enabled = &enabled
	merged.DefaultMustBeProtected = &defaultRequired
	return &configuration.PlumberConfig{
		Version: "2.0",
		GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			BranchMustBeProtected: merged,
		}},
	}
}

// branchLaneCollected reports whether this run actually collected the
// branch-protection lane, i.e. whether the scope handed to the collector asks
// it for anything.
//
// The enabled check cannot be replaced by a nil test on the scope: with a
// single collecting configuration the scope IS that configuration, so a
// disabled control still reaches the collector, which no-ops on its own
// guards. Every one of those guards this function can actually be asked
// about is mirrored here: benched, disabled/no-config, and the unaddressable
// project path included, so a lane recorded as collected always means a
// fetch was attempted (platform decision row 62).
//
// enrichGitHubBranches' pipeline == nil guard is the one deliberately left
// out: this function has no pipeline to test, and both call sites
// (task_github.go) already dereference the pipeline they pass it (reading
// DefaultBranch, then Jobs, to build the AnalysisResult) before
// markGitHubLanes runs. A nil pipeline would have panicked earlier, so that
// guard never has anything to fire on by the time this runs.
func branchLaneCollected(conf *configuration.Configuration, projectPath string, scope *configuration.PlumberConfig) bool {
	if scope == nil || !shouldRunControl(controlBranchMustBeProtected, conf) {
		return false
	}
	if configuration.IsBenched(configuration.ProviderGitHub, controlBranchMustBeProtected) {
		return false
	}
	if _, _, ok := gitHubOwnerRepo(projectPath); !ok {
		return false
	}
	cfg := scope.ControlsFor(configuration.ProviderGitHub).BranchMustBeProtected
	return cfg != nil && cfg.IsEnabled()
}

// controlsByGatedLane names, per provider, the controls that have nothing to
// evaluate when their gated collection did not run. Keyed by provider because
// branchMustBeProtected exists on both and reads a DIFFERENT lane on each: a
// GitLab run must never be discredited by the absence of a GitHub lane.
var controlsByGatedLane = map[string]map[string][]string{
	configuration.ProviderGitLab: {
		laneGitLabProtection: {
			controlBranchMustBeProtected,
			controlMRApprovalRulesMinApprovals,
			controlMRApprovalRulesCoverAllBranches,
			controlMRApprovalSettings,
			controlMRSettings,
		},
		laneGitLabVariables: {
			controlCicdVariablesMustBeProtected,
			controlCicdVariablesMustBeMasked,
		},
		laneGitLabSecurityPolicy: {controlSecurityPolicy},
	},
	configuration.ProviderGitHub: {
		laneGitHubBranches:     {controlBranchMustBeProtected},
		laneGitHubActionSource: {controlMutableRemoteExec},
	},
}

// MarkUncollectedLanes flags every control these entries enable whose gated
// collection did not run this run.
//
// It exists for the per-policy path. Collection is driven by the union of
// the resolved policies' configurations, so in the normal case every
// enabled control's lane WAS collected and this marks nothing. It is the
// guard for the case the union cannot cover - a lane whose gate did not
// fire, a run that never reached the gates - where the GitLab statuses
// abstain with no reason at all and the GitHub ones pass vacuously
// (platform decision row 62).
//
// Runs AFTER the lane-gap and failed-collection markers: those name a more
// specific cause (the platform reported the lane degraded, the fetch
// failed), and MarkNotEvaluable keeps the first reason.
func MarkUncollectedLanes(result *AnalysisResult, entries []ControlEntry, provider string) {
	if result == nil {
		return
	}
	enabled := map[string]bool{}
	for _, e := range entries {
		if !e.Skipped {
			enabled[e.ControlName] = true
		}
	}
	for lane, controls := range controlsByGatedLane[provider] {
		if result.CollectedLanes[lane] {
			continue
		}
		for _, name := range controls {
			if !enabled[name] {
				continue
			}
			result.MarkNotEvaluable(name, ReasonLaneNotCollected)
		}
	}
	result.DropNotEvaluableFindings()
}
