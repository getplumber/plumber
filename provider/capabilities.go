package provider

import (
	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/capability"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
)

// CapabilitiesOf runs the capability recognizer over the analyzed pipeline:
// the one call both bills share (the --pbom artifact and the push's bom
// section), so the two documents never disagree about what the jobs do.
//
// The recognizers are the shipped defaults, then, in platform mode with a
// fetched /context, the org-defined recognizers the platform served, merged
// after them. A standalone run, or a platform run whose /context fetch
// failed, takes the same path with the defaults alone. Nil when the run
// produced no normalized pipeline.
//
// Wrapper scripts are the one rule that reads the disk, and they are read only
// when the checkout IS the analyzed project (CheckoutIsAnalyzedProject) AND
// holds the analyzed ref (CheckoutIsAtRef): the same two gates the CI-file
// read and the config digest apply. GitRepoRoot is whatever repository the
// CLI stands in; with --project naming another one, a script of this checkout
// would otherwise become wrapper_script evidence for a project that never runs
// it, which is false coverage. Otherwise the root stays empty and the rule is
// off; image, include, report and command evidence need no checkout.
func CapabilitiesOf(result *control.AnalysisResult, conf *configuration.Configuration) []capability.Match {
	if result == nil || result.Pipeline == nil {
		return nil
	}
	recs := capability.Defaults()
	repoRoot := ""
	if conf != nil {
		repoRoot = wrapperScriptRoot(conf)
		if rc := conf.PlatformRun; rc != nil && rc.Context != nil {
			served := make([]capability.Recognizer, 0, len(rc.Context.CapabilityRecognizers))
			for _, r := range rc.Context.CapabilityRecognizers {
				served = append(served, capability.Recognizer{Capability: r.Capability, Tool: r.Tool, Images: r.Images, Commands: r.Commands})
			}
			recs = capability.Merge(recs, served)
		}
	}
	return capability.Recognize(result.Pipeline, repoRoot, recs)
}

// wrapperScriptRoot returns the checkout root wrapper scripts may be read
// under, or "" when the checkout is not the analyzed project at the analyzed
// ref (see CapabilitiesOf).
func wrapperScriptRoot(conf *configuration.Configuration) string {
	l := logrus.WithField("context", "capability")
	switch {
	case conf.GitRepoRoot == "":
		l.Debug("capability: wrapper scripts off, the run is not in a git checkout")
		return ""
	case !conf.CheckoutIsAnalyzedProject:
		l.Debug("capability: wrapper scripts off, the checkout is not the analyzed project")
		return ""
	case !gitlab.CheckoutIsAtRef(conf.Branch):
		l.WithField("branch", conf.Branch).Debug("capability: wrapper scripts off, the checkout is not at the analyzed ref")
		return ""
	}
	return conf.GitRepoRoot
}
