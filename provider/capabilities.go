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
// The capabilities are the CLI's built-in list (capability.Effective(nil)),
// compiled. The declarations a platform serves through /context and the
// .plumber.yaml key are wired in by the next change of this series; until then
// a platform run recognizes the built-in list alone, like a standalone run.
// Nil when the run produced no normalized pipeline.
//
// Wrapper scripts are the one rule that reads the disk, and they are read only
// when the checkout IS the analyzed project (CheckoutIsAnalyzedProject) AND
// holds the analyzed ref (CheckoutIsAtRef): the same two gates the CI-file
// read and the config digest apply. GitRepoRoot is whatever repository the
// CLI stands in; with --project naming another one, a script of this checkout
// would otherwise become wrapper_script evidence for a project that never runs
// it, which is false coverage. Otherwise the root stays empty and the rule is
// off; the other five subjects need no checkout.
func CapabilitiesOf(result *control.AnalysisResult, conf *configuration.Configuration) []capability.Match {
	if result == nil || result.Pipeline == nil {
		return nil
	}
	repoRoot := ""
	if conf != nil {
		repoRoot = wrapperScriptRoot(conf)
	}
	decls := capability.Compile(capability.Effective(nil), nil)
	return capability.Recognize(result.Pipeline, repoRoot, decls)
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
