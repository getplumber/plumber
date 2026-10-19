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
// The list compiled is spec 4.2 and 4.6's: in platform mode, the declarations
// served on /context, compiled exactly as served (spec 3 decision 10), with
// no built-in fill-in, because the platform's own default IS the built-in
// list; removing a capability on the platform must remove it everywhere,
// including a served empty list, which recognizes nothing at all. A context
// without the field (an older platform, a failed /context fetch), or a served
// list that fails decoding or the bounds, means the built-in list alone
// (capability.Builtin). Standalone, it is capability.Effective: the
// .plumber.yaml key's declarations first, the built-in list filling in every
// name they do not declare. In both modes the file's key is ignored in
// platform mode, with one info line when it is set. A pattern that does not
// compile is skipped with one warning (Compile). Nil when the run produced no
// normalized pipeline.
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
	l := logrus.WithField("context", "capability")
	repoRoot := ""
	if conf != nil {
		repoRoot = wrapperScriptRoot(conf)
	}
	decls := capability.Compile(capabilityList(conf, l), func(msg string) { l.Warn(msg) })
	return capability.Recognize(result.Pipeline, repoRoot, decls)
}

// capabilityList returns the list CapabilitiesOf compiles (spec 3 decision 10, 4.2, 4.6). In
// platform mode the served list (declaredCapabilities) is used exactly as is when it is not
// nil, including empty (the organization cleared its setting): there is no merge with the
// built-in list, since the platform's own default is the built-in list itself. A nil served
// list (no /context field, a failed fetch, or a served list that failed decoding or the
// bounds, already warned by declaredCapabilities) falls back to capability.Builtin().
// Standalone, the behaviour is unchanged: capability.Effective fills in every built-in name
// the file's list does not declare.
func capabilityList(conf *configuration.Configuration, l *logrus.Entry) []capability.Declaration {
	declared := declaredCapabilities(conf, l)
	if conf != nil && conf.PlatformRun != nil {
		if declared == nil {
			return capability.Builtin()
		}
		return declared
	}
	return capability.Effective(declared)
}

// declaredCapabilities returns the user's declarations the effective list is
// built from (spec 4.6): in platform mode the list /context served, decoded
// tolerantly (an unknown key, a field of a platform newer than the CLI, is
// ignored and the known fields kept), every recognizer left without a pattern
// this CLI knows pruned (one debug line each; a capability left with none keeps
// its name, the disable gesture), then checked against the bounds of spec 4.2
// (the platform checked them at PUT); standalone, the .plumber.yaml key,
// re-encoded from the raw value the configuration load kept, decoded strictly
// (an unknown key or a wrong type is an error) and checked against the same
// bounds. A list that fails is never half used: one warning naming the error,
// the built-in list alone, and the run goes on. Nil means the built-in list
// only: a standalone run without the key, a platform that predates the field,
// a failed /context fetch.
func declaredCapabilities(conf *configuration.Configuration, l *logrus.Entry) []capability.Declaration {
	if conf == nil {
		return nil
	}
	var file interface{}
	if conf.PlumberConfig != nil {
		file = conf.PlumberConfig.Capabilities
	}
	if conf.PlatformRun == nil {
		return capability.FromFile(file, l)
	}
	if file != nil {
		l.Info("capabilities: the platform's declarations are in force, the .plumber.yaml key is ignored in platform mode")
	}
	if conf.PlatformRun.Context == nil || len(conf.PlatformRun.Context.Capabilities) == 0 {
		return nil
	}
	served, err := capability.DecodeJSON(conf.PlatformRun.Context.Capabilities)
	if err == nil && served == nil {
		// A served JSON null decodes to no declarations at all, the same as an
		// absent field: nil here, not the empty-but-present list spec 3
		// decision 10 means (a served `[]`, which PruneEmptyRecognizers would
		// otherwise turn into a non-nil empty slice indistinguishable from it).
		return nil
	}
	if err == nil {
		served = capability.PruneEmptyRecognizers(served, func(name string, index int) {
			l.WithFields(logrus.Fields{"capability": name, "recognizer": index}).
				Debug("capabilities: a served recognizer carries no pattern this CLI knows, pruned")
		})
		err = capability.Validate(served)
	}
	if err != nil {
		l.WithError(err).Warn("capabilities: the platform's declarations are not valid, the built-in list is in force")
		return nil
	}
	return served
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
