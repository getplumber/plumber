package provider

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/capability"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
)

// CapabilitiesOf runs the capability recognizer over the analyzed pipeline:
// the one call both bills share (the --pbom artifact and the push's bom
// section), so the two documents never disagree about what the jobs do.
//
// The capabilities are the effective list of spec 4.2 (capability.Effective):
// the declarations a platform run is served on /context, or a standalone
// run's .plumber.yaml key, with the CLI's built-in list filling in every name
// they do not declare. In platform mode the served list is the configuration
// (spec 4.6): the file's key is ignored, with one info line when it is set.
// A pattern that does not compile is skipped with one warning (Compile).
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
	l := logrus.WithField("context", "capability")
	repoRoot := ""
	if conf != nil {
		repoRoot = wrapperScriptRoot(conf)
	}
	decls := capability.Compile(capability.Effective(declaredCapabilities(conf, l)), func(msg string) { l.Warn(msg) })
	return capability.Recognize(result.Pipeline, repoRoot, decls)
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
		decls, err := fileCapabilities(file)
		if err == nil {
			err = capability.Validate(decls)
		}
		if err != nil {
			l.WithError(err).Warn("capabilities: the .plumber.yaml declarations are not valid, the built-in list is in force")
			return nil
		}
		return decls
	}
	if file != nil {
		l.Info("capabilities: the platform's declarations are in force, the .plumber.yaml key is ignored in platform mode")
	}
	if conf.PlatformRun.Context == nil || len(conf.PlatformRun.Context.Capabilities) == 0 {
		return nil
	}
	served, err := capability.DecodeJSON(conf.PlatformRun.Context.Capabilities)
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

// fileCapabilities decodes the raw .plumber.yaml capabilities value strictly: it is
// re-encoded under its key and read by capability.DecodeYAML, which refuses an unknown key
// by name and a wrong type. Nil value, nil list.
func fileCapabilities(raw interface{}) ([]capability.Declaration, error) {
	if raw == nil {
		return nil, nil
	}
	data, err := yaml.Marshal(map[string]interface{}{"capabilities": raw})
	if err != nil {
		return nil, err
	}
	return capability.DecodeYAML(data)
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
