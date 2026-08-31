package gitlab

import (
	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
)

// This file is the seam between GETTING an upstream fact about an include's
// source project and DECIDING what it means.
//
// Both questions the include controls ask - is this ref ambiguous, is this pin
// behind - can only be answered by talking to the SOURCE project: the
// catalogue that publishes a component, or the project an include points at.
// A CLI run holding its own token asks directly. A tokenless run inside a CI
// job has no credential for it and cannot ask at all.
//
// So an embedding host that collected the data (the Plumber platform) supplies
// the observations on the run's behalf, and the judgements stay here. The host
// serves "this ref exists as a tag" and "here is what the catalogue
// publishes"; latestCatalogVersion and the ref-confusion rule turn those into
// verdicts. A host that served the verdicts instead would hold a second copy
// of the control logic, and two copies of a judgement agree only by
// coincidence.
//
// Everything here is additive. When no observation is supplied the CLI does
// exactly what it did before: it asks upstream itself.

// refExistence reports whether ref names an existing tag, and an existing
// branch, in project - the pair the ref-confusion rule (ISSUE-402) needs.
//
// A host-supplied observation is preferred over a live probe, because in the
// run this exists for there is no credential to probe with. When the host
// supplied nothing the CLI probes upstream itself, which keeps every
// standalone run behaving exactly as it does today.
//
// The third return is "known". False means neither source established an
// answer, and the caller must record that rather than consuming the zero
// values: a ref that could not be checked is not an unambiguous ref, and
// collapsing those two is the silent pass this control exists to catch.
func refExistence(
	inc MergedCIConfResponseInclude,
	project, ref, token string,
	conf *configuration.Configuration,
	l *logrus.Entry,
) (tagExists bool, branchExists bool, known bool) {
	// BOTH halves are required. A host that determined one and not the other
	// has not answered the question, because ambiguity needs both to be true
	// and the missing half could be either. Taking the known half and
	// defaulting the other is how a determined "false" gets manufactured.
	if inc.RefExistsAsTag != nil && inc.RefExistsAsBranch != nil {
		return *inc.RefExistsAsTag, *inc.RefExistsAsBranch, true
	}

	tagExists, branchExists, err := RefResolvesAsTagAndBranch(project, ref, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).WithFields(logrus.Fields{"project": project, "ref": ref}).
			Debug("Could not probe ref for ambiguity")
		return false, false, false
	}
	return tagExists, branchExists, true
}
