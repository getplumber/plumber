package gitlab

import (
	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
)

// GitlabVariablesAnalysisData holds the project's settings CI/CD variables
// (GitLab: Settings > CI/CD > Variables) with their security flags, for the
// cicdVariablesMustBeProtected / cicdVariablesMustBeMasked controls.
//
// Known records whether the listing was read authoritatively. A 401/403 (or
// any other settings-API failure) leaves it false, so the controls report
// not-evaluable rather than a false pass: a token that cannot read the
// variables must not make an unprotected variable look protected (#418).
type GitlabVariablesAnalysisData struct {
	Variables []CICDVariable
	Known     bool
}

// CollectGitlabVariables fetches the project's settings CI/CD variables with
// their protected/masked flags. Any fetch failure — most importantly a
// 401/403 from a token without the variable-read scope — is a definitive
// "cannot evaluate", never a false pass: Variables stays empty and Known
// stays false. The variable values are fetched but never projected onto the
// IR (see gitlab_ir.go::buildSettingsVariables), per the #370
// variable-sensitivity tiers.
//
// The fetch error is also returned (alongside the always-non-nil data) so the
// caller can distinguish a transient network failure — which must degrade the
// run (exit 3), like the branch/image collectors (#220) — from a definitive
// permission failure (401/403 or a null project), which stays a plain
// not-evaluable. Known is false in both cases.
func CollectGitlabVariables(fullPath, token string, conf *configuration.Configuration) (*GitlabVariablesAnalysisData, error) {
	l := logrus.WithFields(logrus.Fields{
		"platform": "gitlab",
		"action":   "CollectGitlabVariables",
		"project":  fullPath,
	})
	vars, err := GetGitlabProjectVariables(fullPath, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Warn("settings-variable listing unreadable; cicdVariablesMustBe* will report not-evaluable")
		return &GitlabVariablesAnalysisData{Known: false}, err
	}
	// The settings controls only need each variable's flags (protected / masked
	// / type / environmentScope), never its value — image resolution uses a
	// separate fetch. Blank the value so a settings-variable secret is never
	// held on this data or risked in any downstream serialization. VariablesData
	// is already json:"-" and the IR carries no Value field; this is defense in
	// depth at the collection boundary.
	for i := range vars {
		vars[i].Value = ""
	}
	return &GitlabVariablesAnalysisData{Variables: vars, Known: true}, nil
}
