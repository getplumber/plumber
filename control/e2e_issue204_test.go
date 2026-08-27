package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

// TestIssue204_DoesNotVoidTheRestOfTheRun is the end-to-end regression for
// the crash reported against v0.4.41, run through the whole analysis path
// (shipped default config -> engine config -> every embedded policy ->
// applicability filter) rather than against a hand-written policy config.
//
// The pipeline below trips two independent controls: a dind service
// (ISSUE-412) and a script line naming two of the ten dangerous variables
// the shipped default ships (ISSUE-204). Before the fix the second one
// aborted its module with eval_conflict_error, and because Engine.Evaluate
// returns on the first module error, evaluatePolicies swallowed it and
// returned ZERO findings: the dind service disappeared too and the run
// scored a clean 100/100.
//
// So this asserts the blast radius, not just the crashing control: one bad
// line must not take the rest of the run with it.
func TestIssue204_DoesNotVoidTheRestOfTheRun(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfig("../defaultConfig/.plumber.yaml")
	if err != nil {
		t.Fatalf("load shipped default config: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.Provider("gitlab"),
		ProjectPath:   "group/project",
		DefaultBranch: "main",
		Jobs: []ir.Job{
			{
				Name:     "deploy",
				Services: []ir.Image{{Name: "docker", Tag: "dind"}},
				Scripts: []string{
					// CI_COMMIT_MESSAGE and CI_COMMIT_REF_NAME are both in the
					// shipped dangerousVariables list, and both appear here.
					`echo "$CI_COMMIT_MESSAGE" && source "./ci/$CI_COMMIT_REF_NAME.sh"`,
				},
			},
		},
	}
	conf := &configuration.Configuration{ProjectPath: "group/project", PlumberConfig: pc}

	findings := evaluatePolicies(logrus.NewEntry(logrus.New()), conf, "gitlab", pipeline)

	seen := map[string]int{}
	for _, f := range findings {
		seen[f.Code]++
	}
	// The unrelated control must survive: this is the regression that made a
	// failing pipeline read as clean.
	if seen["ISSUE-412"] == 0 {
		t.Errorf("the dind finding was voided by the other policy's failure; got %v", seen)
	}
	// And the crashing control itself must now report, once per dangerous
	// variable on the line.
	if seen["ISSUE-204"] != 2 {
		t.Errorf("expected one ISSUE-204 per dangerous variable on the line (2), got %d; all: %v", seen["ISSUE-204"], seen)
	}
}
