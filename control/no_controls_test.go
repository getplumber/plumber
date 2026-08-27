package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

// TestNoControls_SkipsPolicyEvaluation pins the --no-controls contract at the
// engine boundary: when the user asked for no controls, no policy is
// evaluated at all. Filtering the findings afterwards would not be the same
// thing, because a policy that crashes takes the whole run's findings with it
// (Engine.Evaluate returns on the first module error), so a run that
// evaluates nothing is also a run nothing can break.
func TestNoControls_SkipsPolicyEvaluation(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfig("../.plumber.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.Provider("gitlab"),
		ProjectPath:   "group/project",
		DefaultBranch: "main",
		Jobs: []ir.Job{
			// Hardcoded origin plus a bare `pip install`: enough to make at
			// least one enabled control fire on a normal run.
			{Name: "build", OriginKind: "hardcoded", Scripts: []string{"pip install requests"}},
		},
	}

	conf := &configuration.Configuration{ProjectPath: "group/project", PlumberConfig: pc}
	if got := evaluatePolicies(logrus.NewEntry(logrus.New()), conf, "gitlab", pipeline); len(got) == 0 {
		t.Fatal("fixture must produce findings without --no-controls, otherwise this test proves nothing")
	}

	conf.NoControls = true
	got := evaluatePolicies(logrus.NewEntry(logrus.New()), conf, "gitlab", pipeline)
	if len(got) != 0 {
		t.Fatalf("--no-controls must evaluate nothing, got %d findings", len(got))
	}
	if got == nil {
		t.Fatal("must return an empty non-nil slice so JSON marshals [] and not null")
	}
}
