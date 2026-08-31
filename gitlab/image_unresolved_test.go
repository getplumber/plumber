package gitlab

import (
	"testing"

	"github.com/sirupsen/logrus"
)

// parseImageReference's Unresolved flag is what makes the image rules
// abstain instead of judging a placeholder (re-raised #431 review threads):
// a reference still holding a $VARIABLE parses into registry/name/tag
// fields that are present and WRONG, so the flag, not field emptiness, is
// the only honest signal.
func TestParseImageReference_SetsUnresolvedOnVariables(t *testing.T) {
	l := logrus.NewEntry(logrus.New())

	unresolved := &GitlabPipelineImageInfo{Link: "$CI_REGISTRY/app:latest"}
	unresolved.parseImageReference(l)
	if !unresolved.Unresolved {
		t.Fatal("a reference still holding a $VARIABLE must be flagged unresolved")
	}

	resolved := &GitlabPipelineImageInfo{Link: "registry.example.com/team/app:1.2.3"}
	resolved.parseImageReference(l)
	if resolved.Unresolved {
		t.Fatal("a fully literal reference is resolved")
	}
	if resolved.Registry != "registry.example.com" || resolved.Name != "team/app" || resolved.Tag != "1.2.3" {
		t.Fatalf("literal reference parsed wrong: %+v", resolved)
	}
}
