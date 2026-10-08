package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

// The score block says the worst case right before the best fix: path 1's
// So sentence, then the path and its subject, wrapped under its own text
// past the letter.
func TestTheScoreBlockSaysTheWorstCase(t *testing.T) {
	score := finalScreenScore()
	weak := control.AttackPath{ID: "p0", Tier: control.TierHigh, BaseTier: control.TierHigh, EntryKind: control.EntryMutableDependency,
		AnchorCode: "ISSUE-102", Entry: control.EntryFact{Subject: "node:latest"}, Jobs: []string{"lint"}, Reach: control.Reach{Executes: true}}
	score.Paths = append([]control.AttackPath{weak}, score.Paths...)
	var out bytes.Buffer
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, false, finalNotes{Status: &gateStatus{Required: "100 pts required"}})
	got := out.String()
	want := "  ╚═════╝  Worst case: if this image is compromised, an attacker can read 7 secrets of the\n" +
		"           repository (attack path 1: docker.io/alpine:latest)\n" +
		"           Best fix: pin the image by digest (image docker.io/alpine:latest), +15 pts, 70 / 100 (C)\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("score block ends:\n%s\nwant:\n%s", got[strings.LastIndex(got, "Status"):], want)
	}

	score.Paths = nil
	out.Reset()
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, false, finalNotes{})
	if strings.Contains(out.String(), "Worst case") {
		t.Errorf("no path, no worst case:\n%s", out.String())
	}
}
