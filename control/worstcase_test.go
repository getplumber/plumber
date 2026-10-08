package control

import (
	"strings"
	"testing"
)

// The worst case is path 1's So sentence, who gets in and what an
// attacker can do, then the path it reads and its subject; nothing
// without a path.
func TestWorstCaseReadsPathOne(t *testing.T) {
	weak := AttackPath{ID: "a", Tier: TierHigh, EntryKind: EntryMutableDependency, AnchorCode: CodeImageForbiddenTag,
		Entry: EntryFact{Subject: "node:latest"}, Jobs: []string{"lint"}, Reach: Reach{Executes: true}}
	strong := AttackPath{ID: "b", Tier: TierHigh, EntryKind: EntryMutableDependency, AnchorCode: CodeImageForbiddenTag,
		Entry: EntryFact{Subject: "docker.io/alpine:latest"}, Jobs: []string{"build"}, Reach: Reach{Secrets: []string{"A", "B"}, Executes: true}}
	want := "if this image is compromised, an attacker can read 2 secrets of the repository (attack path 1: docker.io/alpine:latest)"
	if got := WorstCase([]AttackPath{weak, strong}); got != want {
		t.Errorf("worst case %q, want %q", got, want)
	}
	if got := WorstCase(nil); got != "" {
		t.Errorf("no path, worst case %q", got)
	}
}

// The merge request comment's summary says the worst case right before
// the best fix.
func TestTheCommentSummarySaysTheWorstCase(t *testing.T) {
	p := AttackPath{ID: "b", Tier: TierHigh, EntryKind: EntryMutableDependency, AnchorCode: CodeImageForbiddenTag,
		Entry: EntryFact{Subject: "docker.io/alpine:latest"}, Jobs: []string{"build"}, Reach: Reach{Secrets: []string{"A"}, Executes: true}}
	result := &AnalysisResult{Paths: []AttackPath{p}}
	score := &PlumberScoreResult{Score: "C", FinalPoints: 55, Paths: result.Paths}
	got := v4CommentSummary(result, score, false)
	worst := strings.Index(got, "- **Worst case:** if this image is compromised, an attacker can read 1 secret of the repository \\(attack path 1: docker.io/alpine:latest\\)\n")
	fix := strings.Index(got, "- **Best fix:**")
	if worst < 0 || fix < worst {
		t.Errorf("want the worst case right before the best fix:\n%s", got)
	}
	if got := v4CommentSummary(&AnalysisResult{}, &PlumberScoreResult{Score: "A", FinalPoints: 100}, false); strings.Contains(got, "Worst case") {
		t.Errorf("no path, no worst case:\n%s", got)
	}
}
