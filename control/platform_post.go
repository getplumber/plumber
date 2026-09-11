package control

// PlatformPostSummary is what a platform-mode run tells the post-analysis
// actions (the GitLab badge and the merge-request comment) about the
// platform's verdict, in place of the run-level Plumber Score they read for a
// standalone run. There is no run-level score in platform mode: every verdict
// belongs to one of the platform's policies, and the single headline figure
// is the platform's own global score from the push response (spec
// 2026-09-10-cli-platform-mode-policies-only s5).
//
// HasGlobal is the honest flag rather than an empty GlobalLetter: a push that
// returned no global score is a routine state (an older platform, a fail-open
// gate), and the comment must say "score unavailable" while the badge stays
// on its last good value. Neither may fall back to a locally computed figure
// the platform never agreed to (QUESTIONS row 44).
type PlatformPostSummary struct {
	GlobalLetter string
	GlobalPoints int
	HasGlobal    bool
	Policies     []PlatformPolicyLine
}

// hasPublishableGlobal reports whether the platform's global score may be
// published as a headline and a badge. It is the single place both consumers
// ask, so neither can publish what the other refuses.
//
// The letter is checked against the closed A-E set the Plumber Score has,
// not merely for being non-empty. It arrives from the platform's push
// response and is interpolated into a shields.io URL (ScoreBadgeURL) that
// then goes into a Markdown image AND link target in a comment posted with
// Plumber's identity: a value like "A)](https://elsewhere)" would close the
// image and forge the link. Anything outside the set is treated exactly like
// no score at all - "score unavailable", and the badge left on its last good
// value - because that is what it is.
func (s *PlatformPostSummary) hasPublishableGlobal() bool {
	return s != nil && s.HasGlobal && ScoreLetterRank(s.GlobalLetter) > 0
}

// PlatformPolicyLine is one resolved policy's row in the merge-request
// comment's table. Letter is empty and FinalPoints zero for a policy the CLI
// could not evaluate; the renderer prints that as "not evaluated" rather than
// as a score of zero. Blocking is the platform's own gate answer for this
// policy, never a CLI recomputation.
type PlatformPolicyLine struct {
	Name        string
	Enforcement string
	Letter      string
	FinalPoints int
	Blocking    bool
}
