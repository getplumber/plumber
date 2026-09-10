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
