package policies_test

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/policies"
)

// The message-style lint. Every GitLab finding message the CLI emits is shown
// verbatim by the platform as the issues page "Details" column (the platform
// stores and serves the pushed text and never rewrites it, invariants I1/I2),
// so the wording contract lives here and nowhere else. The five rules come
// from the issues-page review of 2026-09-22, spec section 5.1:
//
//  1. the message starts with a capital letter (or a backquoted token);
//  2. every technical token the finding carries in its data (job name,
//     variable name, image reference, include path, branch name, service
//     image, tag) appears in the message wrapped in backquotes;
//  3. no em dash, no en dash, no semicolon, no spaced hyphen between words
//     (hyphens inside a backquoted token are fine, and so is anything else
//     inside one: a backquoted span is collector data, not our prose);
//  4. no fix guidance, one short sentence describing the issue with its
//     specific data;
//  5. no API-only token (raw enum values such as the merge method `ff` or the
//     approval behaviour `keep_approvals`), enum values rendered as their
//     human labels.
//
// Scope: the codes whose control applies to GitLab (configuration.ControlMeta
// Providers contains "gitlab"). A control registered for GitHub only is left
// as it is by this review and is not linted here.
//
// The check runs over the whole policy corpus, the same way the identity
// harness does (identity_harness_test.go): TestMain installs an observer that
// records every finding every test in this package emits, and calls
// verifyMessageStyle after m.Run. The corpus IS the fixture set - there is no
// second one - so a rule only gets linted on the messages the suite actually
// renders, with real collector values interpolated.

// gitLabMessageStyleKeys is the scope list AND rule 2's per-code contract: for
// each GitLab-applicable issue code, the finding data keys whose value must
// appear backquoted in the message whenever the finding carries that key with
// a non-empty string value. A code absent from this map is out of scope; a
// GitLab code missing from it fails the completeness check below, so a new
// control forces an author decision here rather than silently escaping the
// lint.
//
// The lists are per code rather than global because a finding often carries
// several renderings of one subject and the message names exactly one of them:
// ISSUE-103 carries link ("alpine:latest"), imageRepo ("alpine") and tag
// ("latest") for a single image, and its sentence quotes the full reference
// only. Listing the key that the sentence is required to name is the whole
// assertion; listing every key the finding happens to carry would force the
// sentence to repeat the same image three times.
var gitLabMessageStyleKeys = map[string][]string{
	// Untrusted image source: the job and the full image reference.
	"ISSUE-101": {"job", "link"},
	// Forbidden tag: the job, the offending tag, and the image it belongs to.
	"ISSUE-102": {"job", "tag", "link"},
	// Image not pinned by digest: the job and the image reference (imageRepo
	// and tag are the same image, sliced differently, for the identity).
	"ISSUE-103": {"job", "link"},
	// Settings variable not protected / not masked: settings-level, no job.
	"ISSUE-201": {"variableName"},
	"ISSUE-202": {"variableName"},
	// Debug trace: the variable, plus the job for the job-level forms (the
	// root `variables:` form carries no job).
	"ISSUE-203": {"job", "variableName"},
	// Unsafe expansion: the variable is quoted in its `$VAR` shell form, which
	// assertBackquotedToken accepts for this code.
	"ISSUE-204": {"job", "variableName"},
	// Controlled variable overridden: same shape, root form carries no job.
	"ISSUE-205": {"job", "variableName"},
	// Hardcoded job: the job (hardcodedJob is the same name, for the identity).
	"ISSUE-401": {"job"},
	// Ref collision: the GitHub form carries job + uses, the GitLab form
	// carries includePath and no job. Each emission is checked on what it has.
	"ISSUE-402": {"job", "uses", "includePath"},
	"ISSUE-403": {"includePath"},
	"ISSUE-404": {"includePath"},
	// Missing template / component: one finding per evaluation naming no
	// single subject; the missing entries travel as missingGroups data.
	"ISSUE-405": {},
	"ISSUE-406": {"templatePath"},
	"ISSUE-408": {},
	"ISSUE-409": {"componentPath"},
	// Security job weakened: the job (detail is a stable token, not prose).
	"ISSUE-410": {"job"},
	// Unverified script: the job. scriptLine is deliberately absent: the data
	// value is the raw line and the message quotes it trimmed.
	"ISSUE-411": {"job"},
	"ISSUE-412": {"job", "serviceImage"},
	"ISSUE-413": {"job"},
	"ISSUE-501": {"branchName"},
	// Approval rule below the minimum: ruleName is optional in GitLab, so it
	// is only required in the message when the finding carries one.
	"ISSUE-502": {"ruleName"},
	// Project-wide singletons: no per-finding technical subject.
	"ISSUE-503": {},
	"ISSUE-504": {},
	"ISSUE-505": {"branchName"},
	"ISSUE-506": {},
	"ISSUE-601": {},
}

// dataArrayKinds classifies every string array a GitLab finding publishes.
//
// A message is not the only text a reader sees: ISSUE-505 puts its detail
// lines in a `reasons` array rendered under the headline, and the wording
// cleanup this review performed on them (dropping "(should be disabled)") was
// caught by nothing, because the lint read `message` alone (PR #484
// re-review). Those elements are prose and belong under the sentence rules.
//
// But an array of strings is one of two things and no amount of looking tells
// them apart: prose a reader reads, or a machine contract a consumer parses.
// ISSUE-503 and ISSUE-506 publish `deviatingSettings`, the raw config key
// names, deliberately kept as the stable contract while the message renders
// them as human labels. Holding those to rule 1 would demand a capital letter
// on `mergeMethod`, which would be nonsense.
//
// So the classification is authored, and a string array the corpus emits that
// is listed here under neither kind FAILS the lint. That is what makes this
// cover "every future array" rather than only today's: a new one cannot ship
// unclassified, and classifying it is exactly the moment someone decides
// whether a human reads it. The value is true for prose, false for a contract.
//
// Arrays whose elements are not all strings (ISSUE-405 / ISSUE-408
// `missingGroups`, a list of lists; ISSUE-406 / ISSUE-409 `overriddenJobs`,
// a list of objects) are not string arrays and need no entry.
var dataArrayKinds = map[string]bool{
	// The detail lines under an ISSUE-505 headline: force push, code owner
	// approval, the two access levels. Shown to a reader, so held to the rules.
	"ISSUE-505.reasons": true,
	// The config keys that deviate. A consumer parses these; the message says
	// the same thing in English (see mr_settings_compliant.rego's _labels).
	"ISSUE-503.deviatingSettings": false,
	"ISSUE-506.deviatingSettings": false,
}

// messageBranches is the render manifest, and the answer to a defect class
// rather than to one instance of it.
//
// Four PR #484 review rounds found the same thing four times: a message
// branch, a helper arm or a label-map entry that this review rewrote, that no
// fixture reaches. The lint judges what the corpus renders, so an unrendered
// branch is not merely untested, it is outside the contract entirely: its
// wording can regress to a semicolon, an em dash or a line of fix guidance and
// every check here stays green because none of them ever sees the string.
//
// So each one is listed, with a substring that identifies it once rendered,
// and a full corpus run must produce all of them. Adding a branch to a rule
// without a fixture is now a failing build, which is the only form of this
// guarantee that does not depend on a reviewer noticing.
//
// marker is matched against the rendered message and against every element of
// the finding's string arrays (ISSUE-505 publishes its detail lines there, so
// its reasons are branches like any other).
//
// An arm that no input can reach carries unreachable with the argument for
// why. There is exactly one, and it is a defensive else.
var messageBranches = []messageBranch{
	{"ISSUE-101", "untrusted image source", "uses image `", ""},
	{"ISSUE-102", "forbidden tag", "uses the forbidden tag `", ""},
	{"ISSUE-103", "no digest", "` without a digest.", ""},
	{"ISSUE-201", "variable not protected", "is not protected and reaches pipelines", ""},
	{"ISSUE-202", "variable not masked", "is not masked and its value prints", ""},
	{"ISSUE-203", "job form", "` sets the debug variable `", ""},
	{"ISSUE-203", "root variables form", "configuration sets the debug variable `", ""},
	{"ISSUE-203", "github expression form", "to the expression", ""},
	{"ISSUE-203", "github env form", "writes the debug variable `", ""},
	{"ISSUE-204", "unsafe expansion", "expands `$", ""},
	{"ISSUE-205", "job form", "` overrides the controlled variable `", ""},
	{"ISSUE-205", "root variables form", "configuration overrides the controlled variable `", ""},
	{"ISSUE-401", "hardcoded job", "is defined in the project CI configuration", ""},
	{"ISSUE-402", "github action ref", "whose ref resolves as both a tag", ""},
	{"ISSUE-402", "gitlab include ref", "` pins the ref `", ""},
	{"ISSUE-403", "outdated include", "` uses version `", ""},
	{"ISSUE-404", "forbidden include version", "uses the forbidden version `", ""},
	{"ISSUE-405", "no template group satisfied", "includes none of the required templates", ""},
	{"ISSUE-406", "template overridden", "The required template `", ""},
	{"ISSUE-408", "no component group satisfied", "includes none of the required components", ""},
	{"ISSUE-409", "component overridden", "The required component `", ""},
	{"ISSUE-410", "allow_failure", "weakened by `allow_failure: true`", ""},
	{"ISSUE-410", "when manual", "weakened by `when: manual`", ""},
	{"ISSUE-410", "rules overridden", "weakened by an overridden `rules:` block", ""},
	{"ISSUE-411", "unverified script", "runs a script fetched from the network", ""},
	{"ISSUE-412", "dind service", "uses the Docker-in-Docker service `", ""},
	{"ISSUE-413", "tls disabled only", "variable is empty, so TLS is off", ""},
	{"ISSUE-413", "tls disabled and host", "is empty and `DOCKER_HOST` uses", ""},
	{"ISSUE-413", "host only", "`DOCKER_HOST` variable uses the non-TLS port", ""},
	{
		"ISSUE-413", "no specific signal", "the daemon configuration is insecure",
		// _insecure_for_job fires only when DOCKER_TLS_CERTDIR is empty or
		// DOCKER_HOST carries :2375, in the job variables or in the pipeline
		// globals. _tls_certdir_empty and _docker_host_value read those same
		// two places, so whenever the rule fires one of the three arms above
		// resolves and this else cannot be reached. It is kept as a defensive
		// default, not as a branch a fixture could exercise.
		"no input reaches it: the guard that admits the finding is the disjunction of the three arms above",
	},
	{"ISSUE-501", "branch unprotected", "is not protected.", ""},
	{"ISSUE-502", "named rule", "The merge request approval rule `", ""},
	{"ISSUE-502", "unnamed rule", "An unnamed merge request approval rule", ""},
	{"ISSUE-502", "one approval, singular", "requires 1 approval,", ""},
	{"ISSUE-502", "several approvals, plural", "approvals, below the configured minimum", ""},
	{"ISSUE-503", "author clause", "authors can approve their own merge requests", ""},
	{"ISSUE-503", "committer clause", "committers can approve", ""},
	{"ISSUE-503", "rule editing clause", "approval rules can be edited per merge request", ""},
	{"ISSUE-503", "re-authentication clause", "approving does not require re-authentication", ""},
	{"ISSUE-503", "behaviour label kept", "approvals are kept when a commit is added", ""},
	{"ISSUE-503", "behaviour label removed for code owners", "expected: removed for code owners", ""},
	{"ISSUE-503", "behaviour label all removed", "expected: all removed", ""},
	{"ISSUE-504", "no covering rule", "No merge request approval rule applies to all protected branches", ""},
	{"ISSUE-505", "headline", "has non-compliant protection settings", ""},
	{"ISSUE-505", "reason force push", "Force push is allowed", ""},
	{"ISSUE-505", "reason code owner", "Code owner approval is not required", ""},
	{"ISSUE-505", "reason merge access level", "Merge access level", ""},
	{"ISSUE-505", "reason push access level", "Push access level", ""},
	{"ISSUE-506", "merge method label Merge commit", `"Merge commit"`, ""},
	{"ISSUE-506", "merge method label Fast-forward merge", `"Fast-forward merge"`, ""},
	{"ISSUE-506", "merge method label Rebase and merge", `"Rebase and merge"`, ""},
	{"ISSUE-506", "squash label Never", `"Never"`, ""},
	{"ISSUE-506", "squash label Always", `"Always"`, ""},
	{"ISSUE-506", "squash label Allow, on by default", `"Allow, on by default"`, ""},
	{"ISSUE-506", "squash label Allow, off by default", `"Allow, off by default"`, ""},
	{"ISSUE-506", "boolean rendered enabled", "(expected enabled)", ""},
	// One entry per setting ISSUE-506 can name, so the corpus has to render
	// every subject. Four of these reached no fixture until this round; the
	// keys are held against the rule's own _labels map by
	// TestIssue506LabelsMatchTheManifest, so a ninth setting cannot slip past.
	{"ISSUE-506", "subject mergeMethod", "Merge method is", ""},
	{"ISSUE-506", "subject squashOption", "Squash is", ""},
	{"ISSUE-506", "subject mergePipelinesEnabled", "Merged results pipelines are", ""},
	{"ISSUE-506", "subject mergeTrainsEnabled", "Merge trains are", ""},
	{"ISSUE-506", "subject allowMergeOnSkippedPipeline", "Merging on a skipped pipeline is", ""},
	{"ISSUE-506", "subject resolveOutdatedDiffDiscussions", "Resolving outdated diff discussions is", ""},
	{"ISSUE-506", "subject printingMergeRequestLinkEnabled", "Printing the merge request link on push is", ""},
	{"ISSUE-506", "subject removeSourceBranchAfterMerge", "Removing the source branch after merge is", ""},
	{"ISSUE-601", "nothing linked, no expectation", "is linked to this project", ""},
	{"ISSUE-601", "nothing linked, expectation set", "is linked (expected", ""},
	{"ISSUE-601", "wrong project, id only", ") is not the expected one (expected id", ""},
	{"ISSUE-601", "wrong project, with path", ", path `", ""},
}

// messageBranch is one entry of the manifest above.
type messageBranch struct {
	code   string
	what   string
	marker string
	// unreachable, when non-empty, is the argument for why no input can
	// produce this arm. Such an entry is exempt from the render requirement
	// and the argument is reviewed like any other claim in this package.
	unreachable string
}

func (b messageBranch) key() string { return b.code + " " + b.what }

// issue506SubjectLabels is the authored expectation of the eight settings
// ISSUE-506 can name, as the message renders each one. It is checked against
// the rule's own _labels map (TestIssue506LabelsMatchTheManifest) so a ninth
// setting added to the Rego shows up here, and every entry is required to be
// rendered by the corpus through the manifest above, so adding one without a
// fixture fails rather than shipping unverified prose.
var issue506SubjectLabels = map[string]string{
	"mergeMethod":                     "Merge method is",
	"squashOption":                    "Squash is",
	"mergePipelinesEnabled":           "Merged results pipelines are",
	"mergeTrainsEnabled":              "Merge trains are",
	"allowMergeOnSkippedPipeline":     "Merging on a skipped pipeline is",
	"resolveOutdatedDiffDiscussions":  "Resolving outdated diff discussions is",
	"printingMergeRequestLinkEnabled": "Printing the merge request link on push is",
	"removeSourceBranchAfterMerge":    "Removing the source branch after merge is",
}

// apiOnlyTokens are the raw wire values rule 5 keeps out of user-facing prose.
// They are what the demo showed leaking ("merge method is merge (expected
// ff)"): GitLab API enum values, meaningless to the reader of an issues page.
// Each must be rendered as its human label instead.
//
// A denylist can only name the tokens that exist today, which is not enough
// where the value is served by the API rather than written by an operator: a
// merge method GitLab adds tomorrow would render raw and match no entry here.
// Every such surface is covered by enumClauseAllowlists below instead; this
// list is the backstop for everything else.
var apiOnlyTokens = []string{
	" ff)",
	" ff ",
	"rebase_merge",
	"default_on",
	"default_off",
	"keep_approvals",
	"remove_approvals_by_code_owners",
	"remove_all_approvals",
}

// enumClauseAllowlists is rule 5's positive half: where a message renders a
// GitLab enum, the rendered text must be one of the labels we chose, on BOTH
// the actual and the expected side of the clause.
//
// This is what the denylist cannot do. ISSUE-506's actual values come from the
// API (mr_settings_compliant.rego's _deviations iterates the projected
// settings), so config validation never sees them, and the rule's
// object.get(_merge_method_labels, value, value) renders an unmapped token
// verbatim. That is exactly the "(expected ff)" defect this review opened on,
// one GitLab release later. Listing what is allowed fails the moment such a
// token reaches a message; listing what is forbidden cannot.
//
// anchor is the clause prefix: a message that carries the anchor but does not
// match the pattern is reported too, so a change to the clause's shape cannot
// silently switch this check off.
var enumClauseAllowlists = []enumClause{
	{
		code:    "ISSUE-506",
		what:    "merge method",
		anchor:  "Merge method is ",
		pattern: regexp.MustCompile(`Merge method is "([^"]*)" \(expected "([^"]*)"\)`),
		allowed: []string{"Merge commit", "Fast-forward merge", "Rebase and merge"},
	},
	{
		code:    "ISSUE-506",
		what:    "squash option",
		anchor:  "Squash is ",
		pattern: regexp.MustCompile(`Squash is "([^"]*)" \(expected "([^"]*)"\)`),
		allowed: []string{"Never", "Always", "Allow, on by default", "Allow, off by default"},
	},
	{
		code:    "ISSUE-503",
		what:    "approval behaviour",
		anchor:  "approvals are ",
		pattern: regexp.MustCompile(`approvals are (.*?) when a commit is added \(expected: ([^)]*)\)`),
		allowed: []string{"kept", "removed for code owners", "all removed"},
	},
}

// enumClause is one such clause. key identifies it for the completeness check
// below, since one code can render more than one (ISSUE-506 renders two).
type enumClause struct {
	code    string
	what    string
	anchor  string
	pattern *regexp.Regexp // two groups: the actual value, then the expected one
	allowed []string
}

func (c enumClause) key() string { return c.code + " " + c.what }

// guidanceMarkers are the phrases rule 4 keeps out: a finding message states
// what is wrong, the control's Remediation states what to do about it.
var guidanceMarkers = []string{
	"should",
	"must ",
	"enable ",
	"mark it",
	"pin to",
	"instead",
	"migrate to",
	"restrict ",
}

// typographicGlyphs are the code points the repo bans everywhere (em dash, en
// dash, curly quotes). Written as Go escapes on purpose: this source file must
// not contain the literal characters it forbids.
var typographicGlyphs = []string{
	string(rune(0x2014)), // em dash
	string(rune(0x2013)), // en dash
	string(rune(0x2018)), // left single quotation mark
	string(rune(0x2019)), // right single quotation mark
	string(rune(0x201C)), // left double quotation mark
	string(rune(0x201D)), // right double quotation mark
}

var (
	backquotedSpan   = regexp.MustCompile("`[^`]*`")
	doubleQuotedSpan = regexp.MustCompile(`"[^"]*"`)
)

// messageTemplate blanks the parts of a message that are collector data
// rather than our prose, so rules 3 and 4 judge the sentence we wrote and not
// the script line, image reference or variable value interpolated into it. A
// fixture whose script line contains a semicolon, a dash or the word "should"
// is not a wording defect. Rules 1, 2 and 5 read the raw message: rule 5 in
// particular has to see inside the double quotes, since that is exactly where
// a raw enum value leaks ("merge method is \"ff\"").
func messageTemplate(msg string) string {
	return doubleQuotedSpan.ReplaceAllString(backquotedSpan.ReplaceAllString(msg, "`_`"), `"_"`)
}

// checkMessageStyle returns one line per rule the message breaks, empty when
// it reads the way the spec requires. Kept separate from the reporting so the
// rules themselves are unit-testable (TestMessageStyleChecker).
// checkSentenceStyle holds one user-facing sentence to the rules that do not
// need to know which finding it came from: rule 1 (it opens like a sentence),
// rule 2's empty-backquote half, rule 3 (punctuation) and rule 4 (no fix
// guidance). The message goes through it, and so does every element of a data
// array a reader reads (see dataArrayKinds): the ISSUE-505 detail lines are
// shown under the headline on the issues page, so "Force push is allowed
// (should be disabled)" is the same defect there as it would be in a message,
// and until the PR #484 re-review nothing said so.
func checkSentenceStyle(text string, report func(string, ...any)) {
	// Rule 1: a sentence, so it opens like one. Text that opens on a
	// backquoted token or on a shell variable is already naming its subject.
	first, _ := utf8.DecodeRuneInString(text)
	if !unicode.IsUpper(first) && first != '`' && first != '$' {
		report("rule 1: must start with a capital letter or a backquoted token")
	}

	// Rule 2's half that does not need to know the code: a backquoted span
	// holding nothing names nothing. It is what a helper renders when the
	// value it was handed is the empty string, and it is the regression two
	// helpers in this package exist to prevent (ISSUE-502's unnamed approval
	// rule, ISSUE-601's linkage with no path). Neither is reachable through
	// the per-code key check, which skips an empty value precisely because
	// most rules legitimately omit one: an empty value must make the sentence
	// change shape, never quote nothing.
	if strings.Contains(text, "``") {
		report("rule 2: carries an empty backquoted token (two consecutive backquotes); a helper quoted a value it does not have")
	}
	for _, span := range backquotedSpan.FindAllString(text, -1) {
		if inner := strings.Trim(span, "`"); inner != "" && strings.TrimSpace(inner) == "" {
			report("rule 2: backquotes a token that is only whitespace (%q)", span)
		}
	}

	template := messageTemplate(text)

	// Rule 3: no typographic glyph, no semicolon, no dash standing between
	// words. The repo bans the glyphs everywhere; the semicolon and the spaced
	// hyphen are what made the demo's messages read as three stapled fragments.
	for _, glyph := range typographicGlyphs {
		if strings.Contains(template, glyph) {
			report("rule 3: contains the typographic code point %U", []rune(glyph)[0])
		}
	}
	if strings.Contains(template, ";") {
		report("rule 3: contains a semicolon")
	}
	if strings.Contains(template, " - ") {
		report("rule 3: contains a spaced hyphen between words")
	}

	// Rule 4: describe the issue, do not prescribe the fix.
	lower := strings.ToLower(template)
	for _, marker := range guidanceMarkers {
		if strings.Contains(lower, marker) {
			report("rule 4: carries fix guidance (%q)", marker)
		}
	}
}

func checkMessageStyle(code, msg string, values map[string]string, arrays map[string][]string) []string {
	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if msg == "" {
		return []string{"the message is the empty string"}
	}

	checkSentenceStyle(msg, report)

	// Rule 2: every technical token the finding carries is quoted, so a reader
	// can tell the data from the prose around it.
	keys := gitLabMessageStyleKeys[code]
	for _, key := range keys {
		value := values[key]
		if value == "" {
			continue
		}
		if strings.Contains(msg, "`"+value+"`") {
			continue
		}
		// ISSUE-204 names its variable in the shell form it appears in.
		if code == "ISSUE-204" && key == "variableName" && strings.Contains(msg, "`$"+value+"`") {
			continue
		}
		report("rule 2: %s %q is not backquoted in the message", key, value)
	}

	// The prose a finding publishes outside its message: the issues page shows
	// these under the headline, so they are held to the same sentence rules.
	// An unclassified array is itself a failure, see dataArrayKinds.
	for _, key := range slices.Sorted(maps.Keys(arrays)) {
		prose, classified := dataArrayKinds[code+"."+key]
		if !classified {
			report("the string array %q is not classified in dataArrayKinds: say whether a reader reads it (prose, held to the sentence rules) or a consumer parses it (a machine contract, left alone)", key)
			continue
		}
		if !prose {
			continue
		}
		for _, element := range arrays[key] {
			if element == "" {
				report("data %s[]: the element is the empty string", key)
				continue
			}
			checkSentenceStyle(element, func(format string, args ...any) {
				report("data %s[] %q: %s", key, element, fmt.Sprintf(format, args...))
			})
		}
	}

	// Rule 5, the denylist half: no raw API enum value we already know of.
	for _, token := range apiOnlyTokens {
		if strings.Contains(msg, token) {
			report("rule 5: leaks the api-only token %q", token)
		}
	}

	// Rule 5, the allowlist half: where the message renders an enum, the text
	// has to be one of our labels, on both sides of the clause.
	for _, clause := range enumClauseAllowlists {
		if clause.code != code || !strings.Contains(msg, clause.anchor) {
			continue
		}
		groups := clause.pattern.FindStringSubmatch(msg)
		if groups == nil {
			report("rule 5: the %s clause does not render in the shape this lint can check (%s)", clause.what, clause.pattern)
			continue
		}
		for i, side := range []string{"actual", "expected"} {
			if !slices.Contains(clause.allowed, groups[i+1]) {
				report("rule 5: the %s %s value %q is not one of the labels %q; an unmapped GitLab enum reached the message", side, clause.what, groups[i+1], clause.allowed)
			}
		}
	}

	return problems
}

// messageValues projects the finding onto the key/value view rule 2 reads.
// `job` is a canonical field (the engine lifts it out of the rule's data), the
// rest are data keys; a non-string value is not a technical token and is
// skipped.
func messageValues(f opaengine.Finding) map[string]string {
	out := map[string]string{}
	if f.Job != "" {
		out["job"] = f.Job
	}
	for key, raw := range f.Data {
		if s, ok := raw.(string); ok {
			out[key] = s
		}
	}
	return out
}

// messageArrays projects the finding's string arrays, the other place a rule
// publishes text. Only an array whose elements are ALL strings counts: a list
// of lists (missingGroups) or of objects (overriddenJobs) carries no sentence,
// and an empty one carries nothing to judge.
func messageArrays(f opaengine.Finding) map[string][]string {
	out := map[string][]string{}
	for key, raw := range f.Data {
		list, ok := raw.([]any)
		if !ok || len(list) == 0 {
			continue
		}
		elements := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				elements = nil
				break
			}
			elements = append(elements, s)
		}
		if elements != nil {
			out[key] = elements
		}
	}
	return out
}

// seenMessage is one distinct message a GitLab rule rendered during the suite,
// kept with the finding values it was rendered from so a rule-2 failure can
// name the token that is missing.
type seenMessage struct {
	message string
	values  map[string]string
	arrays  map[string][]string
}

var (
	messageStyleMu   sync.Mutex
	messageStyleSeen = map[string]map[string]seenMessage{}
	// messageStyleCount counts emissions, not distinct messages: it is how the
	// report says how much evidence the verdict rests on, and it is what the
	// vacuity guard reads. A green lint that linted nothing is not a green
	// lint.
	messageStyleCount int
)

// recordMessageStyle is the second half of the FindingsObserver TestMain
// installs (recordEmissions is the first). Emissions are deduplicated per
// code: the corpus renders the same finding many times and the lint has
// nothing to add by reporting it twice.
//
// The key is the message AND the string arrays it arrived with, not the
// message alone. Two findings of one code can share a headline and differ
// entirely in the prose they publish beside it: ISSUE-505 renders
// "Branch `main` has non-compliant protection settings." both for a
// force-push violation and for an access-level one, so keying on the message
// dropped one of the two reason sets on the floor, unchecked and uncounted.
func recordMessageStyle(fs []opaengine.Finding) {
	messageStyleMu.Lock()
	defer messageStyleMu.Unlock()
	for _, f := range fs {
		if _, inScope := gitLabMessageStyleKeys[f.Code]; !inScope {
			continue
		}
		messageStyleCount++
		byEmission := messageStyleSeen[f.Code]
		if byEmission == nil {
			byEmission = map[string]seenMessage{}
			messageStyleSeen[f.Code] = byEmission
		}
		arrays := messageArrays(f)
		key := emissionKey(f.Message, arrays)
		if _, dup := byEmission[key]; dup {
			continue
		}
		byEmission[key] = seenMessage{message: f.Message, values: messageValues(f), arrays: arrays}
	}
}

// emissionKey identifies one distinct emission for deduplication: the message
// plus every string array it publishes, since those are separate text and two
// findings can share a message without sharing them.
func emissionKey(msg string, arrays map[string][]string) string {
	var b strings.Builder
	b.WriteString(msg)
	for _, key := range slices.Sorted(maps.Keys(arrays)) {
		b.WriteString("\x00")
		b.WriteString(key)
		for _, element := range arrays[key] {
			b.WriteString("\x00")
			b.WriteString(element)
		}
	}
	return b.String()
}

// verifyMessageStyle is the enforcement point, called from TestMain after
// m.Run for the same reason the identity harness is: the corpus that renders
// these messages is the whole package, so no single test function can see it.
// Returns a non-empty report when any message breaks a rule.
//
// completeness says whether the "every GitLab code was rendered at least once"
// check applies: it holds only for an unfiltered run, since `-run <pattern>`
// makes every unexercised code look unrendered, which is a property of the
// invocation and not of the policies. It also gates the vacuity guard: a
// filtered run is allowed to exercise no GitLab rule at all, a full one is not.
func verifyMessageStyle(completeness bool) string {
	messageStyleMu.Lock()
	defer messageStyleMu.Unlock()
	var b strings.Builder

	// Vacuity guard. Every assertion below is over what the corpus rendered, so
	// an empty corpus makes the whole lint pass while proving nothing: a
	// refactor that stopped feeding the observer, or an early failure that cut
	// the run short, would read as "the wording contract holds". Say so instead.
	if completeness && (messageStyleCount == 0 || len(messageStyleSeen) == 0) {
		return fmt.Sprintf("the message lint asserted nothing: %d emissions across %d codes reached it on a full run; the observer in TestMain is not feeding it\n",
			messageStyleCount, len(messageStyleSeen))
	}

	codes := make([]string, 0, len(messageStyleSeen))
	for code := range messageStyleSeen {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	// renderedClauses tallies which enum clauses the corpus actually produced,
	// keyed the way enumClauseAllowlists identifies them.
	renderedClauses := map[string]bool{}
	// renderedBranches is the same tally for the manifest of every rewritten
	// message branch; see messageBranches.
	renderedBranches := map[string]bool{}
	for _, code := range codes {
		keys := make([]string, 0, len(messageStyleSeen[code]))
		for key := range messageStyleSeen[code] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			seen := messageStyleSeen[code][key]
			msg := seen.message
			for _, problem := range checkMessageStyle(code, msg, seen.values, seen.arrays) {
				fmt.Fprintf(&b, "%s: %s\n  message: %q\n", code, problem, msg)
			}
			for _, clause := range enumClauseAllowlists {
				if clause.code == code && strings.Contains(msg, clause.anchor) {
					renderedClauses[clause.key()] = true
				}
			}
			for _, branch := range messageBranches {
				if branch.code != code {
					continue
				}
				if strings.Contains(msg, branch.marker) {
					renderedBranches[branch.key()] = true
					continue
				}
				for _, elements := range seen.arrays {
					for _, element := range elements {
						if strings.Contains(element, branch.marker) {
							renderedBranches[branch.key()] = true
						}
					}
				}
			}
		}
	}

	if completeness {
		var unrendered []string
		for code := range gitLabMessageStyleKeys {
			if len(messageStyleSeen[code]) == 0 {
				unrendered = append(unrendered, code)
			}
		}
		sort.Strings(unrendered)
		for _, code := range unrendered {
			fmt.Fprintf(&b, "%s: in scope of the message lint but no test in this package rendered a message for it; add a fixture that emits it\n", code)
		}

		// A code being rendered is not enough: an allowlisted clause the corpus
		// never produces is an allowlist that asserts nothing. ISSUE-506 was
		// rendered from its first release of this lint, but only ever through
		// its merge-method clause, so the squash labels went unchecked
		// (PR #484 review). Requiring each clause closes that by construction:
		// a new entry in enumClauseAllowlists is red until a fixture renders it.
		for _, clause := range enumClauseAllowlists {
			if !renderedClauses[clause.key()] {
				fmt.Fprintf(&b, "%s: no message in the corpus rendered the %s clause (%q), so its label allowlist asserted nothing; add a fixture that makes that setting deviate\n",
					clause.code, clause.what, clause.anchor)
			}
		}

		// The manifest: a branch nobody renders is a branch nobody checks.
		for _, branch := range messageBranches {
			if branch.unreachable != "" || renderedBranches[branch.key()] {
				continue
			}
			fmt.Fprintf(&b, "%s: no message or data array in the corpus rendered the %s branch (%q), so its wording is held to none of these rules; add a fixture that produces it, or mark it unreachable in messageBranches with the argument for why\n",
				branch.code, branch.what, branch.marker)
		}
	}
	if b.Len() > 0 {
		fmt.Fprintf(&b, "(%d finding emissions across %d GitLab codes were linted)\n",
			messageStyleCount, len(messageStyleSeen))
	}
	return b.String()
}

// gitLabIssueCodes is the authoritative scope: every issue code whose control
// is registered for the GitLab provider. Read from the registry rather than
// hand-listed, so the scope follows the catalog.
func gitLabIssueCodes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, info := range control.AllCodes() {
		meta, ok := configuration.ControlMetaFor(info.ControlName)
		if !ok {
			t.Fatalf("%s: control %q has no registry entry", info.Code, info.ControlName)
		}
		for _, provider := range meta.Providers {
			if provider == configuration.ProviderGitLab {
				out = append(out, string(info.Code))
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestMessageStyleChecker is the lint's own red/green test: it pins what each
// rule accepts and rejects, so the checker cannot quietly stop asserting while
// the corpus keeps passing. The offending samples are the real v0.5.5 messages
// the 2026-09-22 review flagged.
func TestMessageStyleChecker(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		message  string
		values   map[string]string
		arrays   map[string][]string
		wantRule string // the substring of the expected problem; empty = must pass
	}{
		{
			name:    "the spec text for the root variables form passes",
			code:    "ISSUE-205",
			message: "The root `variables:` keyword of the CI configuration overrides the controlled variable `SAST_DISABLED` with \"true\".",
			values:  map[string]string{"variableName": "SAST_DISABLED", "value": "true"},
		},
		{
			name:     "the v0.5.5 root form leaves the variable unquoted and opens on no sentence",
			code:     "ISSUE-205",
			message:  "SAST_DISABLED = \"true\" (global variables)",
			values:   map[string]string{"variableName": "SAST_DISABLED"},
			wantRule: "rule 2",
		},
		{
			name:     "a lower-case opening is rule 1",
			code:     "ISSUE-501",
			message:  "branch `main` is not protected.",
			values:   map[string]string{"branchName": "main"},
			wantRule: "rule 1",
		},
		{
			name:     "an em dash is rule 3",
			code:     "ISSUE-504",
			message:  "No merge request approval rule applies to all protected branches " + string(rune(0x2014)) + " a branch can be merged unreviewed.",
			wantRule: "rule 3",
		},
		{
			name:     "a semicolon is rule 3",
			code:     "ISSUE-413",
			message:  "Job `build` runs Docker-in-Docker with an insecure daemon: TLS is off; the port is 2375.",
			values:   map[string]string{"job": "build"},
			wantRule: "rule 3",
		},
		{
			name:     "fix guidance is rule 4",
			code:     "ISSUE-202",
			message:  "The CI/CD settings variable `TOKEN` is not masked and should be masked.",
			values:   map[string]string{"variableName": "TOKEN"},
			wantRule: "rule 4",
		},
		{
			name:     "a raw enum value is rule 5",
			code:     "ISSUE-506",
			message:  "Merge request settings do not match the policy: merge method is merge (expected ff).",
			wantRule: "rule 5",
		},
		{
			name:    "a script line carrying a semicolon and a dash is data, not prose",
			code:    "ISSUE-411",
			message: "Job `deploy` runs a script fetched from the network: `curl -sSL https://x.sh | bash; echo done`.",
			values:  map[string]string{"job": "deploy"},
		},
		{
			name:    "ISSUE-204 may name its variable in the shell form",
			code:    "ISSUE-204",
			message: "Job `build` expands `$CI_COMMIT_MESSAGE` in a script line: `eval $CI_COMMIT_MESSAGE`.",
			values:  map[string]string{"job": "build", "variableName": "CI_COMMIT_MESSAGE"},
		},
		{
			name:    "the ISSUE-506 labels we chose pass on both sides",
			code:    "ISSUE-506",
			message: `Merge request settings do not match the policy: Merge method is "Merge commit" (expected "Fast-forward merge"), Squash is "Allow, off by default" (expected "Never"), Merge trains are disabled (expected enabled).`,
		},
		{
			name: "a merge method GitLab adds later is caught on the actual side",
			code: "ISSUE-506",
			// The value the API serves is never seen by config validation, and
			// the rule renders an unmapped token verbatim. No denylist entry
			// matches "semi_linear": the allowlist is what catches it.
			message:  `Merge request settings do not match the policy: Merge method is "semi_linear" (expected "Fast-forward merge").`,
			wantRule: "rule 5",
		},
		{
			name:     "an unmapped squash option is caught on the expected side too",
			code:     "ISSUE-506",
			message:  `Merge request settings do not match the policy: Squash is "Never" (expected "default_off").`,
			wantRule: "rule 5",
		},
		{
			name:     "a clause that stops rendering in the checkable shape is caught",
			code:     "ISSUE-506",
			message:  `Merge request settings do not match the policy: Merge method is Merge commit, wanted Fast-forward merge.`,
			wantRule: "rule 5",
		},
		{
			name:     "an empty backquoted token is caught whatever the code",
			code:     "ISSUE-601",
			message:  "The linked GitLab security policy project (id `5`, path ``) is not the expected one (expected id `9`).",
			wantRule: "rule 2",
		},
		{
			name:     "a backquoted token that is only whitespace is caught too",
			code:     "ISSUE-501",
			message:  "Branch ` ` is not protected.",
			values:   map[string]string{"branchName": " "},
			wantRule: "rule 2",
		},
		{
			name:    "the ISSUE-503 ladder labels pass",
			code:    "ISSUE-503",
			message: "Merge request approval settings do not match the policy: approvals are kept when a commit is added (expected: removed for code owners).",
		},
		{
			name:    "the ISSUE-505 reasons pass as sentences",
			code:    "ISSUE-505",
			message: "Branch `main` has non-compliant protection settings.",
			values:  map[string]string{"branchName": "main"},
			arrays: map[string][]string{
				"reasons": {"Force push is allowed", "Code owner approval is not required"},
			},
		},
		{
			name:    "fix guidance in a reasons element is caught, though the message is clean",
			code:    "ISSUE-505",
			message: "Branch `main` has non-compliant protection settings.",
			values:  map[string]string{"branchName": "main"},
			// The wording this review removed from branch_non_compliant.rego.
			// The message says nothing about it, which is why only reading the
			// message let it through for as long as it did.
			arrays: map[string][]string{
				"reasons": {"Force push is allowed (should be disabled)"},
			},
			wantRule: "rule 4",
		},
		{
			name:    "a lower-case reasons element is caught",
			code:    "ISSUE-505",
			message: "Branch `main` has non-compliant protection settings.",
			values:  map[string]string{"branchName": "main"},
			arrays: map[string][]string{
				"reasons": {"force push is allowed"},
			},
			wantRule: "rule 1",
		},
		{
			name:    "a machine-contract array is left alone",
			code:    "ISSUE-506",
			message: `Merge request settings do not match the policy: Merge method is "Merge commit" (expected "Fast-forward merge").`,
			// Config key names, not prose: they must not be asked for a capital.
			arrays: map[string][]string{
				"deviatingSettings": {"mergeMethod", "mergeTrainsEnabled"},
			},
		},
		{
			name:    "an unclassified string array is itself a failure",
			code:    "ISSUE-505",
			message: "Branch `main` has non-compliant protection settings.",
			values:  map[string]string{"branchName": "main"},
			arrays: map[string][]string{
				"someNewList": {"whatever this is"},
			},
			wantRule: "not classified in dataArrayKinds",
		},
		{
			name:     "an unmapped approval rung is caught",
			code:     "ISSUE-503",
			message:  "Merge request approval settings do not match the policy: approvals are kept when a commit is added (expected: remove_everything).",
			wantRule: "rule 5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := checkMessageStyle(tc.code, tc.message, tc.values, tc.arrays)
			joined := strings.Join(problems, " | ")
			if tc.wantRule == "" {
				if len(problems) > 0 {
					t.Errorf("expected a clean message, got: %s", joined)
				}
				return
			}
			if !strings.Contains(joined, tc.wantRule) {
				t.Errorf("expected a %s failure, got: %s", tc.wantRule, joined)
			}
		})
	}
}

// TestIssue506LabelsMatchTheManifest keeps issue506SubjectLabels honest against
// the rule it describes: the keys must be exactly the _labels map's, and each
// subject must be the string the rule renders.
//
// Without it the manifest could drift into a comfortable fiction. A ninth
// setting added to mr_settings_compliant.rego would render a subject nothing
// here asks about, and the render check would pass by simply not knowing the
// key existed. This test fails instead, which forces the key into
// issue506SubjectLabels and messageBranches, which in turn forces a fixture
// that renders it (PR #484 re-review, the fourth report of that same class).
func TestIssue506LabelsMatchTheManifest(t *testing.T) {
	source, err := policies.FS.ReadFile("mr_settings_compliant.rego")
	if err != nil {
		t.Fatalf("read the rule: %v", err)
	}
	labels := regoStringMapEntries(t, string(source), "_labels")
	if len(labels) == 0 {
		t.Fatal("no _labels entries parsed: the map moved or changed shape, and this test is now asserting nothing")
	}
	for key, subject := range labels {
		want, known := issue506SubjectLabels[key]
		if !known {
			t.Errorf("mr_settings_compliant.rego names the setting %q, which issue506SubjectLabels does not: add it there and to messageBranches, then add a fixture that makes it deviate", key)
			continue
		}
		if want != subject {
			t.Errorf("setting %q renders as %q, the manifest says %q", key, subject, want)
		}
	}
	for key := range issue506SubjectLabels {
		if _, ok := labels[key]; !ok {
			t.Errorf("issue506SubjectLabels names the setting %q, which the rule no longer does", key)
		}
	}
	// Every subject is also a manifest entry, so the corpus has to render it.
	for key, subject := range issue506SubjectLabels {
		found := false
		for _, branch := range messageBranches {
			if branch.code == "ISSUE-506" && strings.Contains(subject, branch.marker) {
				found = true
				break
			}
			if branch.code == "ISSUE-506" && strings.Contains(branch.marker, subject) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the subject of %q (%q) is in no messageBranches entry, so nothing requires the corpus to render it", key, subject)
		}
	}
}

// regoStringMapEntries pulls the `"key": "value",` pairs out of a top-level
// Rego string map. Deliberately textual: loading and evaluating the module to
// read one constant would make the test depend on the evaluator it is meant to
// check the source of. Mirrors extractRegoUnsafePatterns in rules_test.go.
func regoStringMapEntries(t *testing.T, source, name string) map[string]string {
	t.Helper()
	start := strings.Index(source, name+" := {")
	if start < 0 {
		return nil
	}
	end := strings.Index(source[start:], "\n}")
	if end < 0 {
		t.Fatalf("%s: no closing brace found", name)
	}
	out := map[string]string{}
	entry := regexp.MustCompile(`"([^"]+)":\s*"([^"]*)"`)
	for _, m := range entry.FindAllStringSubmatch(source[start:start+end], -1) {
		out[m[1]] = m[2]
	}
	return out
}

// TestMessageStyleScopeIsComplete pins that the lint covers every issue code
// whose control applies to GitLab. Without it a new GitLab control could ship
// with an unreviewed message simply by not appearing in the map above.
func TestMessageStyleScopeIsComplete(t *testing.T) {
	for _, code := range gitLabIssueCodes(t) {
		if _, ok := gitLabMessageStyleKeys[code]; !ok {
			t.Errorf("%s: its control applies to GitLab but the message lint does not cover it; add its data keys to gitLabMessageStyleKeys", code)
		}
	}
	for code := range gitLabMessageStyleKeys {
		found := false
		for _, gitLab := range gitLabIssueCodes(t) {
			if gitLab == code {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: listed in the message lint but its control does not apply to GitLab", code)
		}
	}
}
