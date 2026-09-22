package policies_test

import (
	"fmt"
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
func checkMessageStyle(code, msg string, values map[string]string) []string {
	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if msg == "" {
		return []string{"the message is the empty string"}
	}

	// Rule 1: a sentence, so it opens like one. A message that opens on a
	// backquoted token or on a shell variable is already naming its subject.
	first, _ := utf8.DecodeRuneInString(msg)
	if !unicode.IsUpper(first) && first != '`' && first != '$' {
		report("rule 1: must start with a capital letter or a backquoted token")
	}

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

	// Rule 2's other half, and the one that does not need to know the code: a
	// backquoted span holding nothing names nothing. It is what a helper
	// renders when the value it was handed is the empty string, and it is the
	// regression two helpers in this package exist to prevent (ISSUE-502's
	// unnamed approval rule, ISSUE-601's linkage with no path). Neither is
	// reachable through the per-code key check above, which skips an empty
	// value precisely because most rules legitimately omit one: an empty
	// value must make the sentence change shape, never quote nothing.
	// Generalised from the PR #484 review so any future helper that regresses
	// this way fails the corpus lint rather than one hand-written assertion.
	if strings.Contains(msg, "``") {
		report("rule 2: the message carries an empty backquoted token (two consecutive backquotes); a helper quoted a value it does not have")
	}
	for _, span := range backquotedSpan.FindAllString(msg, -1) {
		if inner := strings.Trim(span, "`"); inner != "" && strings.TrimSpace(inner) == "" {
			report("rule 2: the message backquotes a token that is only whitespace (%q)", span)
		}
	}

	template := messageTemplate(msg)

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

// seenMessage is one distinct message a GitLab rule rendered during the suite,
// kept with the finding values it was rendered from so a rule-2 failure can
// name the token that is missing.
type seenMessage struct {
	message string
	values  map[string]string
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
// installs (recordEmissions is the first). Messages are deduplicated per code:
// the corpus renders the same sentence many times and the lint has nothing to
// add by reporting it twice.
func recordMessageStyle(fs []opaengine.Finding) {
	messageStyleMu.Lock()
	defer messageStyleMu.Unlock()
	for _, f := range fs {
		if _, inScope := gitLabMessageStyleKeys[f.Code]; !inScope {
			continue
		}
		messageStyleCount++
		byMessage := messageStyleSeen[f.Code]
		if byMessage == nil {
			byMessage = map[string]seenMessage{}
			messageStyleSeen[f.Code] = byMessage
		}
		if _, dup := byMessage[f.Message]; dup {
			continue
		}
		byMessage[f.Message] = seenMessage{message: f.Message, values: messageValues(f)}
	}
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
	for _, code := range codes {
		messages := make([]string, 0, len(messageStyleSeen[code]))
		for msg := range messageStyleSeen[code] {
			messages = append(messages, msg)
		}
		sort.Strings(messages)
		for _, msg := range messages {
			seen := messageStyleSeen[code][msg]
			for _, problem := range checkMessageStyle(code, msg, seen.values) {
				fmt.Fprintf(&b, "%s: %s\n  message: %q\n", code, problem, msg)
			}
			for _, clause := range enumClauseAllowlists {
				if clause.code == code && strings.Contains(msg, clause.anchor) {
					renderedClauses[clause.key()] = true
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
			name:     "an unmapped approval rung is caught",
			code:     "ISSUE-503",
			message:  "Merge request approval settings do not match the policy: approvals are kept when a commit is added (expected: remove_everything).",
			wantRule: "rule 5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := checkMessageStyle(tc.code, tc.message, tc.values)
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
