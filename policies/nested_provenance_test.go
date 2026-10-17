package policies_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

const wrapperRef = "acme/wrapper@0123456789abcdef0123456789abcdef01234567"

func evalNested(t *testing.T, p *ir.NormalizedPipeline, cfg map[string]any) []opaengine.Finding {
	t.Helper()
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	fs, err := evaluateStrict(engine, context.Background(), p, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return fs
}

// oneNested is a job whose only step is the SHA-pinned wrapper, which
// pulls in uses (the shape of spec 2026-10-16 section 3.1).
func oneNested(uses, comment string, meta *ir.ActionMetadata) *ir.NormalizedPipeline {
	return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{{
		Name: "ci/build", OriginFile: ".github/workflows/ci.yml", Triggers: []string{"push"},
		Uses: []ir.Action{
			{Uses: wrapperRef, Line: 12},
			{Uses: uses, Line: 12, Comment: comment, Metadata: meta, Nested: true, Via: []string{wrapperRef}, DefinedIn: wrapperRef + ":action.yml:9"},
		},
	}}}
}

// nestUnder turns a parsed fixture into the same workflow wrapped in one
// composite: every step nested under the wrapper at the wrapper's line,
// keeping its own line in definedIn.
func nestUnder(t *testing.T, fixture string) *ir.NormalizedPipeline {
	t.Helper()
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	p := parseGitHubActions(t, data)
	p.ProjectPath = "acme/app"
	for i := range p.Jobs {
		j := &p.Jobs[i]
		out := []ir.Action{{Uses: wrapperRef, Line: 1}}
		for _, u := range j.Uses {
			u.DefinedIn = wrapperRef + ":action.yml:" + strconv.Itoa(u.Line)
			u.Line, u.Nested, u.Via = 1, true, []string{wrapperRef}
			out = append(out, u)
		}
		j.Uses = out
	}
	return p
}

var (
	shaA = strings.Repeat("a", 40)
	shaB = strings.Repeat("b", 40)
	shaC = strings.Repeat("c", 40)
)

// TestNestedProvenance_EveryUsesKeyedRule pins spec sections 5 and 6: each
// uses-keyed rule fires on a nested entry (R5: the rule's own severity,
// unchanged), copies nested, via and definedIn into the finding data, and
// renders the chain clause in the message.
func TestNestedProvenance_EveryUsesKeyedRule(t *testing.T) {
	pin := map[string]any{"actionsMustBePinnedByCommitSha": map[string]any{"trustedOwners": []any{"actions", "github"}}}
	sources := map[string]any{"githubActionMustComeFromAuthorizedSources": map[string]any{"trustGithubOfficialActions": true, "trustSameOrgActions": true, "minimumStars": 0}}
	fixture := func(parts ...string) func(*testing.T) *ir.NormalizedPipeline {
		return func(t *testing.T) *ir.NormalizedPipeline {
			return nestUnder(t, filepath.Join(append([]string{"testdata"}, parts...)...))
		}
	}
	meta := func(uses, comment string, m *ir.ActionMetadata) func(*testing.T) *ir.NormalizedPipeline {
		return func(*testing.T) *ir.NormalizedPipeline { return oneNested(uses, comment, m) }
	}
	cases := []struct {
		code, uses string // uses "" matches the code's finding on any entry (fixture cases)
		cfg        map[string]any
		pipeline   func(*testing.T) *ir.NormalizedPipeline
	}{
		{"ISSUE-701", "evil/e@main", pin, meta("evil/e@main", "", nil)},
		{"ISSUE-713", "evil/e@main", sources, meta("evil/e@main", "", nil)},
		{"ISSUE-702", "evil/e@" + shaA, nil, meta("evil/e@"+shaA, "", &ir.ActionMetadata{RepoArchived: true})},
		{"ISSUE-703", "evil/e@" + shaA, nil, meta("evil/e@"+shaA, "", &ir.ActionMetadata{Advisories: []string{"GHSA-aaaa-bbbb-cccc"}})},
		{"ISSUE-707", "evil/e@" + shaA, nil, meta("evil/e@"+shaA, "", &ir.ActionMetadata{RefKnownAbsent: true})},
		{"ISSUE-708", "evil/e@v3", nil, meta("evil/e@v3", "v4.0.0", &ir.ActionMetadata{RefKind: "tag"})},
		{"ISSUE-709", "evil/e@" + shaB, nil, meta("evil/e@"+shaB, "", &ir.ActionMetadata{LatestReleaseSha: shaC, LatestTag: "v9"})},
		{"ISSUE-402", "evil/e@main", nil, meta("evil/e@main", "", &ir.ActionMetadata{RefIsAmbiguous: true})},
		{"ISSUE-711", "mikefarah/yq-action@v4", nil, meta("mikefarah/yq-action@v4", "", nil)},
		{"ISSUE-714", "evil/e@" + shaA, nil, meta("evil/e@"+shaA, "", &ir.ActionMetadata{MutableRemoteExec: &ir.MutableRemoteExec{Tier: "exec", URL: "https://raw.githubusercontent.com/evil/tool/main/install.sh"}})},
		{"ISSUE-715", "evil/e@" + shaA, nil, meta("evil/e@"+shaA, "", &ir.ActionMetadata{MutableRemoteExec: &ir.MutableRemoteExec{Tier: "obfuscated", URL: "https://x.example/p"}})},
		{"ISSUE-716", "evil/e@" + shaA, nil, meta("evil/e@"+shaA, "", &ir.ActionMetadata{MutableRemoteExec: &ir.MutableRemoteExec{Tier: "unverified", File: "action.yml"}})},
		{"ISSUE-307", "", nil, fixture("ISSUE-307", "github", "low_persisted_no_upload.yml")},
		{"ISSUE-310", "", nil, fixture("ISSUE-307", "github", "violation_default_checkout.yml")},
		{"ISSUE-804", "", nil, fixture("ISSUE-804", "github", "violation_head_ref.yml")},
		{"ISSUE-421", "", nil, fixture("ISSUE-421", "github", "violation_pypi_static.yml")},
		{"ISSUE-306", "", nil, fixture("ISSUE-306", "github", "violation_skip_revoke.yml")},
		{"ISSUE-419", "", nil, fixture("ISSUE-419", "github", "violation_dot.yml")},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			var hit *opaengine.Finding
			fs := evalNested(t, tc.pipeline(t), tc.cfg)
			for i := range fs {
				uses, _ := fs[i].Data["uses"].(string)
				if fs[i].Code == tc.code && (tc.uses == "" || uses == tc.uses) {
					hit = &fs[i]
				}
			}
			if hit == nil {
				t.Fatalf("%s must fire on the nested entry", tc.code)
			}
			if hit.Data["nested"] != true {
				t.Errorf("data.nested = %v", hit.Data["nested"])
			}
			via, _ := hit.Data["via"].([]any)
			if len(via) != 1 || via[0] != wrapperRef {
				t.Errorf("data.via = %v", hit.Data["via"])
			}
			if d, _ := hit.Data["definedIn"].(string); !strings.HasPrefix(d, wrapperRef+":action.yml:") {
				t.Errorf("data.definedIn = %v", hit.Data["definedIn"])
			}
			if !strings.Contains(hit.Message, ", pulled in via "+wrapperRef) {
				t.Errorf("message lacks the chain clause: %q", hit.Message)
			}
		})
	}
}

// TestNestedProvenance_ClausePlacement pins spec section 6, ruling 3
// (review of PR 549): a message with a consequence dash (ISSUE-702) takes
// the chain clause immediately before the dash, a message that ends a
// sentence (ISSUE-402) takes it before its final period, a message ending
// otherwise (ISSUE-707, a closing parenthesis) takes it at the very end.
// The nested message is the direct one with the clause inserted, nothing
// else changed.
func TestNestedProvenance_ClausePlacement(t *testing.T) {
	clause := ", pulled in via " + wrapperRef
	dash := " \u2014 "
	cases := []struct {
		code, uses, ending string
		meta               *ir.ActionMetadata
		place              func(direct string) string
	}{
		{"ISSUE-402", "evil/e@main", ".", &ir.ActionMetadata{RefIsAmbiguous: true}, func(d string) string { return strings.TrimSuffix(d, ".") + clause + "." }},
		{"ISSUE-707", "evil/e@" + shaA, ")", &ir.ActionMetadata{RefKnownAbsent: true}, func(d string) string { return d + clause }},
		{"ISSUE-702", "evil/e@" + shaA, "", &ir.ActionMetadata{RepoArchived: true}, func(d string) string { return strings.Replace(d, dash, clause+dash, 1) }},
	}
	message := func(t *testing.T, p *ir.NormalizedPipeline, code, uses string) string {
		t.Helper()
		for _, f := range evalNested(t, p, nil) {
			if u, _ := f.Data["uses"].(string); f.Code == code && u == uses {
				return f.Message
			}
		}
		t.Fatalf("%s must fire on %s", code, uses)
		return ""
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			nestedP := oneNested(tc.uses, "", tc.meta)
			directP := oneNested(tc.uses, "", tc.meta)
			e := &directP.Jobs[0].Uses[1]
			e.Nested, e.Via, e.DefinedIn = false, nil, ""
			direct := message(t, directP, tc.code, tc.uses)
			if tc.ending == "" {
				if !strings.Contains(direct, dash) {
					t.Fatalf("the case needs a direct message with a consequence dash, got %q", direct)
				}
			} else if !strings.HasSuffix(direct, tc.ending) || strings.Contains(direct, dash) {
				t.Fatalf("the case needs a direct message ending in %q without a consequence dash, got %q", tc.ending, direct)
			}
			if got, want := message(t, nestedP, tc.code, tc.uses), tc.place(direct); got != want {
				t.Errorf("nested message:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// TestNestedProvenance_ClauseBeforeTheLastDash pins the review of PR 549
// (finding 4297763494): ISSUE-708 quotes the user's comment before its
// consequence dash, and a comment holding the same dash stays intact, the
// chain clause going before the last dash, the consequence separator.
func TestNestedProvenance_ClauseBeforeTheLastDash(t *testing.T) {
	dash := " \u2014 "
	comment := "v1" + dash + "internal"
	uses := "evil/e@" + shaA
	meta := func() *ir.ActionMetadata { return &ir.ActionMetadata{CommentVersion: "v1", CommentTagSha: shaB} }
	for _, f := range evalNested(t, oneNested(uses, comment, meta()), nil) {
		if u, _ := f.Data["uses"].(string); f.Code != "ISSUE-708" || u != uses {
			continue
		}
		at := strings.LastIndex(f.Message, dash)
		if !strings.Contains(f.Message, strconv.Quote(comment)) || at < 0 || !strings.HasSuffix(f.Message[:at], ", pulled in via "+wrapperRef) {
			t.Fatalf("message = %q, want the comment intact and the clause before the last dash", f.Message)
		}
		return
	}
	t.Fatal("ISSUE-708 must fire on the nested entry")
}

// TestNestedExemptions_BindToTheEntrysOwnReference pins spec section 5 and
// R4: a trusted composite is exempt itself while its third-party child is
// judged, a `./x` nested in a remote container is the scanned
// repository's own code (plan ruling 14, the runner's workspace rule), and
// the scanned repository's own actions stay exempt wherever they appear.
func TestNestedExemptions_BindToTheEntrysOwnReference(t *testing.T) {
	trusted := "github/codeql-action/init@v3"
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{{
		Name: "ci/build", OriginFile: ".github/workflows/ci.yml",
		Uses: []ir.Action{
			{Uses: trusted, Line: 5},
			{Uses: "third-party/x@main", Line: 5, Nested: true, Via: []string{trusted}, DefinedIn: "github/codeql-action@v3:init/action.yml:20"},
			{Uses: "./.github/actions/setup", Line: 5, Nested: true, Via: []string{trusted, "third-party/x@main"}, DefinedIn: "third-party/x@main:action.yml:8"},
			{Uses: "acme/app/.github/actions/own@main", Line: 5, Nested: true, Via: []string{trusted, "third-party/x@main"}, DefinedIn: "third-party/x@main:action.yml:9"},
		},
	}}}
	cfg := map[string]any{
		"actionsMustBePinnedByCommitSha":            map[string]any{"trustedOwners": []any{"actions", "github"}},
		"githubActionMustComeFromAuthorizedSources": map[string]any{"trustGithubOfficialActions": true, "trustSameOrgActions": false, "minimumStars": 0},
	}
	fs := evalNested(t, p, cfg)
	for _, code := range []string{"ISSUE-701", "ISSUE-713"} {
		var got []string
		for _, f := range fs {
			if f.Code == code {
				uses, _ := f.Data["uses"].(string)
				got = append(got, uses)
			}
		}
		if len(got) != 1 || got[0] != "third-party/x@main" {
			t.Errorf("%s: got %v, want only the third-party child", code, got)
		}
	}
}

// TestNestedCountingRules_SeeWrappedActions pins spec section 5: a
// required, scanning or signing action inside a composite counts (417,
// 904, 712), and a static-token publish inside a composite is now seen
// (421). Each case is checked against the same job without the nested
// entry, so the change is the nested entry's doing.
func TestNestedCountingRules_SeeWrappedActions(t *testing.T) {
	job := func(trigger, direct string, nested ...ir.Action) *ir.NormalizedPipeline {
		uses := []ir.Action{{Uses: direct, Line: 4}}
		for _, n := range nested {
			n.Line, n.Nested, n.Via, n.DefinedIn = 4, true, []string{direct}, direct+":action.yml:8"
			uses = append(uses, n)
		}
		return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{{
			Name: "ci/release", OriginFile: ".github/workflows/ci.yml", Triggers: []string{trigger}, Uses: uses,
		}}}
	}
	count := func(p *ir.NormalizedPipeline, cfg map[string]any, code string) int {
		n := 0
		for _, f := range evalNested(t, p, cfg) {
			if f.Code == code {
				n++
			}
		}
		return n
	}
	required := map[string]any{"workflowMustIncludeRequiredActions": map[string]any{"requiredGroups": []any{[]any{"acme/scanner"}}}}
	if count(job("push", wrapperRef), required, "ISSUE-417") != 1 || count(job("push", wrapperRef, ir.Action{Uses: "acme/scanner@v2"}), required, "ISSUE-417") != 0 {
		t.Error("ISSUE-417: a required action inside a composite must satisfy the group")
	}
	if count(job("push", wrapperRef), nil, "ISSUE-904") != 1 || count(job("push", wrapperRef, ir.Action{Uses: "github/codeql-action/analyze@v3"}), nil, "ISSUE-904") != 0 {
		t.Error("ISSUE-904: a scanner inside a composite must count")
	}
	if count(job("release", "softprops/action-gh-release@v2"), nil, "ISSUE-712") != 1 || count(job("release", "softprops/action-gh-release@v2", ir.Action{Uses: "sigstore/cosign-installer@v3"}), nil, "ISSUE-712") != 0 {
		t.Error("ISSUE-712: a signing action inside a composite must count")
	}
	publish := ir.Action{Uses: "pypa/gh-action-pypi-publish@v1", With: map[string]any{"password": "${{ secrets.PYPI_API_TOKEN }}"}}
	if count(job("release", wrapperRef), nil, "ISSUE-421") != 0 || count(job("release", wrapperRef, publish), nil, "ISSUE-421") != 1 {
		t.Error("ISSUE-421: a static-token publish inside a composite must be reported")
	}
}

// calledJobs is a scanned job calling a workflow of another repository,
// with the callee's one job appended as resolved (spec 3.2): nested, on
// the callee's file, its caller recorded with the caller's effective
// permissions.
func calledJobs(calleePerms, callerPerms any) *ir.NormalizedPipeline {
	const ref = "acme/shared/.github/workflows/build.yml@v1"
	return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{
		{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9, WorkflowName: "ci",
			WorkflowHasConcurrency: true, Permissions: callerPerms, ReusableWorkflowUses: ref},
		{Name: "ci/call/build", OriginFile: ref, OriginLine: 4, Nested: true, Via: []string{ref},
			Permissions: calleePerms, Callers: []ir.ReusableCaller{{Job: "ci/call", Permissions: callerPerms}}},
	}}
}

// TestNestedJobs_WorkflowHygieneIsNotTheScannedRepositorys pins spec
// section 5 (plan ruling 15): ISSUE-418 and ISSUE-422 judge the scanned
// repository's workflow files, never a called workflow of another
// repository, whose file is outside the repository (R9).
func TestNestedJobs_WorkflowHygieneIsNotTheScannedRepositorys(t *testing.T) {
	for _, f := range evalNested(t, calledJobs(map[string]any{"contents": "read"}, map[string]any{"contents": "read"}), nil) {
		if f.Code == "ISSUE-418" || f.Code == "ISSUE-422" {
			t.Errorf("%s on %s (%s): a callee without name or concurrency is not this repository's finding", f.Code, f.File, f.Message)
		}
	}
}

// TestNestedJobs_PermissionRulesSkipThem pins spec section 5 (plan
// rulings 15 and the Task 3 round): ISSUE-801 and ISSUE-803 skip a job of a
// workflow called in another repository. The calling job carries the
// token the callee runs with and is judged by its own 801 and 803, so a
// nested finding would duplicate it, or judge a file the user does not
// own. The caller's own findings are what they are without the callee.
func TestNestedJobs_PermissionRulesSkipThem(t *testing.T) {
	codes := func(p *ir.NormalizedPipeline, job string) []string {
		var out []string
		for _, f := range evalNested(t, p, nil) {
			if (f.Code == "ISSUE-801" || f.Code == "ISSUE-803") && f.Job == job {
				out = append(out, f.Code)
			}
		}
		return out
	}
	read := map[string]any{"contents": "read"}
	for _, tc := range []struct {
		name           string
		callee, caller any
	}{
		{"callee write-all, caller read-only", "write-all", read},
		{"callee without a block, caller read-only", nil, read},
		{"callee read-only, caller without a block", read, nil},
		{"callee write-all, caller write-all", "write-all", "write-all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := calledJobs(tc.callee, tc.caller)
			if got := codes(p, "ci/call/build"); len(got) != 0 {
				t.Errorf("the nested job has no permission finding of its own, got %v", got)
			}
			alone := calledJobs(tc.callee, tc.caller)
			alone.Jobs = alone.Jobs[:1]
			if got, want := codes(p, "ci/call"), codes(alone, "ci/call"); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("the caller's own findings = %v, want %v (as without the callee)", got, want)
			}
		})
	}
}

// TestNestedFindings_StayInsideTheRepository pins R9 on the reproduction's
// shape (a composite chain B > D > E and a call of another repository's
// workflow): every finding's file is the scanned repository's, and a
// nested finding's step is the container's step that holds it.
func TestNestedFindings_StayInsideTheRepository(t *testing.T) {
	const (
		b    = "thomasboni/nested-actions-b@main"
		d    = "thomasboni/nested-actions-d@main"
		call = "thomasboni/nested-actions-c/.github/workflows/build.yml@main"
	)
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "thomasboni/nested-actions-a", Jobs: []ir.Job{
		{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 20, ReusableWorkflowUses: call},
		{Name: "ci/call/build", OriginFile: call, OriginLine: 5, Nested: true, Via: []string{call},
			Callers: []ir.ReusableCaller{{Job: "ci/call"}},
			Uses: []ir.Action{{Uses: "evil/w@main", Name: "Callee step", Line: 20, Nested: true, Via: []string{call},
				DefinedIn: "thomasboni/nested-actions-c@main:.github/workflows/build.yml:9"}}},
		{Name: "ci/nested", OriginFile: ".github/workflows/ci.yml", OriginLine: 10, Uses: []ir.Action{
			{Uses: b, Name: "Use B", Line: 13},
			{Uses: d, Name: "Use D", Line: 13, Nested: true, Via: []string{b}, DefinedIn: b + ":action.yml:6"},
			{Uses: "thomasboni/nested-actions-e@main", Name: "Use E", Line: 13, Nested: true, Via: []string{b, d}, DefinedIn: d + ":action.yml:8"},
		}},
	}}
	cfg := map[string]any{
		"actionsMustBePinnedByCommitSha":            map[string]any{"trustedOwners": []any{"actions", "github"}},
		"githubActionMustComeFromAuthorizedSources": map[string]any{"trustGithubOfficialActions": true, "trustSameOrgActions": false, "minimumStars": 0},
	}
	steps := map[string]any{}
	for _, f := range evalNested(t, p, cfg) {
		if f.File != "" && !strings.HasPrefix(f.File, ".github/") {
			t.Errorf("%s on %q: file outside the repository", f.Code, f.File)
		}
		if f.Code == "ISSUE-701" {
			uses, _ := f.Data["uses"].(string)
			steps[uses] = f.Data["step"]
		}
	}
	want := map[string]any{b: "Use B", d: "Use D", "thomasboni/nested-actions-e@main": "Use E", "evil/w@main": "Callee step"}
	for uses, step := range want {
		if steps[uses] != step {
			t.Errorf("ISSUE-701 on %s: step = %v, want %q", uses, steps[uses], step)
		}
	}
}
