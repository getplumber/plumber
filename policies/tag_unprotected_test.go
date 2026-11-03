package policies_test

import (
	"context"
	"maps"
	"reflect"
	"sort"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// fullTagRule is a rule that blocks updates and deletions and restricts
// creation on the given include patterns.
func fullTagRule(include ...string) ir.TagProtectionRule {
	return ir.TagProtectionRule{
		ID: "1", Source: ir.TagRuleSourceRepositoryRuleset, Include: include,
		BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true,
	}
}

func evalTagFindings(t *testing.T, p *ir.NormalizedPipeline, cfg map[string]any) []opaengine.Finding {
	t.Helper()
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	if cfg == nil {
		cfg = map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{"v*"}}}
	}
	findings, err := evaluateStrict(engine, context.Background(), p, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	var out []opaengine.Finding
	for _, f := range findings {
		if f.Code == "ISSUE-510" {
			out = append(out, f)
		}
	}
	return out
}

// tagPatterns returns the flagged patterns, sorted.
func tagPatterns(findings []opaengine.Finding) []string {
	out := []string{}
	for _, f := range findings {
		out = append(out, f.Data["tagPattern"].(string))
	}
	sort.Strings(out)
	return out
}

func TestIssue507_TagProtection(t *testing.T) {
	gh := func(tp *ir.TagProtection, jobs ...ir.Job) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "o/r", TagProtection: tp, Jobs: jobs}
	}
	cases := []struct {
		name string
		p    *ir.NormalizedPipeline
		cfg  map[string]any
		want []string
	}{
		{
			name: "unprotected pattern with a matching tag is flagged",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}}),
			want: []string{"v*"},
		},
		{
			name: "a repository that never tagged stays quiet",
			p:    gh(&ir.TagProtection{Known: true}),
			want: []string{},
		},
		{
			name: "tags matching no pattern stay quiet",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"nightly", "latest"}}),
			want: []string{},
		},
		{
			name: "a trigger on a configured pattern puts it in use with no tag yet",
			p:    gh(&ir.TagProtection{Known: true}, ir.Job{Name: "release/publish", PushTags: []string{"v*"}}),
			want: []string{"v*"},
		},
		{
			name: "a trigger on a pattern that is not configured is never flagged",
			p:    gh(&ir.TagProtection{Known: true}, ir.Job{Name: "release/publish", PushTags: []string{"release-*"}}),
			want: []string{},
		},
		{
			name: "negated and expression trigger patterns put nothing in use",
			p:    gh(&ir.TagProtection{Known: true}, ir.Job{Name: "release/publish", PushTags: []string{"!v*", "${{ inputs.x }}"}}),
			want: []string{},
		},
		{
			name: "an inert job's trigger does not count",
			p:    gh(&ir.TagProtection{Known: true}, ir.Job{Name: "release/publish", PushTags: []string{"v*"}, Inert: "disabled"}),
			want: []string{},
		},
		{
			name: "refs/tags/ prefixes are stripped",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}, Rules: []ir.TagProtectionRule{fullTagRule("v*")}}, ir.Job{Name: "release/publish", PushTags: []string{"refs/tags/v*"}}),
			cfg:  map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{"refs/tags/v*"}}},
			want: []string{},
		},
		{
			name: "a refs/tags/ prefixed configured pattern is flagged under its stripped name",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}}),
			cfg:  map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{"refs/tags/v*"}}},
			want: []string{"v*"},
		},
		{
			name: "unknown protection abstains",
			p:    gh(&ir.TagProtection{Known: false, Tags: []string{"v1.0.0"}}),
			want: []string{},
		},
		{
			name: "no collection abstains",
			p:    gh(nil, ir.Job{Name: "release/publish", PushTags: []string{"v*"}}),
			want: []string{},
		},
		{
			name: "a full rule on the pattern protects it",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}, Rules: []ir.TagProtectionRule{fullTagRule("v*")}}),
			want: []string{},
		},
		{
			name: "an all-tags rule protects every pattern",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0", "release/2"}, Rules: []ir.TagProtectionRule{fullTagRule("**")}}, ir.Job{Name: "r/p", PushTags: []string{"release/*"}}),
			want: []string{},
		},
		{
			name: "a narrower rule does not cover the pattern",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}, Rules: []ir.TagProtectionRule{fullTagRule("v[0-9]*")}}),
			want: []string{"v*"},
		},
		{
			name: "an exclude leaving an existing tag open flags the pattern",
			p: gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0", "v1.1.0-rc1"}, Rules: []ir.TagProtectionRule{{
				ID: "1", Include: []string{"**"}, Exclude: []string{"*-rc*"},
				BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true,
			}}}),
			want: []string{"v*"},
		},
		{
			name: "protections layered across rules add up",
			p: gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}, Rules: []ir.TagProtectionRule{
				{ID: "1", Include: []string{"v*"}, BlocksUpdate: true, BlocksDeletion: true},
				{ID: "2", Include: []string{"**"}, RestrictsCreation: true},
			}}),
			want: []string{},
		},
		{
			name: "a GitLab protected tag translated to v** covers nested tags",
			p: &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: &ir.TagProtection{Known: true, Tags: []string{"v1/hotfix"}, Rules: []ir.TagProtectionRule{{
				ID: "v*", Source: ir.TagRuleSourceProtectedTag, Include: []string{"v**"},
				BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true,
			}}}},
			want: []string{},
		},
		{
			name: "creation left open passes when not required",
			p: gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}, Rules: []ir.TagProtectionRule{
				{ID: "1", Include: []string{"v*"}, BlocksUpdate: true, BlocksDeletion: true},
			}}),
			cfg:  map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{"v*"}, "requireCreationRestricted": false}},
			want: []string{},
		},
		{
			name: "creation left open is flagged by default",
			p: gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}, Rules: []ir.TagProtectionRule{
				{ID: "1", Include: []string{"v*"}, BlocksUpdate: true, BlocksDeletion: true},
			}}),
			want: []string{"v*"},
		},
		{
			name: "only configured patterns are flagged, never workflow ones",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0", "release-1"}}, ir.Job{Name: "a/x", PushTags: []string{"v*", "release-*"}}, ir.Job{Name: "b/y", PushTags: []string{"v[0-9]+.[0-9]+.[0-9]+"}}),
			want: []string{"v*"},
		},
		{
			name: "several configured patterns are each checked",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.0.0", "release-1"}, Rules: []ir.TagProtectionRule{fullTagRule("v*")}}),
			cfg:  map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{"v*", "release-*"}}},
			want: []string{"release-*"},
		},
		{
			// A configured pattern is a glob even when a workflow names the
			// same text: `+` is literal here, so it matches no tag.
			name: "a configured pattern is read as a glob, not a filter",
			p:    gh(&ir.TagProtection{Known: true, Tags: []string{"v1.2.3"}}),
			cfg:  map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{"v[0-9]+.[0-9]+.[0-9]+"}}},
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tagPatterns(evalTagFindings(t, tc.p, tc.cfg))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("flagged patterns = %v, want %v", got, tc.want)
			}
		})
	}
}

// The message names every missing protection when only some are, and the
// missingProtections tokens follow the fixed update, deletion, creation
// order a consumer can rely on.
func TestIssue507_MessageAndMissingProtections(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: &ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}}}
	f := evalTagFindings(t, p, nil)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if got := f[0].Message; got != "Tag pattern `v*` is not protected." {
		t.Errorf("message = %q", got)
	}
	if got := f[0].Data["missingProtections"]; !reflect.DeepEqual(got, []any{"update", "deletion", "creation"}) {
		t.Errorf("missingProtections = %v", got)
	}

	p.TagProtection.Rules = []ir.TagProtectionRule{{ID: "1", Include: []string{"v*"}, BlocksDeletion: true}}
	f = evalTagFindings(t, p, nil)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if got, want := f[0].Message, "Tag pattern `v*` is not fully protected, tag updates are not blocked and tag creation is not restricted."; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}
	if got := f[0].Data["missingProtections"]; !reflect.DeepEqual(got, []any{"update", "creation"}) {
		t.Errorf("missingProtections = %v", got)
	}

	p.TagProtection.Rules = []ir.TagProtectionRule{{ID: "1", Include: []string{"v*"}, BlocksUpdate: true, RestrictsCreation: true}}
	f = evalTagFindings(t, p, nil)
	if len(f) != 1 || f[0].Message != "Tag pattern `v*` is not fully protected, tag deletions are not blocked." {
		t.Fatalf("want the deletion clause alone, got %+v", f)
	}

	// With creation not required, missing update and deletion is the whole
	// requirement, so the short message applies.
	p.TagProtection.Rules = []ir.TagProtectionRule{{ID: "1", Include: []string{"v*"}, RestrictsCreation: true}}
	cfg := map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{"v*"}, "requireCreationRestricted": false}}
	f = evalTagFindings(t, p, cfg)
	if len(f) != 1 || f[0].Message != "Tag pattern `v*` is not protected." {
		t.Fatalf("want the short message, got %+v", f)
	}
}

// occurrenceSeverity is critical when a workflow runs on a tag push (the
// pattern's own trigger, a GitHub release, a GitLab tag pipeline) and high
// otherwise; the registered severity stays critical.
func TestIssue507_OccurrenceSeverity(t *testing.T) {
	tp := func() *ir.TagProtection { return &ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}} }
	cases := []struct {
		name string
		p    *ir.NormalizedPipeline
		want string
	}{
		{"untriggered", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: tp()}, "high"},
		{"GitHub push tags on the pattern", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: tp(), Jobs: []ir.Job{{Name: "r/p", PushTags: []string{"v*"}}}}, "critical"},
		// The trigger pattern itself is protected, so only v* is flagged: it
		// shares the tag v1.0.0 with the trigger, which makes it critical.
		{"GitHub push tags overlapping through a tag", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: &ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}, Rules: []ir.TagProtectionRule{fullTagRule("v[0-9]*")}}, Jobs: []ir.Job{{Name: "r/p", PushTags: []string{"v[0-9]*"}}}}, "critical"},
		// The v*.* rule covers the trigger, not v*; v* is critical because
		// the quantified trigger fires on its tag v1.0.0.
		{"GitHub filter quantifiers overlapping through a tag", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: &ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}, Rules: []ir.TagProtectionRule{fullTagRule("v*.*")}}, Jobs: []ir.Job{{Name: "r/p", PushTags: []string{"v[0-9]+.[0-9]+.[0-9]+"}}}}, "critical"},
		{"GitHub release trigger", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: tp(), Jobs: []ir.Job{{Name: "r/p", Triggers: []string{"release"}}}}, "critical"},
		{"inert release job", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: tp(), Jobs: []ir.Job{{Name: "r/p", Triggers: []string{"release"}, Inert: "disabled"}}}, "high"},
		{"GitHub push tags-ignore", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: tp(), Jobs: []ir.Job{{Name: "r/p", Triggers: []string{"push"}, PushTagsIgnore: []string{"*-rc*"}}}}, "critical"},
		{"inert push tags-ignore job", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: tp(), Jobs: []ir.Job{{Name: "r/p", Triggers: []string{"push"}, PushTagsIgnore: []string{"*-rc*"}, Inert: "disabled"}}}, "high"},
		{"GitHub bare push", &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: tp(), Jobs: []ir.Job{{Name: "r/p", Triggers: []string{"push"}}}}, "high"},
		{"GitLab only tags", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "release", Only: []string{"tags"}}}}, "critical"},
		{"GitLab rule on CI_COMMIT_TAG", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "release", Rules: []map[string]any{{"if": "$CI_COMMIT_TAG"}}}}}, "critical"},
		{"GitLab rule on braced CI_COMMIT_TAG regex", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "release", Rules: []map[string]any{{"if": `${CI_COMMIT_TAG} =~ /^v/`}}}}}, "critical"},
		{"GitLab rule CI_COMMIT_TAG not null", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "release", Rules: []map[string]any{{"if": `$CI_COMMIT_TAG != null`}}}}}, "critical"},
		{"GitLab rule on negated CI_COMMIT_TAG", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "build", Rules: []map[string]any{{"if": "!$CI_COMMIT_TAG"}}}}}, "high"},
		{"GitLab rule on a longer variable name", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "notes", Rules: []map[string]any{{"if": `$CI_COMMIT_TAG_MESSAGE =~ /release/`}}}}}, "high"},
		{"GitLab rule CI_COMMIT_TAG null", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "build", Rules: []map[string]any{{"if": `$CI_COMMIT_TAG == null`}}}}}, "high"},
		{"GitLab rule CI_COMMIT_TAG empty", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "build", Rules: []map[string]any{{"if": `$CI_COMMIT_TAG == ""`}}}}}, "high"},
		{"GitLab tag rule with when never", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "build", Rules: []map[string]any{{"if": "$CI_COMMIT_TAG", "when": "never"}}}}}, "high"},
		{"GitLab job with no rules", &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: tp(), Jobs: []ir.Job{{Name: "build"}}}, "high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := evalTagFindings(t, tc.p, nil)
			if len(f) != 1 {
				t.Fatalf("want 1 finding, got %d", len(f))
			}
			if f[0].Severity != "critical" {
				t.Errorf("ISSUE-510 keeps its registered severity, got %q", f[0].Severity)
			}
			if got := f[0].Data["occurrenceSeverity"]; got != tc.want {
				t.Errorf("occurrenceSeverity = %v, want %s", got, tc.want)
			}
			if got := f[0].Data["triggered"]; got != (tc.want == "critical") {
				t.Errorf("triggered = %v, want %v", got, tc.want == "critical")
			}
		})
	}
}

// With namePatterns empty or unset (the default), every tag must be
// protected by rules on all tags (GitHub ~ALL, GitLab `*`, both `**`)
// that exclude none. One finding, keyed on the provider's all-tags label.
func TestIssue510_AllTags(t *testing.T) {
	emptyCfg := func(extra map[string]any) map[string]any {
		c := map[string]any{"namePatterns": []any{}}
		maps.Copy(c, extra)
		return map[string]any{"tagMustBeProtected": c}
	}
	gh := func(tp *ir.TagProtection, jobs ...ir.Job) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "o/r", TagProtection: tp, Jobs: jobs}
	}
	gl := func(tp *ir.TagProtection, jobs ...ir.Job) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, ProjectPath: "g/p", TagProtection: tp, Jobs: jobs}
	}
	tagged := func(rules ...ir.TagProtectionRule) *ir.TagProtection {
		return &ir.TagProtection{Known: true, Tags: []string{"v1.0.0", "nightly"}, Rules: rules}
	}
	withExclude := fullTagRule("**")
	withExclude.Exclude = []string{"nightly"}
	all := []any{"update", "deletion", "creation"}

	cases := []struct {
		name        string
		p           *ir.NormalizedPipeline
		cfg         map[string]any
		want        []string
		wantMissing []any
	}{
		{name: "an all-tags rule passes", p: gh(tagged(fullTagRule("**"))), cfg: emptyCfg(nil), want: []string{}},
		{name: "unset namePatterns means all tags", p: gh(tagged(fullTagRule("v*"))), cfg: map[string]any{"tagMustBeProtected": map[string]any{}}, want: []string{"~ALL"}, wantMissing: all},
		{name: "no control config at all means all tags", p: gh(tagged()), cfg: map[string]any{}, want: []string{"~ALL"}, wantMissing: all},
		{name: "blank patterns only mean all tags", p: gh(tagged()), cfg: emptyCfg(map[string]any{"namePatterns": []any{"", "refs/tags/"}}), want: []string{"~ALL"}, wantMissing: all},
		{name: "a v* rule is not all tags", p: gh(tagged(fullTagRule("v*"))), cfg: emptyCfg(nil), want: []string{"~ALL"}, wantMissing: all},
		{name: "a * rule is not all tags", p: gh(tagged(fullTagRule("*"))), cfg: emptyCfg(nil), want: []string{"~ALL"}, wantMissing: all},
		{name: "an all-tags rule with an exclusion does not count", p: gh(tagged(withExclude)), cfg: emptyCfg(nil), want: []string{"~ALL"}, wantMissing: all},
		{
			name: "all-tags rules layer per protection",
			p: gh(tagged(
				ir.TagProtectionRule{ID: "1", Include: []string{"**"}, BlocksUpdate: true, BlocksDeletion: true},
				ir.TagProtectionRule{ID: "2", Include: []string{"**"}, RestrictsCreation: true},
			)),
			cfg:  emptyCfg(nil),
			want: []string{},
		},
		{
			name:        "a missing creation rule is reported alone",
			p:           gh(tagged(ir.TagProtectionRule{ID: "1", Include: []string{"**"}, BlocksUpdate: true, BlocksDeletion: true})),
			cfg:         emptyCfg(nil),
			want:        []string{"~ALL"},
			wantMissing: []any{"creation"},
		},
		{
			name: "no creation rule passes when creation is not required",
			p:    gh(tagged(ir.TagProtectionRule{ID: "1", Include: []string{"**"}, BlocksUpdate: true, BlocksDeletion: true})),
			cfg:  emptyCfg(map[string]any{"requireCreationRestricted": false}),
			want: []string{},
		},
		{name: "a repository that never tags stays quiet", p: gh(&ir.TagProtection{Known: true}), cfg: emptyCfg(nil), want: []string{}},
		{name: "unknown protection abstains", p: gh(&ir.TagProtection{Known: false, Tags: []string{"v1.0.0"}}), cfg: emptyCfg(nil), want: []string{}},
		{name: "no collection abstains", p: gh(nil, ir.Job{Name: "r/p", PushTags: []string{"v*"}}), cfg: emptyCfg(nil), want: []string{}},
		{name: "a tag trigger alone puts tags in use", p: gh(&ir.TagProtection{Known: true}, ir.Job{Name: "r/p", PushTags: []string{"release-*"}}), cfg: emptyCfg(nil), want: []string{"~ALL"}, wantMissing: all},
		{name: "a release trigger alone puts tags in use", p: gh(&ir.TagProtection{Known: true}, ir.Job{Name: "r/p", Triggers: []string{"release"}}), cfg: emptyCfg(nil), want: []string{"~ALL"}, wantMissing: all},
		{name: "an inert tag trigger does not", p: gh(&ir.TagProtection{Known: true}, ir.Job{Name: "r/p", PushTags: []string{"v*"}, Inert: "disabled"}), cfg: emptyCfg(nil), want: []string{}},
		{name: "workflow patterns add no finding of their own", p: gh(tagged(fullTagRule("**")), ir.Job{Name: "r/p", PushTags: []string{"release-*"}}), cfg: emptyCfg(nil), want: []string{}},
		{name: "a configured pattern leaves all-tags mode", p: gh(tagged(fullTagRule("v*"))), cfg: map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{"v*"}}}, want: []string{}},
		{name: "a GitLab protected tag * (collected as **) passes", p: gl(tagged(ir.TagProtectionRule{ID: "*", Source: ir.TagRuleSourceProtectedTag, Include: []string{"**"}, BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true})), cfg: emptyCfg(nil), want: []string{}},
		{name: "a GitLab protected tag v* is not all tags", p: gl(tagged(ir.TagProtectionRule{ID: "v*", Source: ir.TagRuleSourceProtectedTag, Include: []string{"v**"}, BlocksUpdate: true, BlocksDeletion: true, RestrictsCreation: true})), cfg: emptyCfg(nil), want: []string{"*"}, wantMissing: all},
		{name: "a GitLab tag job alone puts tags in use", p: gl(&ir.TagProtection{Known: true}, ir.Job{Name: "release", Only: []string{"tags"}}), cfg: emptyCfg(nil), want: []string{"*"}, wantMissing: all},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := evalTagFindings(t, tc.p, tc.cfg)
			if got := tagPatterns(f); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("flagged patterns = %v, want %v", got, tc.want)
			}
			if tc.wantMissing != nil {
				if got := f[0].Data["missingProtections"]; !reflect.DeepEqual(got, tc.wantMissing) {
					t.Errorf("missingProtections = %v, want %v", got, tc.wantMissing)
				}
			}
		})
	}
}

// The all-tags messages name the provider's all-tags target, and the
// finding is critical when any live job runs on tags, whatever its
// pattern, high otherwise.
func TestIssue510_AllTagsMessageAndSeverity(t *testing.T) {
	cfg := map[string]any{"tagMustBeProtected": map[string]any{"namePatterns": []any{}}}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, TagProtection: &ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}}}

	f := evalTagFindings(t, p, cfg)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if got, want := f[0].Message, "Tags are not protected by a rule on all tags (`~ALL`)."; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}
	if f[0].Severity != "critical" || f[0].Data["occurrenceSeverity"] != "high" || f[0].Data["triggered"] != false {
		t.Errorf("untriggered: severity = %v, occurrenceSeverity = %v, triggered = %v", f[0].Severity, f[0].Data["occurrenceSeverity"], f[0].Data["triggered"])
	}

	p.TagProtection.Rules = []ir.TagProtectionRule{{ID: "1", Include: []string{"**"}, BlocksDeletion: true}}
	f = evalTagFindings(t, p, cfg)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if got, want := f[0].Message, "Tags are not fully protected by rules on all tags (`~ALL`), tag updates are not blocked and tag creation is not restricted."; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}

	for name, job := range map[string]ir.Job{
		"push tags expression": {Name: "r/p", PushTags: []string{"${{ inputs.tag }}"}},
		"tags-ignore":          {Name: "r/p", Triggers: []string{"push"}, PushTagsIgnore: []string{"*-rc*"}},
		"release":              {Name: "r/p", Triggers: []string{"release"}},
	} {
		p.Jobs = []ir.Job{job}
		f = evalTagFindings(t, p, cfg)
		if len(f) != 1 || f[0].Data["occurrenceSeverity"] != "critical" || f[0].Data["triggered"] != true {
			t.Errorf("%s: want one critical, triggered finding, got %+v", name, f)
		}
	}

	gl := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, TagProtection: &ir.TagProtection{Known: true, Tags: []string{"v1.0.0"}}}
	f = evalTagFindings(t, gl, cfg)
	if len(f) != 1 || f[0].Message != "Tags are not protected by a rule on all tags (`*`)." {
		t.Errorf("GitLab: want the `*` label, got %+v", f)
	}
}
