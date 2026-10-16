package situation_test

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

type tokenStateResult struct {
	Jobs map[string]struct {
		Privilege struct {
			TokenWrite       []string `json:"tokenWrite"`
			TokenWriteSource string   `json:"tokenWriteSource"`
			TokenWriteState  string   `json:"tokenWriteState"`
		} `json:"privilege"`
	} `json:"jobs"`
}

// TestGitLabContentsWriteSignalIsAProvenTokenWrite pins the state of a
// GitLab contents write: the write is granted only on a positive signal
// (a script running git push, or a protected CI_PUSH_TOKEN reaching the
// job), so the write is proven, its source staying "none" (GitLab
// declares no token scope). A job with neither holds no write.
func TestGitLabContentsWriteSignalIsAProvenTokenWrite(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Jobs: []ir.Job{
		{Name: "push", Scripts: []string{"git push origin main"}},
		{Name: "plain", Scripts: []string{"make test"}},
	}}
	var r tokenStateResult
	evaluateInto(t, p, nil, &r)
	if got := r.Jobs["push"].Privilege; len(got.TokenWrite) != 1 || got.TokenWriteState != "proven" || got.TokenWriteSource != "none" {
		t.Errorf("git push: privilege = %+v, want contents write, state proven, source none", got)
	}
	if got := r.Jobs["plain"].Privilege; len(got.TokenWrite) != 0 || got.TokenWriteState != "unknown" {
		t.Errorf("plain: privilege = %+v, want no write, state unknown", got)
	}

	p = gitlabFixture(t, "release_protected.gitlab-ci.yml", "private")
	p.SettingsVariablesKnown = true
	p.SettingsVariables = []ir.SettingsVariable{{Name: "CI_PUSH_TOKEN", Type: "env_var", Environment: "*", Protected: true}}
	r = tokenStateResult{}
	evaluateInto(t, p, nil, &r)
	if got := r.Jobs["release"].Privilege; len(got.TokenWrite) != 1 || got.TokenWriteState != "proven" || got.TokenWriteSource != "none" {
		t.Errorf("CI_PUSH_TOKEN: privilege = %+v, want contents write, state proven, source none", got)
	}
}
