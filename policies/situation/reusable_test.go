package situation_test

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// callerFact is one entry of a called job's callers fact.
type callerFact struct {
	Job              string   `json:"job"`
	TokenWrite       []string `json:"tokenWrite"`
	TokenWriteSource string   `json:"tokenWriteSource"`
	Secrets          []string `json:"secrets"`
	AllSecrets       bool     `json:"allSecrets"`
	Triggers         []string `json:"triggers"`
}

type reusableFacts struct {
	Privilege privilege    `json:"privilege"`
	Impact    []impact     `json:"impact"`
	Callers   []callerFact `json:"callers"`
}

// reusablePipeline is a nightly upload: nightly/upload calls the local
// reusable workflow _upload.yml with a read token, an OIDC token and the
// R2 secret by an explicit map (the token passed under the callee's
// github-token name); other/lint calls it from a pull request with no
// permissions block and secrets: inherit; the called job reads both
// secrets and runs the upload script.
func reusablePipeline() *ir.NormalizedPipeline {
	return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{
		{
			Name: "nightly/upload", OriginFile: ".github/workflows/nightly.yml", Triggers: []string{"push"},
			Permissions:          map[string]any{"contents": "read", "id-token": "write"},
			ReusableWorkflowUses: "./.github/workflows/_upload.yml",
			ReusableSecrets:      map[string]string{"github-token": "${{ secrets.GITHUB_TOKEN }}", "R2_KEY": "${{ secrets.R2_KEY }}"},
			ReusableCallees:      []string{"_upload/upload"},
		},
		{
			Name: "other/lint", OriginFile: ".github/workflows/other.yml", Triggers: []string{"pull_request"},
			ReusableWorkflowUses: "./.github/workflows/_upload.yml", SecretsInherit: true,
			ReusableCallees: []string{"_upload/upload"},
		},
		{
			Name: "_upload/upload", OriginFile: ".github/workflows/_upload.yml", Triggers: []string{"workflow_call"},
			Scripts:   []string{"bash .ci/pytorch/binary_upload.sh"},
			Variables: map[string]string{"R2": "${{ secrets.R2_KEY }}", "GITHUB_TOKEN": "${{ secrets.github-token }}"},
			Callers: []ir.ReusableCaller{
				{Job: "nightly/upload", Permissions: map[string]any{"contents": "read", "id-token": "write"}, Triggers: []string{"push"},
					Secrets: map[string]string{"github-token": "${{ secrets.GITHUB_TOKEN }}", "R2_KEY": "${{ secrets.R2_KEY }}"}},
				{Job: "other/lint", Triggers: []string{"pull_request"}, SecretsInherit: true},
			},
		},
	}}
}

func reusableJobs(t *testing.T, p *ir.NormalizedPipeline) map[string]reusableFacts {
	t.Helper()
	var r struct {
		Jobs map[string]reusableFacts `json:"jobs"`
	}
	evaluateInto(t, p, nil, &r)
	return r.Jobs
}

// TestCalledJobHoldsWhatEachCallerGives pins the facts of a job of a
// reusable workflow: one entry per call with the token, the secrets and
// the events that call gives it (a secret passed by map counts by the
// caller's name, the job token passed as a secret is the token and no
// secret, inherit passes every secret the job reads); its own token is
// the union of its callers' (assumed only when a caller declares none);
// its secrets are the ones some call really passes.
func TestCalledJobHoldsWhatEachCallerGives(t *testing.T) {
	got := reusableJobs(t, reusablePipeline())["_upload/upload"]
	want := []callerFact{
		{Job: "nightly/upload", TokenWrite: []string{"id-token"}, TokenWriteSource: "declared", Secrets: []string{"R2_KEY"}, Triggers: []string{"push"}},
		{Job: "other/lint", TokenWrite: []string{"contents", "packages"}, TokenWriteSource: "default", Secrets: []string{"R2_KEY", "github-token"}, AllSecrets: true, Triggers: []string{"pull_request"}},
	}
	if !reflect.DeepEqual(got.Callers, want) {
		t.Errorf("callers = %+v\nwant %+v", got.Callers, want)
	}
	if !reflect.DeepEqual(got.Privilege.TokenWrite, []string{"contents", "id-token", "packages"}) || got.Privilege.TokenWriteSource != "default" {
		t.Errorf("token = %v (%s), want the union of the callers', assumed since one declares none", got.Privilege.TokenWrite, got.Privilege.TokenWriteSource)
	}
	if !reflect.DeepEqual(got.Privilege.Secrets, []string{"R2_KEY", "github-token"}) {
		t.Errorf("secrets = %v", got.Privilege.Secrets)
	}

	// With the declaring caller alone, the token is that caller's and the
	// github-token secret is the job token, no secret.
	p := reusablePipeline()
	p.Jobs[2].Callers = p.Jobs[2].Callers[:1]
	got = reusableJobs(t, p)["_upload/upload"]
	if !reflect.DeepEqual(got.Privilege.TokenWrite, []string{"id-token"}) || got.Privilege.TokenWriteSource != "declared" {
		t.Errorf("token = %v (%s), want the caller's declared id-token", got.Privilege.TokenWrite, got.Privilege.TokenWriteSource)
	}
	if !reflect.DeepEqual(got.Privilege.Secrets, []string{"R2_KEY"}) {
		t.Errorf("secrets = %v, want R2_KEY alone", got.Privilege.Secrets)
	}
}

// TestCallingJobHoldsWhatItPassesAndDoesWhatItRuns pins the facts of the
// job that calls a reusable workflow: the secrets of its explicit map are
// its own (by the caller's name, the job token left out), and what the
// called jobs do is what it does, one hop being the call itself.
func TestCallingJobHoldsWhatItPassesAndDoesWhatItRuns(t *testing.T) {
	got := reusableJobs(t, reusablePipeline())["nightly/upload"]
	if !reflect.DeepEqual(got.Privilege.Secrets, []string{"R2_KEY"}) {
		t.Errorf("secrets = %v, want the R2 secret it passes", got.Privilege.Secrets)
	}
	var found bool
	for _, i := range got.Impact {
		if i.Kind == "publishes" && i.Via == "_upload/upload" {
			found = true
		}
	}
	if !found {
		t.Errorf("impact = %+v, want the called job's upload, via _upload/upload", got.Impact)
	}
}
