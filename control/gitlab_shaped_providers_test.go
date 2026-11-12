package control

import (
	"reflect"
	"sort"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// gitLabShapedControls are the eight controls that read GitLab-only
// concepts (includes, components, templates, hardcoded jobs, job
// variables, image allowlists on `image:` keys). They used to declare
// both providers and sit on the GitHub bench; a consumer that reads
// Providers from the catalog (the Platform) then served them on GitHub
// installs. They now declare GitLab only and leave the GitHub bench.
var gitLabShapedControls = []string{
	"includesMustBeUpToDate",
	"includesMustNotUseForbiddenVersions",
	"pipelineMustIncludeComponent",
	"pipelineMustIncludeTemplate",
	"pipelineMustNotIncludeHardcodedJobs",
	"pipelineMustNotOverrideJobVariables",
	"pipelineMustNotUseUnsafeVariableExpansion",
	"containerImageMustComeFromAuthorizedSources",
}

// The sets below are snapshots taken on v0.7.14 before the change: what
// GitHubControls renders, what reaches users on each provider (applicable
// and not benched). The metadata fix must leave all three untouched.
// tagMustBeProtected (#398) was added to both providers since.
var wantGitHubControlsOrder = []string{
	"containerImageMustNotUseForbiddenTags",
	"actionsMustBePinnedByCommitSha",
	"githubActionMustComeFromAuthorizedSources",
	"branchMustBeProtected",
	"tagMustBeProtected",
	"securityJobsMustNotBeWeakened",
	"pipelineMustNotUseDockerInDocker",
	"pipelineMustNotExecuteUnverifiedScripts",
	"reusableWorkflowsMustNotInheritSecrets",
	"workflowMustNotExportEntireSecretsContext",
	"workflowMustNotInjectUserInputInScripts",
	"workflowMustNotWriteUntrustedContentToGitHubEnv",
	"workflowMustNotUseDangerousTriggers",
	"pullRequestTargetMustNotCheckoutHead",
	"checkoutMustNotPersistCredentials",
	"workflowsMustDeclarePermissions",
	"workflowsMustBeValid",
	"workflowMustIncludeRequiredActions",
	"workflowMustNotGrantPermissionsWriteAll",
	"externalRefsMustNotCollide",
	"actionsMustNotBeArchived",
	"actionRefsMustExistUpstream",
	"actionsMustNotCarryKnownCVEs",
	"actionsMustNotExecuteMutableRemoteCode",
	"untrustedTriggersMustNotWriteCache",
	"pipelineMustNotEnableDebugTrace",
}

var wantLiveGitLab = []string{
	"branchMustBeProtected",
	"cicdVariablesMustBeMasked",
	"cicdVariablesMustBeProtected",
	"componentMustComeFromAuthorizedSources",
	"containerImageMustComeFromAuthorizedSources",
	"containerImageMustNotUseForbiddenTags",
	"externalRefsMustNotCollide",
	"functionMustComeFromAuthorizedSources",
	"includesMustBeUpToDate",
	"includesMustNotUseForbiddenVersions",
	"mergeRequestApprovalRulesMustCoverAllProtectedBranches",
	"mergeRequestApprovalRulesMustRequireMinimumApprovals",
	"mergeRequestApprovalSettingsMustBeCompliant",
	"mergeRequestSettingsMustBeCompliant",
	"pipelineMustIncludeComponent",
	"pipelineMustIncludeTemplate",
	"pipelineMustNotEnableDebugTrace",
	"pipelineMustNotExecuteUnverifiedScripts",
	"pipelineMustNotIncludeHardcodedJobs",
	"pipelineMustNotOverrideJobVariables",
	"pipelineMustNotUseDockerInDocker",
	"pipelineMustNotUseUnsafeVariableExpansion",
	"projectMustHaveSecurityPolicySource",
	"securityJobsMustNotBeWeakened",
	"tagMustBeProtected",
}

func liveControls(provider string) []string {
	var out []string
	for _, e := range configuration.ControlsCatalog() {
		if configuration.IsControlApplicableTo(e.Name, provider) && !configuration.IsBenched(provider, e.Name) {
			out = append(out, e.Name)
		}
	}
	sort.Strings(out)
	return out
}

func TestGitLabShapedControls_DeclareGitLabOnly(t *testing.T) {
	for _, name := range gitLabShapedControls {
		meta, ok := configuration.ControlMetaFor(name)
		if !ok {
			t.Fatalf("%s: not in the registry", name)
		}
		if !reflect.DeepEqual(meta.Providers, []string{configuration.ProviderGitLab}) {
			t.Errorf("%s: Providers = %v, want [gitlab] (a catalog consumer would serve it on GitHub)", name, meta.Providers)
		}
		if configuration.IsControlApplicableTo(name, configuration.ProviderGitHub) {
			t.Errorf("%s: applicable to github, want gitlab only", name)
		}
		if configuration.IsBenched(configuration.ProviderGitHub, name) {
			t.Errorf("%s: still on the GitHub bench; the entry is redundant once the control is GitLab only", name)
		}
	}
}

func TestGitLabShapedControls_ControlSetsUnchanged(t *testing.T) {
	var gotOrder []string
	for _, e := range GitHubControls(&configuration.PlumberConfig{}) {
		gotOrder = append(gotOrder, e.ControlName)
	}
	if !reflect.DeepEqual(gotOrder, wantGitHubControlsOrder) {
		t.Errorf("GitHubControls changed:\n got %v\nwant %v", gotOrder, wantGitHubControlsOrder)
	}

	wantLiveGitHub := append([]string(nil), wantGitHubControlsOrder...)
	sort.Strings(wantLiveGitHub)
	if got := liveControls(configuration.ProviderGitHub); !reflect.DeepEqual(got, wantLiveGitHub) {
		t.Errorf("controls reaching GitHub users changed:\n got %v\nwant %v", got, wantLiveGitHub)
	}
	if got := liveControls(configuration.ProviderGitLab); !reflect.DeepEqual(got, wantLiveGitLab) {
		t.Errorf("controls reaching GitLab users changed:\n got %v\nwant %v", got, wantLiveGitLab)
	}
}
