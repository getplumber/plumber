package gitlab

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// fakeBranchServer answers GitLab's single-branch endpoint for a few known
// branches and records which branch names were asked for.
func fakeBranchServer(t *testing.T, asked *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const marker = "/repository/branches/"
		i := strings.LastIndex(r.URL.Path, marker)
		if i < 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		name, _ := url.PathUnescape(r.URL.Path[i+len(marker):])
		*asked = append(*asked, name)
		w.Header().Set("Content-Type", "application/json")
		switch name {
		case "main":
			_, _ = w.Write([]byte(`{"name":"main","protected":true}`))
		case "feature-x":
			_, _ = w.Write([]byte(`{"name":"feature-x","protected":false}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"404 Branch Not Found"}`))
		}
	}))
}

// TestAnalysedBranchIsProtectedAsksGitLabAboutTheAnalysedBranch: over the
// API the protected-ref fact is GitLab's own verdict on the branch under
// analysis, the requested one or else the project's default branch, never
// this process's environment. An unreadable branch counts as unprotected.
func TestAnalysedBranchIsProtectedAsksGitLabAboutTheAnalysedBranch(t *testing.T) {
	t.Setenv("CI_COMMIT_REF_PROTECTED", "true") // this job's own ref must not decide the answer
	var asked []string
	srv := fakeBranchServer(t, &asked)
	defer srv.Close()
	project := &ProjectInfo{Path: "group/project", DefaultBranch: "main"}

	cases := []struct {
		name      string
		branch    string
		want      bool
		wantAsked string
	}{
		{"requested unprotected branch", "feature-x", false, "feature-x"},
		{"requested protected branch", "main", true, "main"},
		{"no request falls back to the default branch", "", true, "main"},
		{"unknown branch reads as unprotected", "ghost", false, "ghost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asked = nil
			conf := &configuration.Configuration{GitlabURL: srv.URL, Branch: tc.branch}
			if got := analysedBranchIsProtected(project, "glpat-test", conf); got != tc.want {
				t.Fatalf("analysedBranchIsProtected = %v, want %v", got, tc.want)
			}
			if len(asked) != 1 || asked[0] != tc.wantAsked {
				t.Fatalf("asked GitLab about %v, want exactly [%q]", asked, tc.wantAsked)
			}
		})
	}

	// No branch to ask about: false, and GitLab is not called.
	asked = nil
	if analysedBranchIsProtected(&ProjectInfo{Path: "group/project"}, "glpat-test", &configuration.Configuration{GitlabURL: srv.URL}) {
		t.Error("no analysed branch must read as unprotected")
	}
	if len(asked) != 0 {
		t.Errorf("no branch to ask about, yet GitLab was asked %v", asked)
	}
	if analysedBranchIsProtected(nil, "glpat-test", &configuration.Configuration{GitlabURL: srv.URL}) || analysedBranchIsProtected(project, "glpat-test", nil) {
		t.Error("a missing project or configuration must read as unprotected")
	}
}

// TestProtectedVariableExpandsOnlyWhenTheAnalysedBranchIsProtected wires the
// verdict into the map: the same protected variable is expandable when the
// analysed branch is protected and stays a placeholder when it is not.
func TestProtectedVariableExpandsOnlyWhenTheAnalysedBranchIsProtected(t *testing.T) {
	var asked []string
	srv := fakeBranchServer(t, &asked)
	defer srv.Close()
	project := &ProjectInfo{Path: "group/project", DefaultBranch: "main"}
	vars := []CICDVariable{{Name: "PROD_REGISTRY", Value: "prod.example.com", Protected: true, Environment: "*"}}

	onMain := ConvertCICDVariableToMap(vars, analysedBranchIsProtected(project, "glpat-test", &configuration.Configuration{GitlabURL: srv.URL, Branch: "main"}))
	if onMain["PROD_REGISTRY"] == "" {
		t.Error("a protected variable is expandable when the analysed branch is protected")
	}
	onFeature := ConvertCICDVariableToMap(vars, analysedBranchIsProtected(project, "glpat-test", &configuration.Configuration{GitlabURL: srv.URL, Branch: "feature-x"}))
	if _, present := onFeature["PROD_REGISTRY"]; present {
		t.Error("a protected variable keeps its placeholder when the analysed branch is not protected")
	}
}

// TestConvertCICDVariableToMapKeepsOnlyWhatTheJobWouldSee pins the API path
// to the same exposure rules the platform path already follows
// (expandableFromJobEnvironment): a variable is a sound substitute for an
// image reference only when the analysed job would actually hold its value.
// A file variable resolves to a temporary path, a masked or hidden one is
// never rendered anywhere, a protected one is withheld on an unprotected
// ref, and an environment-scoped one differs per job. Each of those stays a
// placeholder so the image rules abstain instead of judging a reference the
// job never runs.
func TestConvertCICDVariableToMapKeepsOnlyWhatTheJobWouldSee(t *testing.T) {
	vars := []CICDVariable{
		{Name: "REGISTRY", Value: "registry.example.com", Environment: "*"},
		{Name: "TAG", Value: "1.2.3"},
		{Name: "CERT_BUNDLE", Value: "/builds/tmp/CERT_BUNDLE", Type: "FILE", Environment: "*"},
		{Name: "MASKED_ONE", Value: "abcdefghijklmnop", Masked: true, Environment: "*"},
		{Name: "HIDDEN_ONE", Value: "abcdefghijklmnop", Hidden: true, Environment: "*"},
		{Name: "PROD_ONLY", Value: "prod.example.com", Protected: true, Environment: "*"},
		{Name: "SCOPED", Value: "scoped.example.com", Environment: "production"},
		{Name: "EMPTY_ONE", Value: "", Environment: "*"},
	}

	got := ConvertCICDVariableToMap(vars, false)

	// A defined-but-empty variable is skipped, as on the job-environment
	// path: substituting "" turns `$REGISTRY/app` into `/app`, a reference
	// that looks resolved and is not the one the job uses.
	if _, present := got["EMPTY_ONE"]; present {
		t.Error("an empty value must not be substituted")
	}

	for _, name := range []string{"REGISTRY", "TAG"} {
		if got[name] == "" {
			t.Errorf("%q is a plain variable the job sees and must be expandable", name)
		}
	}
	for _, name := range []string{"CERT_BUNDLE", "MASKED_ONE", "HIDDEN_ONE", "PROD_ONLY", "SCOPED"} {
		if _, present := got[name]; present {
			t.Errorf("%q is not a value this job would see and must stay a placeholder", name)
		}
	}
}

// TestConvertCICDVariableToMapHonoursRefProtection: on a protected ref a job
// does hold a protected variable's value, so it is expandable there.
func TestConvertCICDVariableToMapHonoursRefProtection(t *testing.T) {
	got := ConvertCICDVariableToMap([]CICDVariable{
		{Name: "PROD_ONLY", Value: "prod.example.com", Protected: true, Environment: "*"},
	}, true)
	if got["PROD_ONLY"] == "" {
		t.Error("a protected variable is expandable on a protected ref")
	}
}

// TestJobEnvironmentVariablesExpandsPipelineWidePredefinedOnly: the
// predefined half of the environment is read through an explicit list of
// the pipeline-wide names an image reference is built from, not by prefix.
// A prefix admitted every predefined name, including ones that describe
// the running job or carry the job's own credentials and are never a
// component of another job's image reference.
func TestJobEnvironmentVariablesExpandsPipelineWidePredefinedOnly(t *testing.T) {
	t.Setenv("CI_REGISTRY", "registry.example.com")
	t.Setenv("CI_REGISTRY_IMAGE", "registry.example.com/group/project")
	t.Setenv("CI_TEMPLATE_REGISTRY_HOST", "registry.gitlab.com")
	t.Setenv("CI_COMMIT_REF_SLUG", "feature-x")
	t.Setenv("CI_COMMIT_SHA", "0123456789abcdef0123456789abcdef01234567")
	t.Setenv("CI_COMMIT_SHORT_SHA", "01234567")
	t.Setenv("CI_COMMIT_TAG", "v1.2.3")
	t.Setenv("CI_PIPELINE_IID", "42")
	t.Setenv("CI_REGISTRY_PASSWORD", "not-an-image-component")
	t.Setenv("CI_REPOSITORY_URL", "https://gitlab-ci-token:token@gitlab.example.com/g/p.git")
	t.Setenv("CI_DEPLOY_PASSWORD", "not-an-image-component")
	t.Setenv("CI_JOB_TOKEN", "not-an-image-component")
	t.Setenv("GITLAB_TOKEN", "not-an-image-component")
	t.Setenv("GITLAB_USER_LOGIN", "someone")
	t.Setenv("REGISTRY", "declared.example.com")

	got := JobEnvironmentVariables([]string{"REGISTRY"})

	// Registry hosts and image prefixes, plus the commit and pipeline
	// coordinates image tags are routinely built from
	// (`$CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG`): identical for every job of
	// the pipeline, so this job's value is the value any job would use.
	for _, name := range []string{"CI_REGISTRY", "CI_REGISTRY_IMAGE", "CI_TEMPLATE_REGISTRY_HOST", "REGISTRY",
		"CI_COMMIT_REF_SLUG", "CI_COMMIT_SHA", "CI_COMMIT_SHORT_SHA", "CI_COMMIT_TAG", "CI_PIPELINE_IID"} {
		if got[name] == "" {
			t.Errorf("%q is a pipeline-wide image reference component and must be expandable", name)
		}
	}
	for _, name := range []string{"CI_REGISTRY_PASSWORD", "CI_REPOSITORY_URL", "CI_DEPLOY_PASSWORD", "CI_JOB_TOKEN", "GITLAB_TOKEN", "GITLAB_USER_LOGIN"} {
		if _, present := got[name]; present {
			t.Errorf("%q is not a component of an image reference and must not be substituted", name)
		}
	}
}
