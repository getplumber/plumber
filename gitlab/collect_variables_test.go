package gitlab

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// TestCollectGitlabVariables_UnreadableIsNotEvaluable: a failed fetch (here an
// HTTP 401) maps to Known=false so an unreadable settings API reports
// not-evaluable, never a false pass (#418), and the error is returned so the
// caller can classify it (network -> degrade vs permission -> not-evaluable).
func TestCollectGitlabVariables_UnreadableIsNotEvaluable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	conf := &configuration.Configuration{GitlabURL: srv.URL}
	data, err := CollectGitlabVariables("group/project", "bad-token", conf)
	if err == nil {
		t.Fatal("expected a non-nil error on a failed fetch so the caller can classify it")
	}
	if data == nil || data.Known {
		t.Fatalf("an unreadable settings API must yield Known=false, got %+v", data)
	}
	if len(data.Variables) != 0 {
		t.Fatalf("expected zero variables on a failed fetch, got %d", len(data.Variables))
	}
}

// TestCollectGitlabVariables_NullProjectIsNotEvaluable covers the
// under-privileged case: HTTP 200 (no transport error) with the GraphQL
// `project` field null. Must yield Known=false, and the error must wrap
// ErrProjectVariablesUnreadable so the image collector can tolerate it via
// errors.Is while the settings controls treat it as not-evaluable.
func TestCollectGitlabVariables_NullProjectIsNotEvaluable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"project":null}}`))
	}))
	defer srv.Close()

	conf := &configuration.Configuration{GitlabURL: srv.URL}
	data, err := CollectGitlabVariables("group/project", "under-privileged", conf)
	if data.Known {
		t.Fatal("a null project (HTTP 200, under-privileged token) must yield Known=false")
	}
	if !errors.Is(err, ErrProjectVariablesUnreadable) {
		t.Fatalf("null-project error must wrap ErrProjectVariablesUnreadable (the image collector relies on it via errors.Is), got %v", err)
	}
}

// TestGetGitlabProjectVariables_SuccessMapping exercises the success path: a
// populated ciVariables node list maps to []CICDVariable, and the GraphQL enum
// variableType (ENV_VAR / FILE) is normalised to lower case so the masked
// rule's file exclusion and the ISSUE-201/202 identity value stay consistent
// with the fixtures and the REST convention. The hand-built IR fixtures
// elsewhere already carry lower-case types, so only this test catches a dropped
// ToLower or a field mix-up in the mapping.
func TestGetGitlabProjectVariables_SuccessMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"project":{"ciVariables":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[
			{"key":"AWS_KEY","value":"x","variableType":"ENV_VAR","masked":true,"protected":false,"hidden":false,"environmentScope":"*"},
			{"key":"KUBECONFIG","value":"y","variableType":"FILE","masked":false,"protected":true,"hidden":false,"environmentScope":"production"}
		]}}}}`))
	}))
	defer srv.Close()

	conf := &configuration.Configuration{GitlabURL: srv.URL}
	vars, err := GetGitlabProjectVariables("group/project", "tok", conf.GitlabURL, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("want 2 variables, got %d", len(vars))
	}
	if v := vars[0]; v.Name != "AWS_KEY" || v.Type != "env_var" || !v.Masked || v.Protected {
		t.Fatalf("var 0 mapping mismatch (type must be lower-cased env_var): %+v", v)
	}
	if v := vars[1]; v.Name != "KUBECONFIG" || v.Type != "file" || v.Masked || !v.Protected || v.Environment != "production" {
		t.Fatalf("var 1 mapping mismatch (type must be lower-cased file): %+v", v)
	}
}

// TestGetGitlabProjectVariables_Paginates pins cursor pagination: a variable
// returned only on page 2 (after following endCursor) must appear in the
// result, so a project with more than one page of variables is fully scanned.
func TestGetGitlabProjectVariables_Paginates(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		call++
		if call == 1 {
			_, _ = w.Write([]byte(`{"data":{"project":{"ciVariables":{"pageInfo":{"hasNextPage":true,"endCursor":"CURSOR1"},"nodes":[
				{"key":"PAGE1_VAR","value":"a","variableType":"ENV_VAR","masked":false,"protected":false,"hidden":false,"environmentScope":"*"}
			]}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"project":{"ciVariables":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[
			{"key":"PAGE2_VAR","value":"b","variableType":"FILE","masked":false,"protected":true,"hidden":false,"environmentScope":"prod"}
		]}}}}`))
	}))
	defer srv.Close()

	conf := &configuration.Configuration{GitlabURL: srv.URL}
	vars, err := GetGitlabProjectVariables("group/project", "tok", conf.GitlabURL, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("expected 2 variables across 2 pages, got %d", len(vars))
	}
	if vars[1].Name != "PAGE2_VAR" {
		t.Errorf("the page-2 variable was not fetched (pagination broken): %+v", vars)
	}
}

// TestCollectGitlabVariables_BlanksValues pins that the settings-control path
// strips every variable value (image resolution uses a separate fetch), so a
// secret value is never held on VariablesData even though the GraphQL query
// still selects it.
func TestCollectGitlabVariables_BlanksValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"project":{"ciVariables":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[
			{"key":"SECRET","value":"PLANTED_SECRET","variableType":"ENV_VAR","masked":false,"protected":false,"hidden":false,"environmentScope":"*"}
		]}}}}`))
	}))
	defer srv.Close()

	conf := &configuration.Configuration{GitlabURL: srv.URL}
	data, err := CollectGitlabVariables("group/project", "tok", conf)
	if err != nil || !data.Known || len(data.Variables) != 1 {
		t.Fatalf("expected a clean success with 1 variable, got Known=%v n=%d err=%v", data.Known, len(data.Variables), err)
	}
	if data.Variables[0].Value != "" {
		t.Errorf("settings-path variable value must be blanked, got %q", data.Variables[0].Value)
	}
}
