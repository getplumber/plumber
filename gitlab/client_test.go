package gitlab

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/machinebox/graphql"
)

// spyRoundTripper records whether it was invoked and returns a canned response,
// so a test can assert an injected client's transport is actually used without
// any network access.
type spyRoundTripper struct {
	called bool
	body   string
}

func (s *spyRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	s.called = true
	body := s.body
	if body == "" {
		body = "{}"
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

func TestGetNewGitlabClient_UsesInjectedTransport(t *testing.T) {
	spy := &spyRoundTripper{body: `{"version":"0.0.0","revision":"test"}`}
	conf := &configuration.Configuration{HTTPClient: &http.Client{Transport: spy}}
	client, err := GetNewGitlabClient("glpat-000000000000", "https://gitlab.example.com", conf)
	if err != nil {
		t.Fatalf("GetNewGitlabClient: %v", err)
	}
	_, _, _ = client.Version.GetVersion() //nolint:dogsled // only the transport hit matters
	if !spy.called {
		t.Fatal("the gitlab client did not route through the injected transport")
	}
}

func TestGetGraphQLClient_UsesInjectedTransport(t *testing.T) {
	spy := &spyRoundTripper{body: `{"data":{}}`}
	conf := &configuration.Configuration{HTTPClient: &http.Client{Transport: spy}}
	client := GetGraphQLClient("https://gitlab.example.com", conf)
	_ = client.Run(context.Background(), graphql.NewRequest("query{__typename}"), &struct{}{})
	if !spy.called {
		t.Fatal("the graphql client did not route through the injected transport")
	}
}
