package gitlab

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

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

// An injected client (ADR-0021 rule J: the platform supplies one shared,
// rate-limited/cached client per (provider, instance)) must be used verbatim,
// transport and all — never rebuilt.
func TestGetHTTPClient_UsesInjectedClient(t *testing.T) {
	injected := &http.Client{}
	conf := &configuration.Configuration{HTTPClient: injected}
	if got := GetHTTPClient(conf); got != injected {
		t.Fatal("GetHTTPClient must return the injected *http.Client unchanged")
	}
}

// Default path (CLI's own runs, HTTPClient nil) must be byte-for-byte the old
// behavior — same timeout, non-nil client. Guards against a transparency regression.
func TestGetHTTPClient_DefaultWhenNil(t *testing.T) {
	conf := &configuration.Configuration{HTTPClientTimeout: 7 * time.Second}
	got := GetHTTPClient(conf)
	if got == nil {
		t.Fatal("default client must not be nil")
	}
	if got.Timeout != 7*time.Second {
		t.Fatalf("default path changed: want 7s timeout, got %v", got.Timeout)
	}
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
