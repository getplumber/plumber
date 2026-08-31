package gitlab

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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

// TestGraphQLClientReportsNonOKAsError pins the fix for a silent-pass the
// GraphQL library produces on its own.
//
// machinebox/graphql decodes the response body FIRST and only looks at the
// status code when that decode fails. GitLab answers an unauthorized
// GraphQL request with 401 and a JSON body, which decodes cleanly into a
// response with no data and no `errors` - so without this guard the caller
// receives success and an empty payload.
//
// Every collection behind GraphQL then reads as honestly empty: no merged
// configuration, no catalogue entry, no variables. Each one makes its
// control find nothing to object to and report compliant, which is the one
// direction a compliance scanner must not fail in, and nothing appears in a
// log because nothing errored.
func TestGraphQLClientReportsNonOKAsError(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				// Decodable JSON with neither `data` nor `errors` - exactly
				// what GitLab returns, and exactly what makes this silent.
				_, _ = w.Write([]byte(`{"message":"nope"}`))
			}))
			defer srv.Close()

			conf := &configuration.Configuration{
				HTTPClientTimeout:     10 * time.Second,
				GitlabRetryMaxRetries: 0,
			}
			client := GetGraphQLClient(srv.URL, conf)

			var out struct {
				Project struct{ ID string }
			}
			err := client.Run(context.Background(), graphql.NewRequest(`query q { project { id } }`), &out)
			if err == nil {
				t.Fatalf("a %d response must be an error, not an empty successful result", status)
			}
		})
	}
}

// A 200 must still work, and must still surface GraphQL-level errors.
func TestGraphQLClientPassesThroughOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"project":{"id":"gid://gitlab/Project/7"}}}`))
	}))
	defer srv.Close()

	conf := &configuration.Configuration{
		HTTPClientTimeout:     10 * time.Second,
		GitlabRetryMaxRetries: 0,
	}
	var out struct {
		Project struct{ ID string }
	}
	if err := GetGraphQLClient(srv.URL, conf).Run(context.Background(), graphql.NewRequest(`query q { project { id } }`), &out); err != nil {
		t.Fatalf("a 200 must succeed: %v", err)
	}
	if out.Project.ID != "gid://gitlab/Project/7" {
		t.Fatalf("payload did not decode: %+v", out)
	}
}
