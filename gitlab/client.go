package gitlab

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/machinebox/graphql"
	"github.com/sirupsen/logrus"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const (
	gitlabGraphQLPath   = "/api/graphql"
	personalTokenPrefix = "glpat-" // Personal Access Token prefix
)

// GetNewGitlabClient returns a new GitLab client for API requests
func GetNewGitlabClient(token string, instanceUrl string, conf *configuration.Configuration) (*gitlab.Client, error) {
	l := logger.WithFields(logrus.Fields{
		"action": "GetNewGitlabClient",
	})

	// Sanitize the instance URL to remove any trailing slashes
	sanitizedInstance := strings.TrimSuffix(instanceUrl, "/")

	// Use the host-injected client when present (ADR-0021 rule J: one shared,
	// rate-limited/cached client per provider+instance); otherwise build the
	// default retry-wrapped client — unchanged behavior for the CLI's own runs.
	httpClient := conf.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: WrapTransportWithRetry(http.DefaultTransport, conf),
			Timeout:   conf.HTTPClientTimeout,
		}
	}

	// Initialize the GitLab client depending on the token type
	var err error
	var client *gitlab.Client

	if strings.HasPrefix(token, personalTokenPrefix) {
		// Personal/Group/Project Access Token
		client, err = gitlab.NewClient(token, gitlab.WithHTTPClient(httpClient), gitlab.WithBaseURL(sanitizedInstance))
		if err != nil {
			l.WithError(err).Error("Failed to create GitLab client using a Personal/Group/Project Access Token")
			return nil, err
		}
	} else {
		// OAuth Token
		client, err = gitlab.NewOAuthClient(token, gitlab.WithHTTPClient(httpClient), gitlab.WithBaseURL(sanitizedInstance)) //nolint:staticcheck // requires library upgrade to replace deprecated API
		if err != nil {
			l.WithError(err).Error("Failed to create GitLab OAuth client")
			return nil, err
		}
	}

	return client, nil
}

// GetGraphQLClient creates a GraphQL client with retry logic
func GetGraphQLClient(url string, conf *configuration.Configuration) *graphql.Client {
	// Build GraphQL url
	url += gitlabGraphQLPath

	// Use the host-injected client when present (rule J); otherwise build the
	// default retry-wrapped client — unchanged for the CLI's own runs.
	httpClient := conf.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: WrapTransportWithRetry(http.DefaultTransport, conf),
			Timeout:   conf.HTTPClientTimeout,
		}
	}

	// Initialize the GraphQL client
	client := graphql.NewClient(url, graphql.WithHTTPClient(guardGraphQLStatus(httpClient)))

	// Optionally add logging for debugging GraphQL queries
	// Mask sensitive data like Authorization headers
	client.Log = func(s string) {
		masked := maskSensitiveData(s)
		logrus.WithField("context", "GraphQL").Debug(masked)
	}

	return client
}

// maskSensitiveData masks sensitive information in log strings
// This prevents accidental exposure of tokens in debug logs
func maskSensitiveData(s string) string {
	// Mask Authorization header values (Bearer tokens, etc.)
	// Matches: Authorization:[Bearer glpat-xxx...] or Authorization:[glpat-xxx...]
	// This catches both PATs and CI_JOB_TOKENs when used in headers
	authPattern := regexp.MustCompile(`(Authorization:\[)[^\]]+(\])`)
	s = authPattern.ReplaceAllString(s, "${1}***MASKED***${2}")

	// Mask GitLab PAT/Project/Group tokens (glpat-*, glcbt-*, etc.)
	patPattern := regexp.MustCompile(`gl[a-z]{2,4}-[A-Za-z0-9_-]{10,}`)
	s = patPattern.ReplaceAllString(s, "***MASKED_TOKEN***")

	return s
}

// guardGraphQLStatus returns a client that reports a non-2xx GraphQL
// response as an ERROR rather than as an empty result.
//
// The GraphQL library decodes the body first and only consults the status
// code if that decode fails. GitLab answers an unauthorized GraphQL request
// with 401 and a JSON body - `{"message":"401 Unauthorized"}` - which
// decodes perfectly into a response carrying no data and no `errors`. The
// caller therefore receives success and an empty payload, and cannot tell a
// refused request from a project that genuinely has no CI configuration, no
// catalogue entry, or no variables.
//
// Every silent-pass this produces runs the same way: a control reads an
// empty collection, finds nothing to object to, and reports compliant. That
// is the one direction a compliance scanner must never fail in, and it is
// invisible in a log because nothing errored.
//
// The client is copied rather than mutated: it may be one the embedding
// host injected for its own rate limiting (ADR-0021 rule J), and its
// Timeout, redirect policy and cookie jar have to survive. Only the
// transport is wrapped.
func guardGraphQLStatus(client *http.Client) *http.Client {
	guarded := *client
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	guarded.Transport = graphQLStatusGuard{next: next}
	return &guarded
}

// graphQLStatusGuard turns a non-2xx response into a transport error.
type graphQLStatusGuard struct{ next http.RoundTripper }

func (g graphQLStatusGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := g.next.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return resp, nil
	}
	// The body is drained and closed here rather than handed on: returning
	// an error from RoundTrip means nothing downstream will read it, and an
	// unread body leaks the connection.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, graphQLErrorBodyLimit))
	_ = resp.Body.Close()
	return nil, fmt.Errorf("graphql: %s", resp.Status)
}

// graphQLErrorBodyLimit bounds how much of a failed response is drained
// before the connection is released. The content is not used; draining only
// exists so the connection can be reused.
const graphQLErrorBodyLimit = 4 << 10
