package gitlab

import (
	"net/http"
	"strings"
	"time"

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

	// Create HTTP client with retry logic and timeout
	httpClient := &http.Client{
		Transport: WrapTransportWithRetry(http.DefaultTransport, conf),
		Timeout:   conf.HTTPClientTimeout,
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
		client, err = gitlab.NewOAuthClient(token, gitlab.WithHTTPClient(httpClient), gitlab.WithBaseURL(sanitizedInstance))
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

	// Create HTTP client with retry logic
	httpClient := &http.Client{
		Transport: WrapTransportWithRetry(http.DefaultTransport, conf),
		Timeout:   conf.HTTPClientTimeout,
	}

	// Initialize the GraphQL client
	client := graphql.NewClient(url, graphql.WithHTTPClient(httpClient))

	// Optionally add logging for debugging GraphQL queries
	client.Log = func(s string) {
		logrus.WithField("context", "GraphQL").Debug(s)
	}

	return client
}

// GetHTTPClient creates a simple HTTP client with retry logic
func GetHTTPClient(conf *configuration.Configuration) *http.Client {
	timeout := 30 * time.Second
	if conf != nil && conf.HTTPClientTimeout > 0 {
		timeout = conf.HTTPClientTimeout
	}

	return &http.Client{
		Transport: WrapTransportWithRetry(http.DefaultTransport, conf),
		Timeout:   timeout,
	}
}
