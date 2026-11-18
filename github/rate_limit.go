package github

import (
	"net/http"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/getplumber/plumber/internal/httpcount"
)

// rateLimitTransport sends the GET /rate_limit reads. Nil means
// http.DefaultTransport; tests point it at an httptest server. It is not
// httpcount.DefaultTransport on purpose: the --debug report counts the run's
// own requests, and its rate-limit reads cost no quota anyway.
var rateLimitTransport http.RoundTripper

// FetchRateLimit reads GET /rate_limit on host (empty: api.github.com) with
// token (empty: the go-gh default chain), and returns its resources by name
// (core, graphql, search…). GitHub documents that this read costs no quota.
// A GitHub Enterprise Server host with rate limiting off answers 404, which
// comes back as the error.
func FetchRateLimit(host, token string) (map[string]httpcount.RateResource, error) {
	rest, err := api.NewRESTClient(api.ClientOptions{Host: host, AuthToken: token, Transport: rateLimitTransport})
	if err != nil {
		return nil, err
	}
	var body struct {
		Resources map[string]httpcount.RateResource `json:"resources"`
	}
	if err := rest.Get("rate_limit", &body); err != nil {
		return nil, err
	}
	return body.Resources, nil
}
