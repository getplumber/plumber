package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout bounds every platform call. The platform is a third party
// the pipeline must never be coupled to, so a slow or hung endpoint has to
// degrade rather than hold a CI job open.
const DefaultTimeout = 15 * time.Second

// maxErrorBodyBytes caps how much of a non-2xx body is read into an error
// message. Enough to carry the platform's short {"message": "..."} bodies,
// bounded so a misbehaving endpoint cannot stream an unbounded error.
const maxErrorBodyBytes = 512

// maxContextBodyBytes caps the context response. The snapshot carries a
// merged CI config and settings blobs, so this is generous, but a bound
// still exists: an unbounded read is a way to hang a job.
const maxContextBodyBytes = 16 << 20 // 16 MiB, matching the platform's own body limit

// Unavailability reasons the resolve endpoint returns on a 503. Both are
// EXPECTED steady states, not errors to fail a run on.
const (
	// ReasonResolverBusy means the platform's per-instance resolve
	// concurrency cap was saturated.
	ReasonResolverBusy = "resolver_busy"
	// ReasonResolutionUnavailable means the resolution could not be
	// performed: the timebox was exceeded, the git host was unreachable, no
	// org token is configured, or the project was never onboarded.
	ReasonResolutionUnavailable = "resolution_unavailable"
)

// UnavailableError reports a 503 from the resolve endpoint. It is a normal
// outcome, not a failure: the caller degrades the controls that depend on a
// resolved config to not_evaluable and lets everything else run.
type UnavailableError struct {
	// Reason is the platform's machine-readable vocabulary. It falls back
	// to ReasonResolutionUnavailable when the body carried none, so callers
	// always have a reason to report.
	Reason string
}

func (e *UnavailableError) Error() string {
	return "platform: config resolution unavailable (" + e.Reason + ")"
}

// StatusError reports a non-2xx response that is not a handled 503.
type StatusError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return "platform: " + e.Status
	}
	return "platform: " + e.Status + ": " + e.Body
}

// Client talks to the platform's CI-OIDC endpoints. The zero value is not
// usable; build one with NewClient.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient builds a client for baseURL authenticating with token, the CI
// OIDC id-token. Trailing slashes on baseURL are trimmed so callers may
// pass either spelling.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   token,
		http:    &http.Client{Timeout: DefaultTimeout},
	}
}

// WithHTTPClient replaces the transport, for tests and for callers that
// need their own timeout.
func (c *Client) WithHTTPClient(h *http.Client) *Client {
	c.http = h
	return c
}

// projectRoute builds the /api/v1/projects/{project_path}/... URL.
//
// project_path is a SINGLE route segment carrying slashes ("org/repo"), so
// its slashes must reach the platform percent-encoded. The escaping is done
// by hand rather than through net/url: building a *url.URL and setting Path
// re-normalizes %2F back to a literal slash, which would split the project
// path across route segments and never reach the handler's parameter whole.
func (c *Client) projectRoute(projectPath, suffix string) string {
	return c.baseURL + "/api/v1/projects/" + escapePathSegment(projectPath) + suffix
}

// escapePathSegment percent-encodes a string for use as one path segment.
// Every byte outside the unreserved set is encoded, which covers the "/"
// that makes a project path multi-segment as well as any character a group
// or project name may legally contain.
func escapePathSegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9',
			ch == '-', ch == '_', ch == '.', ch == '~':
			b.WriteByte(ch)
		default:
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

// FetchContext reads the project's resolved policy set and cached data
// snapshot. It is always a cache read on the platform side: the CLI never
// triggers a live collection.
//
// The platform answers 200 for any authenticated, self-attributed project,
// INCLUDING one it has never seen (the policy set then falls back to the
// derived default). A 404 is therefore never an expected outcome here.
func (c *Client) FetchContext(projectPath string) (*ProjectContext, error) {
	req, err := http.NewRequest(http.MethodGet, c.projectRoute(projectPath, "/context"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, statusErrorFrom(resp)
	}

	var out ProjectContext
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxContextBodyBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode context response: %w", err)
	}
	return &out, nil
}

// ResolveConfig asks the platform to resolve the CI configuration at sha.
//
// digest and digestVersion are the CLI's own computation and are sent as a
// pair; pass "" for both when the computation aborted, which tells the
// platform to resolve fresh rather than serve a cache entry keyed on a
// digest the CLI could not produce. Sending only one of the two is a 400,
// so this normalizes a half-supplied pair to neither.
//
// A 503 comes back as *UnavailableError - an expected steady state (an
// un-onboarded project, a saturated resolver, an unreachable git host), not
// a reason to fail a run.
func (c *Client) ResolveConfig(projectPath, sha, digest, digestVersion string) (*ResolvedConfig, error) {
	body := ResolveRequest{Sha: sha}
	if digest != "" && digestVersion != "" {
		body.ConfigDigest = digest
		body.DigestVersion = digestVersion
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal resolve request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.projectRoute(projectPath, "/resolved-config"), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, unavailableFrom(resp)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, statusErrorFrom(resp)
	}

	var out ResolvedConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxContextBodyBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode resolved-config response: %w", err)
	}
	return &out, nil
}

// unavailableFrom builds the typed 503. A body that does not parse, or
// carries no reason, still yields a usable reason rather than an opaque
// error: the caller has to name something in its not_evaluable output.
func unavailableFrom(resp *http.Response) error {
	var parsed struct {
		Reason string `json:"reason"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	_ = json.Unmarshal(raw, &parsed)
	if strings.TrimSpace(parsed.Reason) == "" {
		parsed.Reason = ReasonResolutionUnavailable
	}
	return &UnavailableError{Reason: parsed.Reason}
}

// statusErrorFrom builds a StatusError carrying the platform's own
// {"message": "..."} text when there is one, so an operator sees "not the
// attributed project" rather than a bare 403.
func statusErrorFrom(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	msg := strings.TrimSpace(string(raw))
	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &parsed) == nil && strings.TrimSpace(parsed.Message) != "" {
		msg = strings.TrimSpace(parsed.Message)
	}
	return &StatusError{StatusCode: resp.StatusCode, Status: resp.Status, Body: msg}
}

// IsUnavailable reports whether err is a resolve-endpoint 503, and returns
// its reason. Callers use it to pick the not_evaluable reason to report.
func IsUnavailable(err error) (reason string, ok bool) {
	var ue *UnavailableError
	if errors.As(err, &ue) {
		return ue.Reason, true
	}
	return "", false
}
