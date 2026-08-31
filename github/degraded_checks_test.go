package github

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/getplumber/plumber/internal/ir"
)

// stubbedMetadataClient returns a client whose REST calls are answered by
// respond. TestMain disables the API package-wide, so the instance is
// re-enabled here the way the other enrichment tests do.
func stubbedMetadataClient(t *testing.T, respond func(*http.Request) (string, int)) *GitHubMetadataClient {
	t.Helper()
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, status := respond(r)
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	client := NewGitHubMetadataClientForHost("")
	client.disabled = false
	rest, err := api.NewRESTClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new rest client: %v", err)
	}
	client.rest = rest
	return client
}

func pipelineWithOneAction(uses string) *ir.NormalizedPipeline {
	return &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "build", Uses: []ir.Action{{Uses: uses}}}},
	}
}

// TestAdvisoryLookupFailureIsNotACleanBillOfHealth covers the silent pass on
// the one control whose entire purpose is knowing about published CVEs.
//
// A 403 secondary rate limit on /advisories left an empty result cached and
// served as an answer, so every action from that repo reported clean on
// ISSUE-703. Nothing logged, nothing warned: the check simply did not happen
// and the report said it passed.
func TestAdvisoryLookupFailureIsNotACleanBillOfHealth(t *testing.T) {
	client := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/advisories"):
			// The failure under test.
			return `{"message":"API rate limit exceeded"}`, http.StatusForbidden
		case strings.Count(p, "/") == 3 && strings.HasPrefix(p, "/repos/"):
			return `{"archived":false,"stargazers_count":900}`, http.StatusOK
		case strings.Contains(p, "/releases"):
			return `[]`, http.StatusOK
		}
		return `{}`, http.StatusNotFound
	})

	pipeline := pipelineWithOneAction("actions/checkout@v4")
	enrichActionsWithClient(pipeline, client, false, nil)

	if len(pipeline.AdvisoryWarnings) == 0 {
		t.Fatal("a failed advisory lookup must warn; an empty result is otherwise indistinguishable from 'no known CVEs'")
	}
	joined := strings.Join(pipeline.AdvisoryWarnings, " | ")
	if !strings.Contains(joined, "actions/checkout") {
		t.Errorf("the warning must name the action it applies to, got %q", joined)
	}
}

// TestUnavailableMetadataClientWarnsRatherThanPassing covers the widest
// silent pass on this provider.
//
// With no usable token the enrichment returned before touching a single
// action, so no action carried .Metadata, every rule reading it never fired,
// and nine controls reported passed over an enrichment that never ran. The
// cause was recorded on the client and never read by anything.
func TestUnavailableMetadataClientWarnsRatherThanPassing(t *testing.T) {
	client := NewGitHubMetadataClientForHost("")
	client.disabled = true

	pipeline := pipelineWithOneAction("actions/checkout@v4")
	enrichActionsWithClient(pipeline, client, false, nil)

	if len(pipeline.AdvisoryWarnings) == 0 {
		t.Fatal("an unavailable metadata client must warn; otherwise every metadata-driven control reports a pass it did not earn")
	}
	if !strings.Contains(strings.Join(pipeline.AdvisoryWarnings, " | "), "unavailable") {
		t.Errorf("the warning must say enrichment was unavailable, got %q", pipeline.AdvisoryWarnings)
	}
}

// TestAvailableClientWithCleanAdvisoriesDoesNotWarn is the negative case: a
// lookup that genuinely succeeded and found nothing must stay silent, or the
// warning channel becomes noise and gets ignored.
func TestAvailableClientWithCleanAdvisoriesDoesNotWarn(t *testing.T) {
	client := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/advisories"):
			return `[]`, http.StatusOK
		case strings.Count(p, "/") == 3 && strings.HasPrefix(p, "/repos/"):
			return `{"archived":false,"stargazers_count":900}`, http.StatusOK
		case strings.Contains(p, "/releases"):
			return `[]`, http.StatusOK
		}
		return `{}`, http.StatusNotFound
	})

	pipeline := pipelineWithOneAction("actions/checkout@v4")
	enrichActionsWithClient(pipeline, client, false, nil)

	for _, w := range pipeline.AdvisoryWarnings {
		if strings.Contains(w, "Advisory Database could not be queried") {
			t.Errorf("a successful empty lookup must not warn, got %q", w)
		}
	}
}

// TestUnreadableRepoDoesNotReportNotArchived covers ISSUE-702's silent pass.
//
// The repo object feeds RepoArchived, and an unreadable repo yields the zero
// entry, so archived=false: the control's PASS verdict, produced for an
// action nobody could look at. The rule fires only on archived==true, so no
// Rego guard can catch this; the collector has to say so.
func TestUnreadableRepoDoesNotReportNotArchived(t *testing.T) {
	client := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		p := r.URL.Path
		switch {
		case strings.Count(p, "/") == 3 && strings.HasPrefix(p, "/repos/"):
			// The failure under test: the repo object is unreadable.
			return `{"message":"Must have admin rights"}`, http.StatusForbidden
		case strings.HasPrefix(p, "/advisories"):
			return `[]`, http.StatusOK
		case strings.Contains(p, "/releases"):
			return `[]`, http.StatusOK
		}
		return `{}`, http.StatusNotFound
	})

	pipeline := pipelineWithOneAction("actions/checkout@v4")
	enrichActionsWithClient(pipeline, client, false, nil)

	joined := strings.Join(pipeline.AdvisoryWarnings, " | ")
	if !strings.Contains(joined, "archived-repo check was skipped") {
		t.Fatalf("an unreadable repo must warn that the archived check did not happen, got %q", joined)
	}
}

// TestReadableRepoDoesNotWarnAboutArchived is the negative case: a repo that
// was read must not produce the warning, or it becomes noise.
func TestReadableRepoDoesNotWarnAboutArchived(t *testing.T) {
	client := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		p := r.URL.Path
		switch {
		case strings.Count(p, "/") == 3 && strings.HasPrefix(p, "/repos/"):
			return `{"archived":false,"stargazers_count":900}`, http.StatusOK
		case strings.HasPrefix(p, "/advisories"):
			return `[]`, http.StatusOK
		case strings.Contains(p, "/releases"):
			return `[]`, http.StatusOK
		}
		return `{}`, http.StatusNotFound
	})

	pipeline := pipelineWithOneAction("actions/checkout@v4")
	enrichActionsWithClient(pipeline, client, false, nil)

	if strings.Contains(strings.Join(pipeline.AdvisoryWarnings, " | "), "archived-repo check was skipped") {
		t.Errorf("a repo that was read must not warn, got %q", pipeline.AdvisoryWarnings)
	}
}
