package httpcount

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
)

func newClient(reg *Registry, next http.RoundTripper) *http.Client {
	return &http.Client{Transport: &Transport{Next: next, Registry: reg}}
}

func get(t *testing.T, c *http.Client, u string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	_ = resp.Body.Close()
}

func TestTransport_countsByHostAndStatusClass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/boom":
			w.WriteHeader(http.StatusBadGateway)
		case "/same":
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer srv.Close()

	reg := &Registry{}
	c := newClient(reg, nil)
	for _, p := range []string{"/ok", "/ok", "/missing", "/boom", "/same"} {
		get(t, c, srv.URL+p)
	}

	host := mustHost(t, srv.URL)
	got := reg.Snapshot().Hosts[host]
	want := HostStats{Requests: 5, Status2xx: 2, Status3xx: 1, Status4xx: 1, Status5xx: 1, Unmetered: 5}
	if got != want {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

func TestTransport_countsEveryRedirectHop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusMovedPermanently)
		}
	}))
	defer srv.Close()

	reg := &Registry{}
	get(t, newClient(reg, nil), srv.URL+"/old")

	got := reg.Snapshot().Hosts[mustHost(t, srv.URL)]
	if want := (HostStats{Requests: 2, Status2xx: 1, Status3xx: 1, Unmetered: 2}); got != want {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

func TestTransport_countsTransportErrors(t *testing.T) {
	reg := &Registry{}
	failing := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial failed") })
	if _, err := newClient(reg, failing).Get("https://api.github.com/repos/o/r"); err == nil {
		t.Fatal("want an error")
	}
	if got := reg.Snapshot().Hosts["api.github.com"]; got != (HostStats{Requests: 1, Errors: 1}) {
		t.Fatalf("stats = %+v", got)
	}
}

// Responses arrive out of order: a window keeps its lowest remaining,
// whatever order the responses came in. Two windows of one resource (the
// /advisories bucket next to core) are two quotas.
func TestTransport_keepsLowestQuotaPerWindow(t *testing.T) {
	cases := []struct {
		name      string
		responses [][2]string // {remaining, reset}
		want      []Quota
	}{
		{name: "in order", responses: [][2]string{{"4999", "100"}, {"4998", "100"}}, want: []Quota{{Remaining: 4998, Reset: 100, Requests: 2}}},
		{name: "out of order", responses: [][2]string{{"4997", "100"}, {"4999", "100"}}, want: []Quota{{Remaining: 4997, Reset: 100, Requests: 2}}},
		{
			name:      "two windows",
			responses: [][2]string{{"4930", "200"}, {"4147", "100"}, {"4929", "200"}},
			want:      []Quota{{Remaining: 4147, Reset: 100, Requests: 1}, {Remaining: 4929, Reset: 200, Requests: 2}},
		},
		{
			name:      "a window reported a second apart",
			responses: [][2]string{{"4898", "201"}, {"4786", "200"}},
			want:      []Quota{{Remaining: 4786, Reset: 201, Requests: 2}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-RateLimit-Limit", "5000")
				w.Header().Set("X-RateLimit-Resource", "core")
				w.Header().Set("X-RateLimit-Remaining", tc.responses[n][0])
				w.Header().Set("X-RateLimit-Reset", tc.responses[n][1])
				n++
			}))
			defer srv.Close()

			reg := &Registry{}
			c := newClient(reg, nil)
			for range tc.responses {
				get(t, c, srv.URL)
			}

			want := slices.Clone(tc.want)
			for i := range want {
				want[i].Host, want[i].Resource, want[i].Anonymous, want[i].Limit = mustHost(t, srv.URL), "core", true, 5000
			}
			if got := reg.Snapshot().Quotas; !slices.Equal(got, want) {
				t.Fatalf("quotas =\n%+v\nwant\n%+v", got, want)
			}
		})
	}
}

// Each token and anonymous reads have their own quota: an anonymous answer
// in a later window must not hide the token's quota.
func TestTransport_keepsQuotaPerCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Resource", "core")
		switch r.Header.Get("Authorization") {
		case "":
			w.Header().Set("X-RateLimit-Limit", "60")
			w.Header().Set("X-RateLimit-Remaining", "59")
			w.Header().Set("X-RateLimit-Reset", "300")
		case "token a":
			w.Header().Set("X-RateLimit-Limit", "5000")
			w.Header().Set("X-RateLimit-Remaining", "4000")
			w.Header().Set("X-RateLimit-Reset", "100")
		default:
			w.Header().Set("X-RateLimit-Limit", "5000")
			w.Header().Set("X-RateLimit-Remaining", "4500")
			w.Header().Set("X-RateLimit-Reset", "200")
		}
	}))
	defer srv.Close()

	reg := &Registry{}
	c := newClient(reg, nil)
	for _, auth := range []string{"token a", "", "token b"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	host := mustHost(t, srv.URL)
	want := []Quota{
		{Host: host, Resource: "core", Credential: CredentialKey("token a"), Limit: 5000, Remaining: 4000, Reset: 100, Requests: 1},
		{Host: host, Resource: "core", Credential: CredentialKey("token b"), Limit: 5000, Remaining: 4500, Reset: 200, Requests: 1},
		{Host: host, Resource: "core", Anonymous: true, Limit: 60, Remaining: 59, Reset: 300, Requests: 1},
	}
	if got := reg.Snapshot().Quotas; !slices.Equal(got, want) {
		t.Fatalf("quotas =\n%+v\nwant\n%+v", got, want)
	}
}

func TestTransport_concurrentRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	reg := &Registry{}
	c := newClient(reg, nil)
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { get(t, c, srv.URL) })
	}
	wg.Wait()

	if got := reg.Snapshot().Total(); got != 50 {
		t.Fatalf("total = %d, want 50", got)
	}
}

// A go-gh REST client given the transport counts what it sends.
func TestTransport_goghRESTClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	reg := &Registry{}
	host := mustHost(t, srv.URL)
	rest, err := api.NewRESTClient(api.ClientOptions{
		Host:      host,
		AuthToken: "test",
		Transport: &Transport{Next: srv.Client().Transport, Registry: reg},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := rest.Get("repos/o/r", &out); err != nil {
		t.Fatal(err)
	}
	if got := reg.Snapshot().Hosts[host]; got != (HostStats{Requests: 1, Status2xx: 1, Unmetered: 1}) {
		t.Fatalf("stats = %+v", got)
	}
}

// The report names a credential by computing the key record stored for it.
func TestCredentialKey(t *testing.T) {
	if CredentialKey("") != "" {
		t.Fatal("anonymous must key as empty")
	}
	if CredentialKey("token a") == CredentialKey("token b") {
		t.Fatal("two tokens share a key")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4999")
	}))
	defer srv.Close()
	reg := &Registry{}
	reg.EnableLog()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "token a")
	resp, err := newClient(reg, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	snap := reg.Snapshot()
	if snap.Entries[0].Credential != CredentialKey("token a") || snap.Quotas[0].Credential != CredentialKey("token a") {
		t.Fatalf("stored keys %q / %q, want %q", snap.Entries[0].Credential, snap.Quotas[0].Credential, CredentialKey("token a"))
	}
}

// The log is off by default: a run without --debug keeps only the counts.
func TestRegistry_logOffByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	reg := &Registry{}
	get(t, newClient(reg, nil), srv.URL)
	if snap := reg.Snapshot(); len(snap.Entries) != 0 || snap.Total() != 1 {
		t.Fatalf("entries = %d, total = %d", len(snap.Entries), snap.Total())
	}
}

// With the log on, every hop is an entry carrying its path, query, status
// and the quota headers.
func TestRegistry_logRecordsEveryRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/repos/o/r?per_page=100", http.StatusMovedPermanently)
			return
		}
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4990")
		w.Header().Set("X-RateLimit-Used", "10")
		w.Header().Set("X-RateLimit-Resource", "core")
		w.Header().Set("X-RateLimit-Reset", "100")
	}))
	defer srv.Close()

	reg := &Registry{}
	reg.EnableLog()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/old", nil)
	req.Header.Set("Authorization", "token secret")
	resp, err := newClient(reg, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	entries := reg.Snapshot().Entries
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if e := entries[0]; e.Seq != 1 || e.Path != "/old" || e.Status != 301 || e.HasQuota {
		t.Fatalf("first hop = %+v", e)
	}
	e := entries[1]
	if e.Seq != 2 || e.Method != "GET" || e.Path != "/repos/o/r" || e.Query != "per_page=100" || e.Status != 200 ||
		!e.Authenticated || !e.HasQuota || e.Resource != "core" || e.Remaining != 4990 || e.Used != 10 || e.Reset != 100 {
		t.Fatalf("second hop = %+v", e)
	}
}

// A query the GitHub API did not answer can be the credential of a signed
// URL (the job-log store's SAS): the log keeps it redacted, so the shared
// report never carries it. A request with no query stays without one.
func TestRegistry_logRedactsUnmeteredQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	reg := &Registry{}
	reg.EnableLog()
	get(t, newClient(reg, nil), srv.URL+"/blob?sig=secret&se=2026-11-19")
	get(t, newClient(reg, nil), srv.URL+"/plain")

	snap := reg.Snapshot()
	if len(snap.Entries) != 2 || snap.Entries[0].Query != RedactedQuery || snap.Entries[1].Query != "" {
		t.Fatalf("entries = %+v", snap.Entries)
	}
	var b strings.Builder
	if err := (Report{Snapshot: snap}).WriteMarkdown(&b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "secret") {
		t.Fatalf("report carries the signed query:\n%s", b.String())
	}
}

func TestTemplate(t *testing.T) {
	cases := []struct{ host, path, want string }{
		{"api.github.com", "/repos/actions/checkout", "/repos/{owner}/{repo}"},
		{"api.github.com", "/repos/actions/checkout/git/ref/tags/v4", "/repos/{owner}/{repo}/git/ref/tags/{tag}"},
		{"api.github.com", "/repos/actions/checkout/git/ref/tags/release/v4", "/repos/{owner}/{repo}/git/ref/tags/{tag}"},
		{"api.github.com", "/repos/actions/checkout/git/tags/abc123", "/repos/{owner}/{repo}/git/tags/{sha}"},
		{"api.github.com", "/repos/o/r/branches", "/repos/{owner}/{repo}/branches"},
		{"api.github.com", "/repos/o/r/branches/release/v1/protection", "/repos/{owner}/{repo}/branches/{branch}/protection"},
		{"api.github.com", "/repos/o/r/branches/release/v1", "/repos/{owner}/{repo}/branches/{branch}"},
		{"api.github.com", "/repos/o/r/rules/branches/main", "/repos/{owner}/{repo}/rules/branches/{branch}"},
		{"api.github.com", "/repos/o/r/commits/abc123", "/repos/{owner}/{repo}/commits/{ref}"},
		{"api.github.com", "/repos/o/r/releases", "/repos/{owner}/{repo}/releases"},
		{"api.github.com", "/repos/o/r/releases/latest", "/repos/{owner}/{repo}/releases/latest"},
		{"api.github.com", "/repos/o/r/releases/tags/v1.2.3", "/repos/{owner}/{repo}/releases/tags/{tag}"},
		{"api.github.com", "/repos/o/r/tags", "/repos/{owner}/{repo}/tags"},
		{"api.github.com", "/repos/o/r/contents/.github/workflows/ci.yml", "/repos/{owner}/{repo}/contents/{path}"},
		{"api.github.com", "/repos/o/r/contents", "/repos/{owner}/{repo}/contents/{path}"},
		{"api.github.com", "/repos/o/r/environments", "/repos/{owner}/{repo}/environments"},
		{"api.github.com", "/repos/o/r/actions/workflows", "/repos/{owner}/{repo}/actions/workflows"},
		{"api.github.com", "/repos/o/r/actions/runs", "/repos/{owner}/{repo}/actions/runs"},
		{"api.github.com", "/repos/o/r/actions/runs/42/jobs", "/repos/{owner}/{repo}/actions/runs/{run_id}/jobs"},
		{"api.github.com", "/repos/o/r/actions/jobs/42/logs", "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs"},
		{"api.github.com", "/advisories", "/advisories"},
		{"api.github.com", "/rate_limit", "/rate_limit"},
		{"api.github.com", "/repos/o/r/pulls", "/repos/o/r/pulls"},
		{"ghes.example.com", "/api/v3/repos/o/r/tags", "/api/v3/repos/{owner}/{repo}/tags"},
		{"raw.githubusercontent.com", "/actions/checkout/abc123/action.yml", "/{owner}/{repo}/{ref}/action.yml"},
		{"raw.githubusercontent.com", "/o/r/v1/dist/index.js", "/{owner}/{repo}/{ref}/dist/index.js"},
	}
	for _, tc := range cases {
		if got := Template(tc.host, tc.path); got != tc.want {
			t.Errorf("Template(%q, %q) = %q, want %q", tc.host, tc.path, got, tc.want)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
