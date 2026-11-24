package github

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/getplumber/plumber/internal/httpcount"
)

func serveRateLimit(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	saved := rateLimitTransport
	rateLimitTransport = srv.Client().Transport
	t.Cleanup(func() { rateLimitTransport = saved })
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func TestFetchRateLimit(t *testing.T) {
	host := serveRateLimit(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/rate_limit" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"resources":{
			"core":{"limit":5000,"used":405,"remaining":4595,"reset":1795000149},
			"graphql":{"limit":5000,"used":0,"remaining":5000,"reset":1795000149}},
			"rate":{"limit":5000,"used":405,"remaining":4595,"reset":1795000149}}`))
	})

	got, err := FetchRateLimit(host, "test")
	if err != nil {
		t.Fatal(err)
	}
	want := httpcount.RateResource{Limit: 5000, Used: 405, Remaining: 4595, Reset: 1795000149}
	if got["core"] != want || len(got) != 2 {
		t.Fatalf("resources = %+v", got)
	}
}

// GHES with rate limiting off answers 404: an error, never a panic or an
// empty success.
func TestFetchRateLimit_disabled(t *testing.T) {
	host := serveRateLimit(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })

	if got, err := FetchRateLimit(host, "test"); err == nil {
		t.Fatalf("want an error, got %+v", got)
	}
}

// The --debug report shows the run's own requests: its rate-limit reads
// are not counted.
func TestFetchRateLimit_notCounted(t *testing.T) {
	host := serveRateLimit(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"resources":{}}`)) })

	before := httpcount.Default.Snapshot().Hosts[host]
	if _, err := FetchRateLimit(host, "test"); err != nil {
		t.Fatal(err)
	}
	if after := httpcount.Default.Snapshot().Hosts[host]; after != before {
		t.Fatalf("rate-limit read was counted: %+v → %+v", before, after)
	}
}

// An empty token is the anonymous lane: the read goes out with no
// Authorization header, even with no token in the environment (go-gh
// refuses to build a client without one).
func TestFetchRateLimit_anonymous(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	t.Setenv("GITHUB_ENTERPRISE_TOKEN", "")
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	var auth []string
	host := serveRateLimit(t, func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Values("Authorization")...)
		_, _ = w.Write([]byte(`{"resources":{"core":{"limit":60,"used":3,"remaining":57,"reset":1795000149}}}`))
	})

	got, err := FetchRateLimit(host, "")
	if err != nil {
		t.Fatal(err)
	}
	if got["core"].Limit != 60 || len(auth) != 0 {
		t.Fatalf("resources = %+v, Authorization = %q, want the anonymous quota and no header", got, auth)
	}
}
