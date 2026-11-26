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

// A read with a token sends that token, and no other; an anonymous read of
// the same host sends none. The transport is a recorder on a plain host
// name: go-gh adds the token only to requests for the client's host, and
// compares it without the port an httptest server has.
func TestFetchRateLimit_sendsTheToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "env-token")
	t.Setenv("GH_ENTERPRISE_TOKEN", "env-token")
	var auth [][]string
	var urls []string
	saved := rateLimitTransport
	rateLimitTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		auth = append(auth, r.Header.Values("Authorization"))
		urls = append(urls, r.URL.String())
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json")
		_, _ = rec.WriteString(`{"resources":{"core":{"limit":5000,"used":1,"remaining":4999,"reset":1795000149}}}`)
		resp := rec.Result()
		resp.Request = r
		return resp, nil
	})
	t.Cleanup(func() { rateLimitTransport = saved })

	for _, token := range []string{"lane-token", ""} {
		got, err := FetchRateLimit("ghes.example.com", token)
		if err != nil {
			t.Fatal(err)
		}
		if got["core"].Limit != 5000 {
			t.Errorf("token %q: resources = %+v", token, got)
		}
	}
	if len(auth) != 2 || len(auth[0]) != 1 || auth[0][0] != "token lane-token" || len(auth[1]) != 0 {
		t.Fatalf("Authorization = %q, want the lane's token then none", auth)
	}
	for _, u := range urls {
		if u != "https://ghes.example.com/api/v3/rate_limit" {
			t.Errorf("URL = %s", u)
		}
	}
}

// anonymousTransport drops the Authorization header from the request it
// sends and leaves the caller's request as it was. With no base it sends
// through http.DefaultTransport.
func TestAnonymousTransport(t *testing.T) {
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Clone())
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	var viaBase int
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		viaBase++
		return http.DefaultTransport.RoundTrip(r)
	})
	for _, tr := range []anonymousTransport{{}, {base: base}} {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/rate_limit", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "token placeholder")
		req.Header.Set("Accept", "application/json")
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("status = %d, want the server's answer", resp.StatusCode)
		}
		if got := req.Header.Get("Authorization"); got != "token placeholder" {
			t.Errorf("caller's Authorization = %q, want it untouched", got)
		}
	}
	if len(seen) != 2 || viaBase != 1 {
		t.Fatalf("server saw %d requests, base sent %d; want 2 and 1", len(seen), viaBase)
	}
	for i, h := range seen {
		if len(h.Values("Authorization")) != 0 || h.Get("Accept") != "application/json" {
			t.Errorf("request %d headers = %v, want no Authorization and the other headers kept", i, h)
		}
	}
}
