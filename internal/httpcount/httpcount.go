// Package httpcount counts the HTTP requests the CLI sends, per host, and
// per rate-limit quota the responses reported. It measures what one run
// costs against the GitHub rate limits (plumber#618).
//
// Not every request costs the token's 5,000/hour: anonymous reads have
// their own 60/hour per IP, /advisories its own bucket, and responses with
// no x-ratelimit headers (raw.githubusercontent.com…) no API quota at all.
// The counts therefore split requests by the quota that answered them.
//
// Counting is opt-in per client: a client sends through DefaultTransport
// (go-gh's api.ClientOptions.Transport, or http.Client.Transport). The
// process-wide http.DefaultTransport is never replaced, because OPA's
// http.send type-asserts it to *http.Transport.
package httpcount

import (
	"fmt"
	"hash/fnv"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Default is the registry DefaultTransport records into.
var Default = &Registry{}

// DefaultTransport counts every request into Default, then sends it through
// http.DefaultTransport.
var DefaultTransport http.RoundTripper = &Transport{Registry: Default}

// MemoTransport answers a repeated GET from memory (Memo), then sends the
// rest through DefaultTransport. It is for the GitHub API and raw-content
// reads only: a minted token, a signed one-shot URL or a version check
// goes through DefaultTransport.
var MemoTransport http.RoundTripper = &Memo{Next: DefaultTransport, Registry: Default}

// Transport is an http.RoundTripper that records each request it sends.
// A redirect is one request per hop, as the http.Client sends each one
// through the transport.
type Transport struct {
	// Next sends the request. Nil means http.DefaultTransport, read at
	// request time.
	Next     http.RoundTripper
	Registry *Registry
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	next := t.Next
	if next == nil {
		next = http.DefaultTransport
	}
	start := time.Now()
	resp, err := next.RoundTrip(req)
	t.Registry.record(req, resp, err, start, time.Since(start))
	return resp, err
}

// HostStats is what one host answered: every request, by status class.
// Errors are requests that got no response at all. Unmetered are the
// responses that carried no x-ratelimit headers (raw.githubusercontent.com,
// the job-log store, the OIDC token): no API quota counts them.
type HostStats struct {
	Requests  int
	Status2xx int
	Status3xx int
	Status4xx int
	Status5xx int
	Errors    int
	Unmetered int
}

// Quota is the lowest remaining a host reported for one resource (core,
// search, graphql…), one credential and one window, and how many of the
// run's requests it answered. Each token, and anonymous reads, have a quota
// of their own, and one resource can run several windows at once: GitHub
// answers /advisories as core from a bucket of its own. Reset is the
// window's end, in Unix seconds.
type Quota struct {
	Host       string
	Resource   string
	Credential string // CredentialKey of the request's Authorization header
	Anonymous  bool
	Limit      int
	Remaining  int
	Reset      int64
	Requests   int
}

// CredentialKey identifies the credential of an Authorization header
// without keeping it: a hash, "" for an anonymous request. A caller that
// knows a token computes the same key to name it in the report.
func CredentialKey(authorization string) string {
	if authorization == "" {
		return ""
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(authorization))
	return fmt.Sprintf("%x", h.Sum64())
}

// Entry is one request of the log EnableLog turns on. Status is 0 when the
// request got no response (Err says why). The rate-limit fields are set
// only when HasQuota: the response carried x-ratelimit headers.
type Entry struct {
	Seq           int
	Offset        time.Duration // since EnableLog
	Method        string
	Host          string
	Path          string
	Query         string // RedactedQuery unless the GitHub API answered
	Status        int
	Err           string
	Duration      time.Duration
	Authenticated bool
	Credential    string // CredentialKey
	HasQuota      bool
	Resource      string
	Limit         int
	Remaining     int
	Used          int
	Reset         int64
}

// Registry holds the counts. It is safe for concurrent use: the lanes of
// an analyze send in parallel.
type Registry struct {
	mu    sync.Mutex
	hosts map[string]HostStats
	// quotas holds the windows of one host, resource and credential.
	quotas map[string][]Quota
	// logging, set by EnableLog, keeps every request in log.
	logging  bool
	logStart time.Time
	log      []Entry
	// memoHits counts the requests Memo answered without sending them.
	memoHits int
	// graphql holds each GraphQL query's cost, in the order sent.
	graphql []GraphQLQuery
}

// GraphQLQuery is one GraphQL query and the cost GitHub reported for it in
// the query's own rateLimit field: points, not requests, so the headers
// alone do not tell it.
type GraphQLQuery struct {
	Label     string
	Cost      int
	Remaining int
}

// RecordGraphQL keeps the cost of one GraphQL query for the report.
func (r *Registry) RecordGraphQL(label string, cost, remaining int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.graphql = append(r.graphql, GraphQLQuery{Label: label, Cost: cost, Remaining: remaining})
}

// RedactedQuery stands for the query of a request the GitHub API did not
// answer. The report is meant to be shared, and only the API is known to
// take no credential in the query: the job-log store and codeload redirect
// to signed URLs whose query is the credential.
const RedactedQuery = "<redacted>"

// resetJitter is how far apart two resets of one window can be: GitHub
// reports the same window ending a second apart.
const resetJitter = 5

// EnableLog keeps every request from now on, for the --debug report. The
// counts run either way; the log is off by default, as it grows with the run.
func (r *Registry) EnableLog() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.logging {
		r.logging = true
		r.logStart = time.Now()
	}
}

func (r *Registry) recordMemoHit() {
	r.mu.Lock()
	r.memoHits++
	r.mu.Unlock()
}

func (r *Registry) record(req *http.Request, resp *http.Response, err error, start time.Time, took time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hosts == nil {
		r.hosts = map[string]HostStats{}
		r.quotas = map[string][]Quota{}
	}
	host := req.URL.Host
	authorization := req.Header.Get("Authorization")
	// The credential is kept as a hash, so no token is kept in memory.
	credential := CredentialKey(authorization)

	var entry *Entry
	if r.logging {
		query := ""
		if req.URL.RawQuery != "" {
			query = RedactedQuery
		}
		r.log = append(r.log, Entry{
			Seq:           len(r.log) + 1,
			Offset:        start.Sub(r.logStart),
			Method:        req.Method,
			Host:          host,
			Path:          req.URL.Path,
			Query:         query,
			Duration:      took,
			Authenticated: authorization != "",
			Credential:    credential,
		})
		entry = &r.log[len(r.log)-1]
	}

	s := r.hosts[host]
	s.Requests++
	switch {
	case err != nil || resp == nil:
		s.Errors++
		if entry != nil && err != nil {
			entry.Err = err.Error()
		}
	case resp.StatusCode >= 500:
		s.Status5xx++
	case resp.StatusCode >= 400:
		s.Status4xx++
	case resp.StatusCode >= 300:
		s.Status3xx++
	default:
		s.Status2xx++
	}
	if resp == nil {
		r.hosts[host] = s
		return
	}
	if entry != nil {
		entry.Status = resp.StatusCode
	}
	limit, errLimit := strconv.Atoi(resp.Header.Get("X-Ratelimit-Limit"))
	remaining, errRemaining := strconv.Atoi(resp.Header.Get("X-Ratelimit-Remaining"))
	if errLimit != nil || errRemaining != nil {
		s.Unmetered++
		r.hosts[host] = s
		return
	}
	r.hosts[host] = s
	reset, _ := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Reset"), 10, 64)
	resource := resp.Header.Get("X-Ratelimit-Resource")
	if entry != nil {
		used, _ := strconv.Atoi(resp.Header.Get("X-Ratelimit-Used"))
		entry.Query = req.URL.RawQuery
		entry.HasQuota, entry.Resource, entry.Limit, entry.Remaining, entry.Used, entry.Reset = true, resource, limit, remaining, used, reset
	}
	key := host + " " + resource + " " + credential
	windows := r.quotas[key]
	for i, w := range windows {
		if max(reset, w.Reset)-min(reset, w.Reset) > resetJitter {
			continue
		}
		// Parallel lanes finish out of order, so the last response is not
		// the latest quota: keep the lowest remaining.
		if remaining < w.Remaining {
			windows[i].Remaining = remaining
		}
		windows[i].Reset = max(reset, w.Reset)
		windows[i].Requests++
		return
	}
	r.quotas[key] = append(windows, Quota{Host: host, Resource: resource, Credential: credential, Anonymous: authorization == "",
		Limit: limit, Remaining: remaining, Reset: reset, Requests: 1})
}

// Snapshot is a copy of the counts at one point in time. Entries is empty
// unless EnableLog was called. MemoHits are the requests answered from
// memory, never sent: they are in no other count.
type Snapshot struct {
	Hosts    map[string]HostStats
	Quotas   []Quota
	Entries  []Entry
	MemoHits int
	GraphQL  []GraphQLQuery
}

// Snapshot copies the counts. Quotas are sorted by host, resource,
// credential (tokens before anonymous, then by limit), then window.
func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := Snapshot{Hosts: maps.Clone(r.hosts), Entries: slices.Clone(r.log), MemoHits: r.memoHits, GraphQL: slices.Clone(r.graphql)}
	for _, windows := range r.quotas {
		snap.Quotas = append(snap.Quotas, windows...)
	}
	sort.Slice(snap.Quotas, func(i, j int) bool {
		a, b := snap.Quotas[i], snap.Quotas[j]
		switch {
		case a.Host != b.Host:
			return a.Host < b.Host
		case a.Resource != b.Resource:
			return a.Resource < b.Resource
		case a.Anonymous != b.Anonymous:
			return !a.Anonymous
		case a.Limit != b.Limit:
			return a.Limit > b.Limit
		case a.Reset != b.Reset:
			return a.Reset < b.Reset
		}
		return a.Remaining < b.Remaining
	})
	return snap
}

// Total is the number of requests sent to every host.
func (s Snapshot) Total() int {
	n := 0
	for _, h := range s.Hosts {
		n += h.Requests
	}
	return n
}
