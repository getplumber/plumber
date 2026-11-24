package httpcount

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memoServer answers /ok 200, /missing 404, /limited 403, /boom 502 and
// /big a body past maxMemoBytes, counting the requests it receives.
func memoServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/limited":
			w.WriteHeader(http.StatusForbidden)
		case "/boom":
			w.WriteHeader(http.StatusBadGateway)
		case "/big":
			_, _ = io.WriteString(w, strings.Repeat("x", maxMemoBytes+1))
			return
		}
		_, _ = io.WriteString(w, "body of "+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func memoGet(t *testing.T, c *http.Client, u, authorization string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestMemo_answersRepeatedDefinitiveGETsFromMemory(t *testing.T) {
	srv, hits := memoServer(t)
	reg := &Registry{}
	c := &http.Client{Transport: &Memo{Next: &Transport{Registry: reg}, Registry: reg}}

	for _, p := range []string{"/ok", "/missing"} {
		status1, body1 := memoGet(t, c, srv.URL+p, "token a")
		status2, body2 := memoGet(t, c, srv.URL+p, "token a")
		if status1 != status2 || body1 != body2 {
			t.Fatalf("%s: replay = %d %q, want %d %q", p, status2, body2, status1, body1)
		}
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
	snap := reg.Snapshot()
	if snap.MemoHits != 2 || snap.Total() != 2 {
		t.Fatalf("memo hits = %d, sent = %d, want 2 and 2", snap.MemoHits, snap.Total())
	}
}

func TestMemo_sendsAgain(t *testing.T) {
	for _, tc := range []struct {
		name, path, auth1, auth2 string
	}{
		{"rate limited", "/limited", "token a", "token a"},
		{"server error", "/boom", "token a", "token a"},
		{"too large to keep", "/big", "token a", "token a"},
		{"other credential", "/ok", "token a", "token b"},
		{"anonymous then authenticated", "/ok", "", "token a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, hits := memoServer(t)
			c := &http.Client{Transport: &Memo{}}
			_, body1 := memoGet(t, c, srv.URL+tc.path, tc.auth1)
			_, body2 := memoGet(t, c, srv.URL+tc.path, tc.auth2)
			if got := hits.Load(); got != 2 {
				t.Fatalf("server saw %d requests, want 2", got)
			}
			if body1 != body2 {
				t.Fatalf("bodies differ: %d and %d bytes", len(body1), len(body2))
			}
		})
	}
}

func TestMemo_neverKeepsOtherMethods(t *testing.T) {
	srv, hits := memoServer(t)
	c := &http.Client{Transport: &Memo{}}
	for range 2 {
		resp, err := c.Post(srv.URL+"/ok", "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
}

func TestMemo_sendsConcurrentIdenticalGETsOnce(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	slow := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("shared")), Request: r}, nil
	})
	reg := &Registry{}
	c := &http.Client{Transport: &Memo{Next: slow, Registry: reg}}

	const callers = 8
	var wg sync.WaitGroup
	bodies := make([]string, callers)
	for i := range callers {
		wg.Go(func() { _, bodies[i] = memoGet(t, c, "https://api.github.com/repos/o/r", "token a") })
	}
	// Hold the first request at the server so the others queue behind it.
	for hits.Load() == 0 {
		runtime.Gosched()
	}
	close(release)
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("sent %d requests, want 1", got)
	}
	for i, b := range bodies {
		if b != "shared" {
			t.Fatalf("caller %d got %q", i, b)
		}
	}
}

func TestMemo_waiterHonoursItsOwnContext(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	stalled := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("late")), Request: r}, nil
	})
	m := &Memo{Next: stalled}
	const u = "https://api.github.com/repos/o/r"

	var leader sync.WaitGroup
	leader.Go(func() {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if resp, err := m.RoundTrip(req); err == nil {
			_ = resp.Body.Close()
		}
	})
	defer func() {
		close(release)
		leader.Wait()
	}()
	for hits.Load() == 0 {
		runtime.Gosched()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if _, err := m.RoundTrip(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter err = %v, want its own deadline", err)
	}
}

func TestMemo_panicInNextReleasesTheKey(t *testing.T) {
	var calls atomic.Int64
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			panic("transport bug")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	m := &Memo{Next: next}
	const u = "https://api.github.com/repos/o/r"
	func() {
		defer func() { _ = recover() }()
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		_, _ = m.RoundTrip(req)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatalf("the GET after a panic must go out, got %v", err)
	}
	_ = resp.Body.Close()
	if got := calls.Load(); got != 2 {
		t.Fatalf("sent %d requests, want 2", got)
	}
}

func TestMemo_otherHeadersAreOtherRequests(t *testing.T) {
	for _, header := range []string{"Range", "X-GitHub-Api-Version", "If-None-Match"} {
		t.Run(header, func(t *testing.T) {
			srv, hits := memoServer(t)
			c := &http.Client{Transport: &Memo{}}
			for _, v := range []string{"a", "b"} {
				req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ok", nil)
				req.Header.Set(header, v)
				resp, err := c.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
			}
			if got := hits.Load(); got != 2 {
				t.Fatalf("server saw %d requests, want 2", got)
			}
		})
	}
}

func TestMemo_stopsKeepingPastTheTotalBudget(t *testing.T) {
	old := maxMemoTotal
	maxMemoTotal = len("body of /ok")
	t.Cleanup(func() { maxMemoTotal = old })
	srv, hits := memoServer(t)
	c := &http.Client{Transport: &Memo{}}

	for range 2 {
		memoGet(t, c, srv.URL+"/ok", "")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want 1: the first answer fits the budget", got)
	}
	for range 2 {
		memoGet(t, c, srv.URL+"/missing", "")
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("server saw %d requests, want 3: past the budget nothing new is kept", got)
	}
	memoGet(t, c, srv.URL+"/ok", "")
	if got := hits.Load(); got != 3 {
		t.Fatalf("server saw %d requests, want 3: what was kept still answers", got)
	}
}
