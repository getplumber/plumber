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

// parkedContext tells when its request reached Memo's wait on another's
// request: that select is the only place Memo reads Done.
type parkedContext struct {
	context.Context
	once   sync.Once
	parked chan<- struct{}
}

func (c *parkedContext) Done() <-chan struct{} {
	c.once.Do(func() { c.parked <- struct{}{} })
	return c.Context.Done()
}

// memoTrip sends one GET straight through m and reads the answer.
func memoTrip(ctx context.Context, m *Memo, u string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := m.RoundTrip(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func memoResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: r}
}

// A waiter whose leader got an answer that is not kept sends its own
// request: a 503 is never shared.
func TestMemo_waitersSendTheirOwnWhenTheAnswerIsNotKept(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if hits.Add(1) == 1 {
			<-release
		}
		return memoResponse(r, http.StatusServiceUnavailable, "busy"), nil
	})
	reg := &Registry{}
	m := &Memo{Next: next, Registry: reg}
	const u = "https://api.github.com/repos/o/r"

	const waiters = 3
	statuses := make([]int, waiters+1)
	errs := make([]error, waiters+1)
	var wg sync.WaitGroup
	wg.Go(func() { statuses[0], _, errs[0] = memoTrip(context.Background(), m, u) })
	for hits.Load() == 0 {
		runtime.Gosched()
	}
	parked := make(chan struct{}, waiters)
	for i := 1; i <= waiters; i++ {
		wg.Go(func() {
			statuses[i], _, errs[i] = memoTrip(&parkedContext{Context: context.Background(), parked: parked}, m, u)
		})
	}
	for range waiters {
		<-parked
	}
	close(release)
	wg.Wait()

	if got := hits.Load(); got != waiters+1 {
		t.Fatalf("sent %d requests, want %d: each waiter sends its own", got, waiters+1)
	}
	for i := range statuses {
		if errs[i] != nil || statuses[i] != http.StatusServiceUnavailable {
			t.Fatalf("caller %d got %d, %v, want 503", i, statuses[i], errs[i])
		}
	}
	if got := reg.Snapshot().MemoHits; got != 0 {
		t.Fatalf("memo hits = %d, want 0", got)
	}
}

// A panic in the leader's transport releases a waiter already queued behind
// it: the waiter sends its own request instead of waiting for ever.
func TestMemo_panicInNextReleasesAQueuedWaiter(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int64
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			<-release
			panic("transport bug")
		}
		return memoResponse(r, http.StatusOK, "ok"), nil
	})
	m := &Memo{Next: next}
	const u = "https://api.github.com/repos/o/r"

	var wg sync.WaitGroup
	wg.Go(func() {
		defer func() { _ = recover() }()
		_, _, _ = memoTrip(context.Background(), m, u)
	})
	for calls.Load() == 0 {
		runtime.Gosched()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	parked := make(chan struct{}, 1)
	var status int
	var body string
	var err error
	wg.Go(func() { status, body, err = memoTrip(&parkedContext{Context: ctx, parked: parked}, m, u) })
	<-parked
	close(release)
	wg.Wait()

	if err != nil || status != http.StatusOK || body != "ok" {
		t.Fatalf("waiter got %d %q, %v, want its own 200", status, body, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("sent %d requests, want 2", got)
	}
}

// Every waiter of a kept answer is a memo hit, and none of them is sent.
func TestMemo_countsWaitersAsMemoHits(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		<-release
		return memoResponse(r, http.StatusOK, "shared"), nil
	})
	reg := &Registry{}
	m := &Memo{Next: next, Registry: reg}
	const u = "https://api.github.com/repos/o/r"

	const waiters = 7
	var wg sync.WaitGroup
	wg.Go(func() { _, _, _ = memoTrip(context.Background(), m, u) })
	for hits.Load() == 0 {
		runtime.Gosched()
	}
	parked := make(chan struct{}, waiters)
	bodies := make([]string, waiters)
	for i := range waiters {
		wg.Go(func() {
			_, bodies[i], _ = memoTrip(&parkedContext{Context: context.Background(), parked: parked}, m, u)
		})
	}
	for range waiters {
		<-parked
	}
	close(release)
	wg.Wait()

	for i, b := range bodies {
		if b != "shared" {
			t.Fatalf("waiter %d got %q", i, b)
		}
	}
	snap := reg.Snapshot()
	if hits.Load() != 1 || snap.MemoHits != waiters || snap.Total() != 0 {
		t.Fatalf("sent = %d, memo hits = %d, counted as sent = %d, want 1, %d and 0", hits.Load(), snap.MemoHits, snap.Total(), waiters)
	}
}

// A network error is never kept: the next caller asks again, and the
// answer it gets is the one kept.
func TestMemo_neverKeepsANetworkError(t *testing.T) {
	var calls atomic.Int64
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("dial failed")
		}
		return memoResponse(r, http.StatusOK, "ok"), nil
	})
	reg := &Registry{}
	m := &Memo{Next: next, Registry: reg}
	const u = "https://api.github.com/repos/o/r"

	if _, _, err := memoTrip(context.Background(), m, u); err == nil || err.Error() != "dial failed" {
		t.Fatalf("first GET err = %v, want the network error", err)
	}
	for i := range 2 {
		if status, body, err := memoTrip(context.Background(), m, u); err != nil || status != http.StatusOK || body != "ok" {
			t.Fatalf("GET %d after the error = %d %q, %v", i+2, status, body, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("sent %d requests, want 2: the error is asked again, the 200 is kept", got)
	}
	if got := reg.Snapshot().MemoHits; got != 1 {
		t.Fatalf("memo hits = %d, want 1", got)
	}
}

// A body past maxMemoBytes reaches the caller whole: what Memo read to
// measure it, then the rest.
func TestMemo_oversizeBodyReachesTheCallerWhole(t *testing.T) {
	srv, hits := memoServer(t)
	c := &http.Client{Transport: &Memo{}}
	want := strings.Repeat("x", maxMemoBytes+1)
	for i := range 2 {
		if _, body := memoGet(t, c, srv.URL+"/big", ""); body != want {
			t.Fatalf("GET %d: body is %d bytes (all x: %v), want %d", i+1, len(body), strings.Trim(body, "x") == "", len(want))
		}
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
}

// An answer that declares a body past maxMemoBytes is handed over unread:
// here the body is short, so only the declared length keeps it out.
func TestMemo_declaredOversizeIsNotKept(t *testing.T) {
	var calls atomic.Int64
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		resp := memoResponse(r, http.StatusOK, "short")
		resp.ContentLength = maxMemoBytes + 1
		return resp, nil
	})
	m := &Memo{Next: next}
	for i := range 2 {
		if status, body, err := memoTrip(context.Background(), m, "https://api.github.com/repos/o/r"); err != nil || status != http.StatusOK || body != "short" {
			t.Fatalf("GET %d = %d %q, %v", i+1, status, body, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("sent %d requests, want 2", got)
	}
}

// A body that fails while Memo reads it is not kept, and the caller still
// gets what was read, then the failure.
func TestMemo_bodyReadErrorIsNotKept(t *testing.T) {
	var calls atomic.Int64
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		resp := memoResponse(r, http.StatusOK, "")
		resp.Body = io.NopCloser(io.MultiReader(strings.NewReader("par"), failingReader{}))
		return resp, nil
	})
	m := &Memo{Next: next}
	for i := range 2 {
		status, body, err := memoTrip(context.Background(), m, "https://api.github.com/repos/o/r")
		if status != http.StatusOK || body != "par" || err == nil || err.Error() != "connection reset" {
			t.Fatalf("GET %d = %d %q, %v, want 200, \"par\", then the read error", i+1, status, body, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("sent %d requests, want 2", got)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// Only 2xx and 404 are definitive: an informational, redirect or
// not-modified answer is asked again.
func TestMemo_neverKeepsOtherStatuses(t *testing.T) {
	for _, status := range []int{http.StatusContinue, http.StatusMovedPermanently, http.StatusNotModified, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int64
			m := &Memo{Next: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return memoResponse(r, status, ""), nil
			})}
			for range 2 {
				if got, _, err := memoTrip(context.Background(), m, "https://api.github.com/repos/o/r"); err != nil || got != status {
					t.Fatalf("status = %d, %v, want %d", got, err, status)
				}
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("sent %d requests, want 2", got)
			}
		})
	}
}

// A replay is the kept answer as a response of its own: the headers, the
// length and the asking request, and a caller that changes its headers
// does not change the next replay.
func TestMemo_replayCarriesTheKeptResponse(t *testing.T) {
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp := memoResponse(r, http.StatusNotFound, "gone")
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Set("X-RateLimit-Remaining", "4990")
		return resp, nil
	})
	m := &Memo{Next: next}
	const u = "https://api.github.com/repos/o/r"
	if _, _, err := memoTrip(context.Background(), m, u); err != nil {
		t.Fatal(err)
	}

	for i := range 2 {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		resp, err := m.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || resp.Status != "404 Not Found" || string(body) != "gone" ||
			resp.ContentLength != int64(len("gone")) || resp.Request != req {
			t.Fatalf("replay %d = %d %q %q, length %d, own request %v", i+1, resp.StatusCode, resp.Status, body, resp.ContentLength, resp.Request == req)
		}
		if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("X-RateLimit-Remaining") != "4990" {
			t.Fatalf("replay %d headers = %v", i+1, resp.Header)
		}
		resp.Header.Set("Content-Type", "changed by the caller")
		resp.Header.Del("X-RateLimit-Remaining")
	}
}
