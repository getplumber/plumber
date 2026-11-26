package httpcount

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sync"
)

// maxMemoBytes is the largest body Memo keeps. API answers and action
// definitions fit well under it; a bundled dist/index.js (a few MB, read
// once) does not, so the run never holds every entrypoint to its end.
const maxMemoBytes = 1 << 20

// maxMemoTotal bounds the bodies Memo keeps in all: past it new answers go
// to the caller unkept, so memory does not grow with the number of actions
// a run reads. A var so a test can lower it.
var maxMemoTotal = 32 << 20

// Memo is an http.RoundTripper that answers a repeated GET from memory for
// the rest of the process: the same request sent twice in one run reach GitHub once (plumber#618). The same request is the
// same URL and the same headers, every one of them (memoKey). Only definitive answers
// are kept, 2xx and 404: a 403, a 429, a 5xx or a network error is never
// kept, so the next caller asks again. Nothing is written to disk.
//
// Concurrent identical requests are sent once: the first one goes out, the
// others wait for its answer, or for their own context to end, and send
// their own only when it was not kept.
//
// It is for idempotent GitHub reads only (MemoTransport): an answer meant
// to be fresh each time, such as a minted token, must not go through it.
type Memo struct {
	// Next sends the request. Nil means http.DefaultTransport, read at
	// request time.
	Next http.RoundTripper
	// Registry, when set, counts each request answered from memory.
	Registry *Registry

	mu        sync.Mutex
	kept      map[[sha256.Size]byte]*memoEntry
	keptBytes int
	inFlight  map[[sha256.Size]byte]*memoCall
}

type memoEntry struct {
	status int
	header http.Header
	body   []byte
}

type memoCall struct {
	done  chan struct{}
	entry *memoEntry // nil when the answer was not kept
}

// RoundTrip implements http.RoundTripper.
func (m *Memo) RoundTrip(req *http.Request) (*http.Response, error) {
	next := m.Next
	if next == nil {
		next = http.DefaultTransport
	}
	if req.Method != http.MethodGet {
		return next.RoundTrip(req)
	}
	key := memoKey(req)

	m.mu.Lock()
	if e, ok := m.kept[key]; ok {
		m.mu.Unlock()
		return m.hit(req, e), nil
	}
	if c, ok := m.inFlight[key]; ok {
		m.mu.Unlock()
		// The caller's deadline still applies while it waits on another's
		// request, however long that one takes.
		select {
		case <-c.done:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		if c.entry != nil {
			return m.hit(req, c.entry), nil
		}
		return next.RoundTrip(req)
	}
	if m.inFlight == nil {
		m.kept = map[[sha256.Size]byte]*memoEntry{}
		m.inFlight = map[[sha256.Size]byte]*memoCall{}
	}
	c := &memoCall{done: make(chan struct{})}
	m.inFlight[key] = c
	m.mu.Unlock()

	// Deferred so a panic in next still releases the waiters: they find
	// no entry and send their own.
	defer func() {
		m.mu.Lock()
		if c.entry != nil {
			m.kept[key] = c.entry
			m.keptBytes += len(c.entry.body)
		}
		delete(m.inFlight, key)
		m.mu.Unlock()
		close(c.done)
	}()
	resp, err := next.RoundTrip(req)
	if err == nil && m.hasRoom() {
		resp, c.entry = keep(resp)
	}
	return resp, err
}

// hasRoom reports whether the kept bodies are still under maxMemoTotal.
func (m *Memo) hasRoom() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keptBytes < maxMemoTotal
}

// memoKey hashes what makes two GETs the same request: the URL and every
// header, so a Range, an API version or a credential of its own is a
// request of its own. Hashed, so no token is kept in memory.
func memoKey(req *http.Request) [sha256.Size]byte {
	h := sha256.New()
	write := func(s string) {
		_, _ = io.WriteString(h, s)
		_, _ = h.Write([]byte{0})
	}
	write(req.URL.String())
	for _, name := range slices.Sorted(maps.Keys(req.Header)) {
		write(name)
		for _, v := range req.Header[name] {
			write(v)
		}
		_, _ = h.Write([]byte{1})
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

// keep reads a definitive answer into memory and hands the caller a
// response that replays it. Any other answer, or a body past maxMemoBytes,
// goes back to the caller unread.
func keep(resp *http.Response) (*http.Response, *memoEntry) {
	if resp.StatusCode != http.StatusNotFound && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return resp, nil
	}
	if resp.ContentLength > maxMemoBytes {
		return resp, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMemoBytes+1))
	if err != nil || len(body) > maxMemoBytes {
		// Hand back what was read followed by the rest, still unread.
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
		return resp, nil
	}
	_ = resp.Body.Close()
	e := &memoEntry{status: resp.StatusCode, header: resp.Header.Clone(), body: body}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, e
}

func (m *Memo) hit(req *http.Request, e *memoEntry) *http.Response {
	if m.Registry != nil {
		m.Registry.recordMemoHit()
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", e.status, http.StatusText(e.status)),
		StatusCode:    e.status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        e.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(e.body)),
		ContentLength: int64(len(e.body)),
		Request:       req,
	}
}
