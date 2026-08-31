package platform

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient wires a Client to a handler and returns both, plus a
// pointer to the last request path the handler saw.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *[]*http.Request) {
	t.Helper()
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Clone(r.Context()))
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-token"), &seen
}

// TestProjectPathReachesTheHandlerWhole is the load-bearing URL test: a
// project path carries slashes but occupies ONE route segment, so its
// slashes must arrive percent-encoded. Going through net/url would
// re-normalize %2F into a literal slash and split the path across segments,
// which the platform's router would never match to :project_path.
func TestProjectPathReachesTheHandlerWhole(t *testing.T) {
	c, seen := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"schema_version":1,"project":"grp/sub/proj","policies":[],"snapshot":{}}`)
	})
	if _, err := c.FetchContext("grp/sub/proj"); err != nil {
		t.Fatalf("FetchContext: %v", err)
	}
	got := (*seen)[0].URL.EscapedPath()
	want := "/api/v1/projects/grp%2Fsub%2Fproj/context"
	if got != want {
		t.Fatalf("request path:\n got  %s\n want %s", got, want)
	}
	// And the server-side decode must recover the original path.
	if decoded := (*seen)[0].URL.Path; decoded != "/api/v1/projects/grp/sub/proj/context" {
		t.Fatalf("decoded path: %s", decoded)
	}
}

func TestFetchContext_DecodesFullShape(t *testing.T) {
	const body = `{
	  "schema_version": 1,
	  "project": "e2e/rail-proj",
	  "policies": [
	    {"id":"33333333-3333-3333-3333-333333339501","name":"Baseline","enforcement":"report"},
	    {"id":"44444444-4444-4444-4444-444444449501","name":"Blocking","enforcement":"block"}
	  ],
	  "snapshot": {
	    "collected_at": "2026-08-24T07:57:30.32668Z",
	    "data": {
	      "schema_version": "1",
	      "merged_yaml": "stages:\n  - build\n",
	      "branch_protection": {"protections": [{"protectionPattern":"main"}]},
	      "mr_approvals": {"rules": [], "settings": {"approvals_before_merge": 2}},
	      "variables": {"items": [{"name":"TOKEN","scope":"project","masked":true}]},
	      "resolution_anchor": {
	        "ref": "main",
	        "sha": "deadbeef",
	        "config_digest": "abc123",
	        "digest_version": "1"
	      }
	    }
	  },
	  "an_unknown_future_field": {"nested": true}
	}`
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})

	ctx, err := c.FetchContext("e2e/rail-proj")
	if err != nil {
		t.Fatalf("FetchContext: %v", err)
	}
	if ctx.SchemaVersion != 1 || ctx.Project != "e2e/rail-proj" {
		t.Fatalf("envelope: %+v", ctx)
	}
	if len(ctx.Policies) != 2 {
		t.Fatalf("want 2 policies, got %d", len(ctx.Policies))
	}
	if !ctx.Policies[1].Enforcement.Blocking() || ctx.Policies[0].Enforcement.Blocking() {
		t.Fatalf("enforcement dials misread: %+v", ctx.Policies)
	}
	if ctx.Snapshot.CollectedAt == nil {
		t.Fatal("collected_at must decode: it is what the run reports as the snapshot's age")
	}
	if got := ctx.Snapshot.CollectedAt.UTC().Format(time.RFC3339); got != "2026-08-24T07:57:30Z" {
		t.Fatalf("collected_at: %s", got)
	}
	anchor := ctx.Snapshot.Anchor()
	if anchor == nil || !anchor.HasDigest() {
		t.Fatalf("anchor: %+v", anchor)
	}
	if !anchor.Matches("abc123", "1") {
		t.Fatal("anchor must match its own digest+version")
	}
	if ctx.Snapshot.Data.MergedYaml == "" {
		t.Fatal("merged_yaml must decode")
	}
	// The raw blobs stay raw and are the provider's to decode.
	if len(ctx.Snapshot.Data.BranchProtection) == 0 || len(ctx.Snapshot.Data.MrApprovals) == 0 || len(ctx.Snapshot.Data.Variables) == 0 {
		t.Fatal("settings blobs must survive as raw JSON")
	}
}

// TestFetchContext_ForwardTolerant: the contract says a CLI must ignore
// fields it does not know. An unknown key anywhere - including inside a
// known object - must never fail the decode.
func TestFetchContext_ForwardTolerant(t *testing.T) {
	const body = `{"schema_version":2,"project":"a/b","future_top":1,
	  "policies":[{"id":"x","name":"n","enforcement":"report","future_policy":true}],
	  "snapshot":{"collected_at":"2026-01-02T03:04:05Z","future_snap":[1,2],
	    "data":{"future_data":{"deep":true},"merged_yaml":"x: 1\n"}}}`
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	ctx, err := c.FetchContext("a/b")
	if err != nil {
		t.Fatalf("unknown fields must not fail the decode: %v", err)
	}
	if ctx.SchemaVersion != 2 || len(ctx.Policies) != 1 || ctx.Snapshot.Data.MergedYaml != "x: 1\n" {
		t.Fatalf("known fields lost while tolerating unknown ones: %+v", ctx)
	}
}

// TestFetchContext_EmptySnapshotIs200: a cache miss is an empty snapshot on
// a 200, never a 404. Reading it must yield honest nils, not an error.
func TestFetchContext_EmptySnapshotIs200(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"schema_version":1,"project":"a/b","policies":[{"id":"`+NilUUID+`","name":"[Plumber default]","enforcement":"report"}],"snapshot":{}}`)
	})
	ctx, err := c.FetchContext("a/b")
	if err != nil {
		t.Fatalf("FetchContext: %v", err)
	}
	if ctx.Snapshot.CollectedAt != nil || ctx.Snapshot.Data != nil {
		t.Fatalf("a cache miss must decode to an honestly empty snapshot, got %+v", ctx.Snapshot)
	}
	if ctx.Snapshot.Anchor() != nil {
		t.Fatal("no data means no anchor")
	}
	if ctx.Policies[0].IsReal() {
		t.Fatal("the derived fallback carries the nil uuid and must never be treated as a real policy id")
	}
}

func TestFetchContext_StatusErrorsCarryThePlatformMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
		want string
	}{
		{"403", http.StatusForbidden, `{"message":"not the attributed project"}`, "not the attributed project"},
		{"401", http.StatusUnauthorized, `{"message":"invalid CI OIDC token"}`, "invalid CI OIDC token"},
		{"500", http.StatusInternalServerError, `{"message":"policy resolution failed"}`, "policy resolution failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := c.FetchContext("a/b")
			var se *StatusError
			if !errors.As(err, &se) {
				t.Fatalf("want a StatusError, got %v", err)
			}
			if se.StatusCode != tc.code || se.Body != tc.want {
				t.Fatalf("got (%d, %q), want (%d, %q)", se.StatusCode, se.Body, tc.code, tc.want)
			}
		})
	}
}

func TestResolveConfig_SendsDigestPairOrNeither(t *testing.T) {
	cases := []struct {
		name          string
		digest, ver   string
		wantDigestKey bool
	}{
		{name: "both present are sent", digest: "abc", ver: "1", wantDigestKey: true},
		{name: "neither is sent when the computation aborted", wantDigestKey: false},
		{name: "a half pair is normalized to neither", digest: "abc", wantDigestKey: false},
		{name: "a version without a digest is also neither", ver: "1", wantDigestKey: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &body)
				_, _ = io.WriteString(w, `{"merged_yaml":"x: 1\n","resolved_sha":"cafe","valid":true,"source":"resolved"}`)
			})
			if _, err := c.ResolveConfig("a/b", "deadbeef", tc.digest, tc.ver); err != nil {
				t.Fatalf("ResolveConfig: %v", err)
			}
			if body["sha"] != "deadbeef" {
				t.Fatalf("sha must always be sent, got %v", body["sha"])
			}
			_, gotDigest := body["config_digest"]
			_, gotVersion := body["digest_version"]
			if gotDigest != tc.wantDigestKey || gotVersion != tc.wantDigestKey {
				t.Fatalf("digest keys present = (%v, %v), want both %v: the pair is all-or-nothing, a half pair is a 400",
					gotDigest, gotVersion, tc.wantDigestKey)
			}
		})
	}
}

func TestResolveConfig_DecodesAndDoesNotAssertShaEquality(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		// A cache hit answers with the CACHED resolution's sha, which
		// legitimately differs from the requested one.
		_, _ = io.WriteString(w, `{"merged_yaml":"stages: [a]\n","resolved_sha":"OTHERSHA","valid":true,"source":"cache","config_digest":"d","digest_version":"1"}`)
	})
	got, err := c.ResolveConfig("a/b", "REQUESTEDSHA", "d", "1")
	if err != nil {
		t.Fatalf("ResolveConfig: %v", err)
	}
	if got.ResolvedSha != "OTHERSHA" || got.Source != "cache" || !got.Valid {
		t.Fatalf("decoded: %+v", got)
	}
}

// TestResolveConfig_InvalidConfigIsA200: GitLab reporting the merge as
// INVALID is a user error in their config, not a resolution failure. It
// must decode cleanly so the caller can report it, not surface as an error.
func TestResolveConfig_InvalidConfigIsA200(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"merged_yaml":"","resolved_sha":"cafe","valid":false,"source":"resolved"}`)
	})
	got, err := c.ResolveConfig("a/b", "cafe", "", "")
	if err != nil {
		t.Fatalf("valid:false is a 200, not an error: %v", err)
	}
	if got.Valid || got.MergedYaml != "" {
		t.Fatalf("decoded: %+v", got)
	}
}

func TestResolveConfig_503IsTypedAndNeverFatal(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantReason string
	}{
		{"resolver busy", `{"reason":"resolver_busy"}`, ReasonResolverBusy},
		{"unavailable", `{"reason":"resolution_unavailable"}`, ReasonResolutionUnavailable},
		{"unknown reason survives", `{"reason":"something_new"}`, "something_new"},
		{"no reason falls back", `{}`, ReasonResolutionUnavailable},
		{"unparseable body falls back", `not json`, ReasonResolutionUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := c.ResolveConfig("a/b", "cafe", "", "")
			reason, ok := IsUnavailable(err)
			if !ok {
				t.Fatalf("a 503 must be a typed UnavailableError, got %v", err)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason: got %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

func TestClient_SendsBearerAndContentType(t *testing.T) {
	c, seen := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"merged_yaml":"","resolved_sha":"s","valid":true,"source":"resolved"}`)
	})
	if _, err := c.ResolveConfig("a/b", "s", "", ""); err != nil {
		t.Fatalf("ResolveConfig: %v", err)
	}
	r := (*seen)[0]
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization: %q", got)
	}
	// The push endpoint parses Content-Type strictly; the resolve endpoint
	// binds a JSON body. Send exactly application/json on both.
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type: %q", got)
	}
}

func TestNewClient_TrimsTrailingSlashes(t *testing.T) {
	for _, in := range []string{"https://p.example.com", "https://p.example.com/", "  https://p.example.com//  "} {
		if got := NewClient(in, "t").baseURL; got != "https://p.example.com" {
			t.Fatalf("NewClient(%q).baseURL = %q", in, got)
		}
	}
}

func TestEscapePathSegment(t *testing.T) {
	cases := map[string]string{
		"org/repo":       "org%2Frepo",
		"a/b/c":          "a%2Fb%2Fc",
		"plain":          "plain",
		"with-dash_u.nd": "with-dash_u.nd",
		"sp ace":         "sp%20ace",
		"pct%":           "pct%25",
	}
	for in, want := range cases {
		if got := escapePathSegment(in); got != want {
			t.Fatalf("escapePathSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFetchContext_TransportErrorIsReturned: an unreachable platform must
// surface as an ordinary error for the caller to degrade on, never a panic
// or a silent empty context.
func TestFetchContext_TransportErrorIsReturned(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", "t")
	c.http = &http.Client{Timeout: 200 * time.Millisecond}
	ctx, err := c.FetchContext("a/b")
	if err == nil {
		t.Fatalf("want a transport error, got context %+v", ctx)
	}
	if !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "dial") {
		t.Logf("transport error (shape is platform-specific): %v", err)
	}
}
