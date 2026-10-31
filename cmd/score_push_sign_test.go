package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
	providerPkg "github.com/getplumber/plumber/provider"
)

// signedPushHarness wires a GitHub Actions push against stub OIDC and score
// servers and returns a getter for the bundle header the score service saw
// and whether it was pushed at all.
func signedPushHarness(t *testing.T) (p providerPkg.Provider, header func() (string, bool)) {
	t.Helper()
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "id-tok"})
	}))
	t.Cleanup(oidc.Close)
	var got atomic.Value
	var pushed atomic.Bool
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get(scoreBundleHeader))
		pushed.Store(true)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(score.Close)

	oldPush, oldEnd := pushScore, scoreEndpoint
	t.Cleanup(func() { pushScore, scoreEndpoint = oldPush, oldEnd })
	pushScore, scoreEndpoint = true, score.URL
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "octo/repo")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req")
	return p, func() (string, bool) {
		h, _ := got.Load().(string)
		return h, pushed.Load()
	}
}

// countingSigner swaps newScoreSignerFn for one that counts how often the
// signer is built and returns the given stub.
func countingSigner(t *testing.T, s scoreSigner) *atomic.Int32 {
	t.Helper()
	var built atomic.Int32
	old := newScoreSignerFn
	newScoreSignerFn = func(providerPkg.Provider) scoreSigner {
		built.Add(1)
		return s
	}
	t.Cleanup(func() { newScoreSignerFn = old })
	return &built
}

// TestMaybePushScore_SelfHostedEndpointNeverSigns locks the I1 ruling:
// signing is limited to the hosted endpoint. A push to a self-hosted score
// service without PLUMBER_SCORE_SIGN never builds the signer (no id-token
// mint, no TUF fetch, no Rekor entry), sends no bundle header and prints no
// warning; the push itself goes out as before.
func TestMaybePushScore_SelfHostedEndpointNeverSigns(t *testing.T) {
	p, header := signedPushHarness(t)
	built := countingSigner(t, stubSigner{bundle: []byte(`{"verificationMaterial":{}}`)})
	t.Setenv(scoreSignEnv, "")

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	stderr := captureStderr(t, func() { maybePushScore(p, conf, []byte(`{}`), "main") })

	h, pushed := header()
	if !pushed {
		t.Fatal("the push must still go out")
	}
	if n := built.Load(); n != 0 {
		t.Fatalf("signer built %d times for a self-hosted endpoint, want 0", n)
	}
	if h != "" {
		t.Fatalf("bundle header = %q, want none", h)
	}
	if strings.Contains(stderr, "not signed") || strings.Contains(stderr, "⚠️") {
		t.Fatalf("skipping the signer must be silent, got %q", stderr)
	}
}

// TestMaybePushScore_SelfHostedOptInSigns: PLUMBER_SCORE_SIGN=true (any
// case) names a self-hosted service that verifies the bundle, so the push is
// signed and carries the header.
func TestMaybePushScore_SelfHostedOptInSigns(t *testing.T) {
	p, header := signedPushHarness(t)
	built := countingSigner(t, stubSigner{bundle: []byte(`{"verificationMaterial":{}}`)})
	t.Setenv(scoreSignEnv, "TRUE")

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	_ = captureStderr(t, func() { maybePushScore(p, conf, []byte(`{}`), "main") })

	h, pushed := header()
	if !pushed || built.Load() != 1 || h == "" {
		t.Fatalf("pushed=%v built=%d header=%q, want a signed push", pushed, built.Load(), h)
	}
}

// TestScoreSigningWanted covers the gate itself: the hosted endpoint always
// signs, a self-hosted one only on an explicit "true".
func TestScoreSigningWanted(t *testing.T) {
	cases := []struct {
		endpoint, env string
		want          bool
	}{
		{configuration.DefaultScoreEndpoint, "", true},
		{configuration.DefaultScoreEndpoint, "false", true},
		{"https://score.example.internal", "", false},
		{"https://score.example.internal", "false", false},
		{"https://score.example.internal", "1", false},
		{"https://score.example.internal", "true", true},
		{"https://score.example.internal", " True ", true},
	}
	for _, tc := range cases {
		t.Setenv(scoreSignEnv, tc.env)
		if got := scoreSigningWanted(tc.endpoint); got != tc.want {
			t.Errorf("scoreSigningWanted(%q) with %s=%q = %v, want %v", tc.endpoint, scoreSignEnv, tc.env, got, tc.want)
		}
	}
}

// TestSignScorePayload_HostedEndpointSigns: on the hosted endpoint the signer
// is built and its bundle returned without any opt-in.
func TestSignScorePayload_HostedEndpointSigns(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}
	t.Setenv(scoreSignEnv, "")
	bundle := []byte(`{"verificationMaterial":{}}`)
	built := countingSigner(t, stubSigner{bundle: bundle})
	if got := signScorePayload(p, configuration.DefaultScoreEndpoint, []byte(`{}`)); !bytes.Equal(got, bundle) || built.Load() != 1 {
		t.Fatalf("bundle=%q built=%d, want the stub bundle from one signer", got, built.Load())
	}
}

// TestMaybePushScore_OversizeBundleDroppedWithWarning: a bundle whose base64
// form exceeds 64 KiB is not sent (proxies reject such headers); the push
// still goes out and one warning says why.
func TestMaybePushScore_OversizeBundleDroppedWithWarning(t *testing.T) {
	p, header := signedPushHarness(t)
	t.Setenv(scoreSignEnv, "true")
	withScoreSigner(t, stubSigner{bundle: bytes.Repeat([]byte("a"), 70<<10)})

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	stderr := captureStderr(t, func() { maybePushScore(p, conf, []byte(`{}`), "main") })

	h, pushed := header()
	if !pushed || h != "" {
		t.Fatalf("pushed=%v header length=%d, want a push without the header", pushed, len(h))
	}
	if !strings.Contains(stderr, "bundle too large") || !strings.Contains(stderr, "pushed without it") {
		t.Fatalf("expected the too-large warning, got %q", stderr)
	}
}

// blockingSigner ignores its context and blocks until release is closed,
// the worst case for an inner leg (a Sigstore call that does not honor the
// context).
type blockingSigner struct{ release chan struct{} }

func (s blockingSigner) Sign(context.Context, []byte) ([]byte, error) {
	<-s.release
	return []byte(`{"late":true}`), nil
}

// ctxSigner blocks until its context is done, then returns its error.
type ctxSigner struct{}

func (ctxSigner) Sign(ctx context.Context, _ []byte) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestSignScorePayload_TimeoutIsAnOverallCap: scoreSignTimeout caps signing as
// a whole, so the caller returns at the deadline on the warning path whatever
// the signer does, with a signer that honors the context and one that does
// not.
func TestSignScorePayload_TimeoutIsAnOverallCap(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}
	old := scoreSignTimeout
	scoreSignTimeout = 50 * time.Millisecond
	t.Cleanup(func() { scoreSignTimeout = old })
	t.Setenv(scoreSignEnv, "true")

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	for name, s := range map[string]scoreSigner{
		"honors the context":  ctxSigner{},
		"ignores the context": blockingSigner{release: release},
	} {
		t.Run(name, func(t *testing.T) {
			withScoreSigner(t, s)
			start := time.Now()
			var got []byte
			stderr := captureStderr(t, func() { got = signScorePayload(p, "https://score.example.internal", []byte(`{}`)) })
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("signScorePayload returned after %s, want about %s", elapsed, scoreSignTimeout)
			}
			if got != nil {
				t.Fatalf("bundle = %q, want nil after the deadline", got)
			}
			if !strings.Contains(stderr, "not signed") {
				t.Fatalf("expected the not-signed warning, got %q", stderr)
			}
		})
	}
}
