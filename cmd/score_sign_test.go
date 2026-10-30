package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	providerPkg "github.com/getplumber/plumber/provider"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// A TUF mirror that accepts the connection and never answers must not hold
// the score push: the trusted-root fetch is bounded by the fetcher's HTTP
// client timeout and fails fast, so the caller warns and pushes unsigned.
func TestSigstoreTUFOptions_StallingMirrorTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	opts := sigstoreTUFOptions(200 * time.Millisecond)
	opts.RepositoryBaseURL = srv.URL
	opts.CachePath = t.TempDir()

	done := make(chan error, 1)
	go func() {
		_, err := root.FetchTrustedRootWithOptions(opts)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from a stalling TUF mirror")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the trusted-root fetch did not time out against a stalling TUF mirror")
	}
}

// fakeGitHubProvider returns the registered GitHub provider, used here as a
// stand-in identity for provider-dependent signer selection.
func fakeGitHubProvider() providerPkg.Provider {
	p, ok := providerPkg.Get("github")
	if !ok {
		panic("github provider not registered")
	}
	return p
}

// fakeGitLabProvider returns the registered GitLab provider, used here as a
// stand-in identity for provider-dependent signer selection.
func fakeGitLabProvider() providerPkg.Provider {
	p, ok := providerPkg.Get("gitlab")
	if !ok {
		panic("gitlab provider not registered")
	}
	return p
}

func TestNewScoreSigner_NoSignerOutsideActions(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	if _, ok := newScoreSigner(fakeGitHubProvider()).(noSigner); !ok {
		t.Fatal("expected noSigner outside GitHub Actions")
	}
	if _, ok := newScoreSigner(fakeGitLabProvider()).(noSigner); !ok {
		t.Fatal("expected noSigner on GitLab")
	}
}

func TestNewScoreSigner_KeylessOnActions(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.invalid/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x")
	if _, ok := newScoreSigner(fakeGitHubProvider()).(*keylessSigner); !ok {
		t.Fatal("expected keylessSigner on GitHub Actions")
	}
}

// TestScoreBundleHeader_Name locks the exact header name Task 3 posts the
// bundle under; it also keeps the constant referenced until Task 3 wires it
// into the request.
func TestScoreBundleHeader_Name(t *testing.T) {
	if scoreBundleHeader != "Plumber-Sigstore-Bundle" {
		t.Fatalf("scoreBundleHeader = %q", scoreBundleHeader)
	}
}

func TestKeylessSigner_TokenFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("audience") != "sigstore" {
			t.Errorf("audience = %q", r.URL.Query().Get("audience"))
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := &keylessSigner{tokenURL: srv.URL, tokenReq: "x"}
	if _, err := s.Sign(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected an error when the id-token cannot be minted")
	}
}
