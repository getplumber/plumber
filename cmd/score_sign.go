package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	providerPkg "github.com/getplumber/plumber/provider"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"google.golang.org/protobuf/encoding/protojson"
)

// scoreBundleHeader is the request header that carries the Sigstore bundle
// (protojson, base64) alongside the score push.
const scoreBundleHeader = "Plumber-Sigstore-Bundle"

// sigstoreAudience is the audience Fulcio expects on a GitHub Actions
// id-token.
const sigstoreAudience = "sigstore"

// scoreSigner signs the exact bytes the score push posts and returns the
// Sigstore bundle as protojson, or ("", nil) when signing is not available in
// this environment (no Actions id-token). An error is a warning for the
// caller.
type scoreSigner interface {
	Sign(ctx context.Context, payload []byte) (bundleJSON []byte, err error)
}

// noSigner is the signer used wherever keyless signing is not available
// (outside GitHub Actions, or on GitHub Actions without the id-token grant).
// It never errors: the caller pushes the score unsigned.
type noSigner struct{}

func (noSigner) Sign(context.Context, []byte) ([]byte, error) { return nil, nil }

// keylessSigner signs with an ephemeral key certified by Fulcio for the
// job's OIDC identity and logs the signature in Rekor (the public
// instances).
type keylessSigner struct {
	tokenURL, tokenReq string
}

// newScoreSigner picks the implementation: sigstore keyless on GitHub
// Actions, noSigner elsewhere.
func newScoreSigner(p providerPkg.Provider) scoreSigner {
	if p.Name() != "github" {
		return noSigner{}
	}
	u := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	tok := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	if u == "" || tok == "" {
		return noSigner{}
	}
	return &keylessSigner{tokenURL: u, tokenReq: tok}
}

func (s *keylessSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	idToken, err := fetchGitHubActionsIDToken(s.tokenURL, s.tokenReq, sigstoreAudience)
	if err != nil {
		return nil, fmt.Errorf("mint the sigstore id-token: %w", err)
	}
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, err
	}
	// The public Sigstore TUF root, cached by sigstore-go, each fetch bounded.
	trusted, err := root.FetchTrustedRootWithOptions(sigstoreTUFOptions(scorePushHTTPTimeout))
	if err != nil {
		return nil, fmt.Errorf("fetch the sigstore trusted root: %w", err)
	}
	opts := sign.BundleOptions{
		CertificateProvider:        sign.NewFulcio(&sign.FulcioOptions{BaseURL: "https://fulcio.sigstore.dev", Timeout: scorePushHTTPTimeout, Retries: 1}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: idToken},
		TransparencyLogs:           []sign.Transparency{sign.NewRekor(&sign.RekorOptions{BaseURL: "https://rekor.sigstore.dev", Timeout: scorePushHTTPTimeout, Retries: 1})},
		TrustedRoot:                trusted,
		Context:                    ctx,
	}
	b, err := sign.Bundle(&sign.PlainData{Data: payload}, keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("sign the report: %w", err)
	}
	return protojson.Marshal(b)
}

// sigstoreTUFOptions returns the public-good TUF options with a fetcher whose
// HTTP client carries a timeout. The go-tuf default fetcher uses
// http.DefaultClient, which has none: a mirror that accepts the connection
// and never answers would hold the score push indefinitely, while signing
// must only ever cost a warning.
func sigstoreTUFOptions(timeout time.Duration) *tuf.Options {
	opts := tuf.DefaultOptions()
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPUserAgent("plumber/" + Version)
	f.SetHTTPClient(&http.Client{Timeout: timeout})
	opts.Fetcher = f
	return opts
}
