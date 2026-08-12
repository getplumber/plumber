package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	providerPkg "github.com/getplumber/plumber/provider"
)

// scorePushHTTPTimeout bounds the OIDC token fetch and the push POST.
// Publishing a badge must never hang a pipeline.
const scorePushHTTPTimeout = 15 * time.Second

// gitlabScoreTokenEnv is the env var the GitLab CI component's `id_tokens:`
// block writes the score-service OIDC id-token to; the CLI reads it on the
// GitLab path. (GitHub Actions exposes a request URL instead, so the CLI
// mints the token itself there.)
const gitlabScoreTokenEnv = "PLUMBER_ANALYZE_SCORE_TOKEN"

// gitlabPlatformTokenEnv is the env var the GitLab CI component's `id_tokens:`
// block writes the PLATFORM OIDC id-token to. It is separate from the score
// token because the audience must equal the destination, and the two
// destinations differ.
const gitlabPlatformTokenEnv = "PLUMBER_ANALYZE_PLATFORM_TOKEN"

// effectiveScorePush resolves whether to publish and the score service
// endpoint. Publishing has a single opt-in: the `--score-push` flag /
// PLUMBER_ANALYZE_SCORE_PUSH env, which the CI integration input (the
// action/component `score-push`) sets. The endpoint comes from the
// `--score-endpoint` flag / PLUMBER_ANALYZE_SCORE_ENDPOINT env, else the
// built-in default. It is resolved only from these operator-controlled
// sources, never from the analyzed repository's config file.
func effectiveScorePush() (push bool, endpoint string) {
	push = pushScore
	// A run publishes to one destination. The platform supersedes the public
	// badge when both are configured; maybePushScore prints the note so the
	// skip is never silent.
	if platformPush, _ := effectivePlatformPush(); platformPush {
		push = false
	}
	endpoint = strings.TrimRight(strings.TrimSpace(scoreEndpoint), "/")
	if endpoint == "" {
		endpoint = configuration.DefaultScoreEndpoint
	}
	return push, endpoint
}

// maybePushScore publishes the analysis report to the hosted score service
// when push is enabled AND a CI-native OIDC id-token is available. It NEVER
// fails the run: any problem is a warning. Outside a token-granting CI it can't
// publish; an explicit --score-push then prints a one-line note instead of
// skipping silently, so the requested push is never a mystery.
func maybePushScore(p providerPkg.Provider, conf *configuration.Configuration, payload []byte, defaultBranch string) {
	// The --platform-preempts-badge skip note lives in handleScorePublishingOnce
	// (printScorePushSkippedForPlatform), the only production caller: it decides
	// push/no-push BEFORE building the payload, so by the time maybePushScore
	// runs, push is already true. Do not duplicate that note here — a prior
	// version did, and it went uncovered by any production call path because
	// this function is only ever invoked after the caller already confirmed
	// push == true.
	push, endpoint := effectiveScorePush()
	if !push || len(payload) == 0 {
		return
	}

	// A CI run's OIDC identity — and thus the only badge it may write — is the
	// pipeline's own repo. If --project / the `project` input pointed the scan at
	// a DIFFERENT repository, the badge would be keyed to the CI repo but carry
	// the foreign project's score. Skip rather than mis-key it.
	if ciRepo, scanned, mismatch := ciScoreTargetMismatch(p, conf); mismatch {
		scoreWarn(fmt.Sprintf("score push skipped: analyzing %q but this pipeline's identity is %q; a badge can only be published for the pipeline's own repository", scanned, ciRepo))
		return
	}

	forgeHost, projectPath, ok := resolveScoreTarget(p, conf)
	if !ok {
		scoreWarn("could not resolve the project path for the score push; skipped")
		return
	}

	token, err := scoreOIDCToken(p, endpoint)
	if err != nil {
		scoreWarn(fmt.Sprintf("could not mint the CI OIDC id-token for the score push (%v); skipped", err))
		return
	}
	if token == "" {
		// No id-token: a CI run that has not granted it (point the user at the
		// fix) or a run outside a token-granting CI (an explicit --score-push
		// gets a note so it is not silently ignored). Never fail.
		switch {
		case p.Name() == "github" && strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true"):
			scoreWarn("score push needs `permissions: id-token: write` in the workflow; skipped")
		case p.Name() != "github" && strings.EqualFold(os.Getenv("GITLAB_CI"), "true"):
			scoreWarn("score push needs the component's `id_tokens:` block (" + gitlabScoreTokenEnv + "); skipped")
		case pushScore:
			fmt.Fprintln(os.Stderr, "ℹ️  --score-push skipped: a live badge is published only from CI (it needs a CI-issued OIDC id-token, e.g. GitHub Actions or GitLab CI).")
		}
		return
	}

	target := fmt.Sprintf("%s/%s/%s", endpoint, forgeHost, projectPath)
	if err := postScoreReport(target, token, payload); err != nil {
		scoreWarn(fmt.Sprintf("score push failed: %v", err))
		return
	}
	note := ""
	// The score service keeps only default-branch pushes for the public badge
	// (per-branch records stay reachable via ?branch=). When this run's branch
	// is knowably not the default, say so instead of implying the badge changed.
	if branch := ciRunBranch(p); branch != "" && defaultBranch != "" && branch != defaultBranch {
		note = fmt.Sprintf(" (but not displayed on the public badge: %q is not the default branch)", branch)
	}
	fmt.Fprintf(os.Stderr, "✓ Plumber Score published: %s/%s/%s%s\n", endpoint, forgeHost, projectPath, note)
}

// ciRunBranch returns the branch this CI run executes on, or "" when unknown
// (local run, tag pipeline, GitLab MR pipeline). GitHub: GITHUB_REF_NAME when
// GITHUB_REF_TYPE is "branch" — a PR run reports its merge ref ("N/merge"),
// which correctly reads as not-the-default-branch. GitLab: CI_COMMIT_BRANCH,
// set only on branch pipelines. Comparison against the default branch is
// case-sensitive downstream, matching git ref semantics and the score service.
func ciRunBranch(p providerPkg.Provider) string {
	if p.Name() == "github" {
		if os.Getenv("GITHUB_REF_TYPE") != "branch" {
			return ""
		}
		return strings.TrimSpace(os.Getenv("GITHUB_REF_NAME"))
	}
	return strings.TrimSpace(os.Getenv("CI_COMMIT_BRANCH"))
}

// ciScoreTargetMismatch reports whether the scan analyzed a different project
// than the one this CI pipeline can publish for. Inside a pipeline the badge is
// gated by the OIDC identity (the CI repo); a scan retargeted with --project /
// the `project` input therefore cannot be published here. mismatch is false
// when either side is unknown (e.g. a local run, where env.RepoPath is empty)
// so the existing local-run handling still applies.
func ciScoreTargetMismatch(p providerPkg.Provider, conf *configuration.Configuration) (ciRepo, scanned string, mismatch bool) {
	env := p.CIEnvVars()
	ciRepo = strings.Trim(strings.TrimSpace(os.Getenv(env.RepoPath)), "/")
	if conf != nil {
		scanned = strings.Trim(strings.TrimSpace(conf.ProjectPath), "/")
	}
	if ciRepo == "" || scanned == "" {
		return ciRepo, scanned, false
	}
	return ciRepo, scanned, !strings.EqualFold(ciRepo, scanned)
}

// resolveScoreTarget returns the {forge host} and {namespace/repo} project
// path the badge is keyed by. The CI env (authoritative inside a pipeline)
// wins over config. ok is false when no project path can be determined.
func resolveScoreTarget(p providerPkg.Provider, conf *configuration.Configuration) (forgeHost, projectPath string, ok bool) {
	env := p.CIEnvVars()

	projectPath = strings.Trim(strings.TrimSpace(os.Getenv(env.RepoPath)), "/")
	if projectPath == "" && conf != nil {
		projectPath = strings.Trim(strings.TrimSpace(conf.ProjectPath), "/")
	}

	serverURL := strings.TrimSpace(os.Getenv(env.ServerURL))
	if serverURL == "" && conf != nil {
		if p.Name() == "github" {
			serverURL = githubWebURL(conf.GithubAPIHost)
		} else {
			serverURL = conf.GitlabURL
		}
	}
	forgeHost = hostOf(serverURL)
	if forgeHost == "" {
		if p.Name() == "github" {
			forgeHost = "github.com"
		} else {
			forgeHost = "gitlab.com"
		}
	}

	return forgeHost, projectPath, projectPath != ""
}

// scoreOIDCToken returns the CI-native OIDC id-token minted for the score
// service's audience (= endpoint), or "" when none is available (a local run
// or a CI run without the token grant). A non-nil error means the token
// request itself failed.
func scoreOIDCToken(p providerPkg.Provider, endpoint string) (string, error) {
	if p.Name() == "github" {
		reqURL := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
		reqTok := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
		if reqURL == "" || reqTok == "" {
			return "", nil // not a token-granting GitHub Actions context
		}
		return fetchGitHubActionsIDToken(reqURL, reqTok, endpoint)
	}
	// GitLab (and others): the pipeline's id_tokens: block writes the token to
	// the env; the CLI just reads it. Audience is pinned in the template, so
	// the destination decides which of the two tokens to read.
	if platformPush, platformEndpoint := effectivePlatformPush(); platformPush && endpoint == platformEndpoint {
		return strings.TrimSpace(os.Getenv(gitlabPlatformTokenEnv)), nil
	}
	return strings.TrimSpace(os.Getenv(gitlabScoreTokenEnv)), nil
}

// fetchGitHubActionsIDToken exchanges the runtime request URL + token for an
// id-token minted for the given audience (the score endpoint).
func fetchGitHubActionsIDToken(reqURL, reqToken, audience string) (string, error) {
	u := reqURL
	if audience != "" {
		sep := "?"
		if strings.Contains(reqURL, "?") {
			sep = "&"
		}
		u = reqURL + sep + "audience=" + url.QueryEscape(audience)
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: scorePushHTTPTimeout}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("id-token request returned %s", resp.Status)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Value == "" {
		return "", fmt.Errorf("empty id-token in response")
	}
	return out.Value, nil
}

// postScoreReport POSTs the report JSON to the score service. Any non-2xx is
// an error (the caller turns it into a warning, never a failure).
func postScoreReport(target, token string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: scorePushHTTPTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			return fmt.Errorf("%s", resp.Status)
		}
		return fmt.Errorf("%s: %s", resp.Status, msg)
	}
	return nil
}

// hostOf extracts the host from a (possibly scheme-less) URL.
func hostOf(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// scoreWarn prints a non-fatal score-push warning to stderr.
func scoreWarn(msg string) {
	fmt.Fprintf(os.Stderr, "⚠️  %s (the run is not failed)\n", msg)
}

// printScorePushSkippedForPlatform tells the operator that their explicit
// --score-push was preempted by --platform, so an explicitly requested badge
// push is never dropped without a trace. Unlike maybeScoreNudge, this is NOT
// gated by --print/--silent: the global "the skip is never silent" rule for
// --platform vs --score-push is a hard requirement, not a cosmetic one.
func printScorePushSkippedForPlatform(target string) {
	fmt.Fprintf(os.Stderr, "ℹ️  --score-push skipped: results are being pushed to the platform at %s instead.\n", target)
}

// scorePublishOnce guards handleScorePublishing so a run publishes at most
// once. The two entry points — runWithProvider (GitLab) and
// presentResultWithProvider (GitHub) — are mutually exclusive today, but a
// future refactor that routes a provider through both must not POST the badge
// (or print the nudge) twice. Reset in tests via scorePublishOnce = sync.Once{}.
var scorePublishOnce sync.Once

// handleScorePublishing publishes the score when push is enabled, otherwise
// nudges the user (interactive local runs only) to wire it into CI. payload is
// the same analysis JSON bytes buildAnalysisJSONReport produced for --output,
// built once by the caller and shared with the platform push, so the badge
// record and the file on disk never diverge. Never fails the run, and runs at
// most once per process (scorePublishOnce).
func handleScorePublishing(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult, summary complianceSummary, payload []byte) {
	scorePublishOnce.Do(func() { handleScorePublishingOnce(p, conf, result, summary, payload) })
}

func handleScorePublishingOnce(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult, summary complianceSummary, payload []byte) {
	if push, _ := effectiveScorePush(); !push {
		// A push was explicitly requested (--score-push) but --platform preempted
		// it: say so instead of falling through to the "you should turn on
		// score-push" nudge, which would be both wrong (it's already on) and,
		// under --silent, would print nothing at all — silently dropping an
		// explicit request.
		if pushScore {
			if platformPush, target := effectivePlatformPush(); platformPush {
				printScorePushSkippedForPlatform(target)
				return
			}
		}
		maybeScoreNudge()
		return
	}
	// Skip a degraded run: an incomplete or rate-limited collection must not
	// overwrite the last good score with a misleading one (the same guard the
	// letter-score badge uses, #220). Branch is NOT filtered here: the CLI
	// publishes on every run, and the score service keeps only the default
	// branch for the public badge by reading the verified branch from the OIDC
	// token (which the CLI cannot forge).
	if result.DataCollectionDegraded {
		scoreWarn("data collection was incomplete; score not published (avoids overwriting the last good badge)")
		return
	}
	if len(payload) == 0 {
		scoreWarn("could not build the score report payload; skipped")
		return
	}
	maybePushScore(p, conf, payload, result.DefaultBranch)
}

// maybeScoreNudge prints an invitation to publish a live badge whenever text
// output is on — including in CI — so a run that isn't already publishing a
// score still points the user at how to turn it on. Suppressed only when
// terminal output is off (e.g. --silent / JSON-only) so it never spams
// machine-readable output.
func maybeScoreNudge() {
	if !printOutput {
		return
	}
	fmt.Fprintln(os.Stderr, "💡 Display a live Plumber Score badge for this repo: turn on score-push in your CI pipeline. Learn more: https://getplumber.io/docs/plumber-score")
}
