package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/getplumber/plumber/configuration"
	providerPkg "github.com/getplumber/plumber/provider"
)

// platformContextPolicy is one entry of the platform's /context resolved
// policy set. Only id and name are consulted here (the exact-name match that
// stamps policy_id); enforcement and every other field the platform may add
// are left undecoded on purpose - /context is forward tolerant, and the CLI
// has no use for the rest of the shape yet.
type platformContextPolicy struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// platformContext is the platform's GET .../context response. snapshot
// (data-collection info for control evaluation) is deliberately not decoded
// here - this call site only needs the resolved policy set - so an unknown
// or newer snapshot shape never breaks parsing.
type platformContext struct {
	Policies []platformContextPolicy `json:"policies"`
}

// fetchPlatformContext calls the platform's self-only /context endpoint for
// this project (Bearer = the same OIDC token the push itself uses) and
// returns its resolved policy set. Any non-2xx status or a body that does
// not parse as JSON is returned as an error. Every caller treats every error
// identically: no policy_id is stamped, one warning line is printed, and the
// push proceeds name-only - /context is best-effort keying, never a
// condition the run can fail on.
//
// projectPath is percent-escaped as a single path segment (url.PathEscape)
// because it contains "/" (e.g. "org/repo") and the platform's route is
// /projects/:project_path/context: an unescaped path would be split across
// route segments by the platform's router instead of reaching the
// project_path param whole.
func fetchPlatformContext(endpoint, token, projectPath string) (*platformContext, error) {
	target := endpoint + "/api/v1/projects/" + url.PathEscape(projectPath) + "/context"
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: scorePushHTTPTimeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	var ctx platformContext
	if err := json.NewDecoder(resp.Body).Decode(&ctx); err != nil {
		return nil, fmt.Errorf("decode /context response: %w", err)
	}
	return &ctx, nil
}

// matchPlatformContextPolicyID resolves the /context policy id for the
// locally-derived policy name (platformPolicyNameFor). Matching is EXACT
// name equality, case-sensitive: this mirrors the same key the platform's
// own one-version name tolerance resolves on server-side, moved client-side
// now that /context provides the authoritative list. Exactly one match is
// required to stamp an id - zero or multiple matches return ok=false, and
// the caller falls back to a name-only push (the platform's tolerance
// covers it); guessing at an ambiguous match would risk mis-keying the push
// to the wrong policy.
func matchPlatformContextPolicyID(name string, policies []platformContextPolicy) (id string, ok bool) {
	for _, p := range policies {
		if p.Name != name {
			continue
		}
		if ok {
			return "", false // a second match: ambiguous, no id
		}
		id, ok = p.ID, true
	}
	return id, ok
}

// resolvePlatformPolicyID makes the run's (at most one) /context call and
// returns the policy id to stamp, or "" when none was resolved. It never
// returns an error: every failure mode (no resolvable project path,
// transport error, non-2xx, unparseable body, no/ambiguous name match) is
// handled here with a single informative line on stderr, and the push
// always proceeds - /context is additive keying, not a gate.
func resolvePlatformPolicyID(p providerPkg.Provider, conf *configuration.Configuration, endpoint, token, configPath string) string {
	_, projectPath, ok := resolveScoreTarget(p, conf)
	if !ok {
		scoreWarn("could not resolve the project path for the platform /context lookup; pushing without a policy id")
		return ""
	}

	ctx, err := fetchPlatformContext(endpoint, token, projectPath)
	if err != nil {
		scoreWarn(fmt.Sprintf("could not fetch the platform's policy set (%v); pushing without a policy id", err))
		return ""
	}

	name := platformPolicyNameFor(configPath)
	id, matched := matchPlatformContextPolicyID(name, ctx.Policies)
	if !matched {
		fmt.Fprintf(os.Stderr, "ℹ️  platform push: no single /context policy named %q; pushing without a policy id\n", name)
		return ""
	}
	return id
}
