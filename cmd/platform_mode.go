package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/cidigest"
	"github.com/getplumber/plumber/internal/platform"
	providerPkg "github.com/getplumber/plumber/provider"
)

// setupPlatformMode resolves everything platform mode needs BEFORE
// collection begins, and returns the run context to hang on conf. It
// returns nil when --platform is not set, which is the CLI's default and
// leaves every downstream path exactly as it is in standalone mode.
//
// Nothing here can fail a run. A platform that is unreachable, forbidden or
// out of date degrades to a stated warning and a standalone collection: the
// pipeline is never coupled to a third party's availability. The one
// exception is the token, which is minted against the CI provider's OWN
// infrastructure and is handled by the push path exactly as before.
func setupPlatformMode(p providerPkg.Provider, conf *configuration.Configuration) *platform.RunContext {
	push, endpoint := effectivePlatformPush()
	if !push {
		return nil
	}

	rc := &platform.RunContext{Endpoint: endpoint}

	token, err := scoreOIDCToken(p, endpoint)
	if err != nil || strings.TrimSpace(token) == "" {
		// The push path reports and classifies a token failure - it is the
		// one condition that fails a run - so this only records why the
		// context could not be fetched and lets the run proceed. Reporting
		// it twice would double up on the same diagnosis.
		rc.ContextErr = fmt.Errorf("no CI OIDC id-token available")
		return rc
	}

	_, projectPath, ok := resolveScoreTarget(p, conf)
	if !ok {
		rc.ContextErr = fmt.Errorf("could not resolve the project path")
		return rc
	}
	rc.ProjectPath = projectPath

	client := platform.NewClient(endpoint, token)
	rc.SetClient(client)

	ctx, err := client.FetchContext(projectPath)
	if err != nil {
		rc.ContextErr = err
		return rc
	}
	rc.Context = ctx

	// The snapshot's ci_config_path is what the platform anchored its own
	// digest against, so digesting over anything else can never cache-hit on
	// a project with a custom path.
	localDigest, abortReason := computeLocalCIDigest(conf, rc.SnapshotCIConfigPath())
	sha, shaFromAnchor := platformAnalyzedSha(p, conf, ctx.Snapshot.Anchor())
	// Started, not awaited: on a divergent digest the resolve request is in
	// flight when setup returns, and the first consumer that needs the
	// merged config joins on it (RunContext.MergedYAML). The local work in
	// between runs concurrently with the platform's resolution, and a hung
	// endpoint costs its timeout in parallel rather than before any of it.
	rc.Config = platform.StartRunConfigResolution(client, ctx.Snapshot, projectPath, sha, localDigest, abortReason)
	rc.Config.ShaFromAnchor = shaFromAnchor
	return rc
}

// computeLocalCIDigest computes this checkout's CI config digest, the key
// that decides whether the platform's already-resolved config describes
// this branch.
//
// It returns ("", reason) for every state where no digest may be claimed,
// and the caller treats a missing digest as ALWAYS DIVERGENT - the safe
// direction, since the alternative is evaluating a branch against a
// configuration that is not its own.
//
// The digest is only computed when the checkout on disk IS the analyzed
// project. Analyzing a remote project from an unrelated working directory
// (plumber analyze --project other/repo) would otherwise digest whatever
// CI config happens to be in the current directory, and a coincidental
// match would silently evaluate one project against another's config.
//
// That question is CheckoutIsAnalyzedProject, not IsLocalProject. The
// latter additionally requires that the operator did not name the project,
// which is the right rule for reading the CI file off disk and the wrong
// one here: the GitLab CI component passes the project path as an env var,
// so gating on it meant the digest was never computed in a CI job - the one
// place it exists for. See the field's own documentation.
func computeLocalCIDigest(conf *configuration.Configuration, snapshotPath string) (digest, abortReason string) {
	if conf == nil || !conf.CheckoutIsAnalyzedProject || strings.TrimSpace(conf.GitRepoRoot) == "" {
		return "", "no checkout of the analyzed project"
	}
	digest, err := cidigest.ComputeForCheckout(conf.GitRepoRoot, ciConfigPathForDigest(conf, snapshotPath))
	if err != nil {
		return "", cidigest.AbortReason(err)
	}
	return digest, ""
}

// ciConfigPathForDigest picks which CI config path this run's digest is
// computed over. It has to agree with the path the PLATFORM anchored its own
// digest against, or the two can never match and a custom-path project
// re-resolves on every single run instead of ever hitting the cache.
//
// Precedence, strongest evidence first:
//
//  1. An explicit --ci-config-path from the operator. They are overriding on
//     purpose, and a snapshot value must not silently win over that.
//  2. The path the platform reports for the project, which is the one its
//     anchor digest was computed against - the whole reason the field exists.
//  3. Empty, leaving cidigest on its own ".gitlab-ci.yml" default.
func ciConfigPathForDigest(conf *configuration.Configuration, snapshotPath string) string {
	if conf != nil && strings.TrimSpace(conf.CIConfigPathOverride) != "" {
		return conf.CIConfigPathOverride
	}
	return strings.TrimSpace(snapshotPath)
}

// platformAnalyzedSha is the commit the resolve request asks about.
//
// In CI the environment knows it, and that is the authoritative answer: it
// is the exact commit the job checked out.
//
// Outside CI - analyzing a remote project with --project - there is no such
// variable, and the resolve endpoint rejects an empty sha outright. The
// snapshot's anchor carries a usable one, but only for the ref it was
// resolved at (the default branch at collection time), so it is used ONLY
// when that is the ref being analyzed. Handing back the default branch's
// configuration for a run that asked for another branch would be the exact
// wrong-config verdict the whole digest mechanism exists to prevent.
//
// An empty return means "no sha to resolve at", and the caller degrades
// rather than sending a request the platform will refuse. fromAnchor
// reports that the sha is the ANCHOR's rather than the job's own: the run
// then evaluates the project's remote state at that commit, which the
// describe output states so a local-uncommitted-edits divergence is not
// read as a contradiction (see ConfigResolution.ShaFromAnchor).
func platformAnalyzedSha(p providerPkg.Provider, conf *configuration.Configuration, anchor *platform.ResolutionAnchor) (sha string, fromAnchor bool) {
	if sha := strings.TrimSpace(os.Getenv(p.CIEnvVars().CommitSHA)); sha != "" {
		return sha, false
	}
	if anchor == nil || strings.TrimSpace(anchor.Sha) == "" {
		return "", false
	}
	// conf.Branch empty means the run analyzes the project's default
	// branch, which is what the anchor's ref is.
	branch := ""
	if conf != nil {
		branch = strings.TrimSpace(conf.Branch)
	}
	if branch == "" || branch == anchor.Ref {
		return anchor.Sha, true
	}
	return "", false
}

// reportPlatformMode prints what platform mode resolved. It runs before the
// analysis output so an operator reads which policy set and which CI
// configuration produced the verdict they are about to see, rather than
// having to infer it.
//
// The lines go to stderr, next to the other run diagnostics, so a
// --print=false run piping JSON on stdout is unaffected.
func reportPlatformMode(rc *platform.RunContext) {
	if !rc.Active() {
		return
	}
	lines := rc.Describe()
	if len(lines) == 0 {
		return
	}
	if rc.Context == nil {
		// A context that could not be fetched is a degradation the operator
		// must see even without --verbose: their policies were not applied.
		for _, line := range lines {
			fmt.Fprintf(os.Stderr, "⚠️  %s\n", line)
		}
		return
	}
	// Printed on every platform-mode run, not just under --verbose. These
	// eight or so lines are the provenance of the verdict that follows:
	// which policies applied, how old the snapshot was, and which CI
	// configuration was evaluated. A reader who cannot see that cannot tell
	// a clean report from one produced against a stale or absent config,
	// and reaching for --verbose to find out floods the terminal with
	// debug logging for every job and every API call.
	for _, line := range lines {
		fmt.Fprintf(os.Stderr, "  %s\n", line)
	}
}

// reportPlatformOutcome prints one line at the END of a run in which
// --platform was asked for but platform mode never engaged.
//
// The same fact is already reported before collection starts, but a full
// report is over a hundred lines of controls, findings and a score banner,
// and on a normal terminal that scrolls the warning away entirely. What is
// left on screen is an ordinary-looking verdict produced WITHOUT the
// project's policies — the one outcome someone must not walk away with by
// accident. Repeating it last costs a line and removes that failure mode.
func reportPlatformOutcome(rc *platform.RunContext) {
	if !rc.Active() || rc.Engaged() {
		return
	}
	reason := "unknown error"
	if rc.ContextErr != nil {
		reason = rc.ContextErr.Error()
	}
	fmt.Fprintf(os.Stderr,
		"⚠️  platform mode did NOT engage (%s).\n"+
			"    This run used local collection and the local config only: none of the project's platform policies were applied.\n",
		reason)
}
