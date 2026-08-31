package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/cidigest"
	"github.com/getplumber/plumber/internal/platform"
)

// TestLocalDigestVersionMatchesCidigest pins the two halves of the pair
// together. The platform package states the version it sends on the wire
// without importing cidigest, so nothing but this test stops the two from
// drifting — and a mismatched pair silently compares digests across
// algorithm versions, which is exactly what the version exists to prevent.
func TestLocalDigestVersionMatchesCidigest(t *testing.T) {
	if platform.LocalDigestVersion != cidigest.Version {
		t.Fatalf("digest version drift: platform sends %q, cidigest computes %q",
			platform.LocalDigestVersion, cidigest.Version)
	}
}

func TestComputeLocalCIDigest(t *testing.T) {
	writeRepo := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte("stages:\n  - build\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return dir
	}

	// The digest of that fixture is a shared golden vector, so this also
	// proves the wiring feeds cidigest the checkout it claims to.
	const wantDigest = "b2dc627c8d9fdad3ffb53f2138197a9ca4600b91ac59c515fa2e8fbe0cbe7009"

	t.Run("computes over the checkout when it IS the analyzed project", func(t *testing.T) {
		dir := writeRepo(t)
		got, reason := computeLocalCIDigest(&configuration.Configuration{
			CheckoutIsAnalyzedProject: true, GitRepoRoot: dir,
		}, "")
		if reason != "" {
			t.Fatalf("unexpected abort reason %q", reason)
		}
		if got != wantDigest {
			t.Fatalf("digest:\n got  %s\n want %s", got, wantDigest)
		}
	})

	// Analyzing a REMOTE project from an unrelated working directory must
	// not digest whatever CI config happens to be in that directory. A
	// coincidental match would make the run evaluate one project against
	// another project's configuration.
	t.Run("refuses when the checkout is not the analyzed project", func(t *testing.T) {
		dir := writeRepo(t)
		got, reason := computeLocalCIDigest(&configuration.Configuration{
			CheckoutIsAnalyzedProject: false, GitRepoRoot: dir,
		}, "")
		if got != "" {
			t.Fatalf("want no digest, got %q", got)
		}
		if !strings.Contains(reason, "no checkout") {
			t.Fatalf("reason: %q", reason)
		}
	})

	t.Run("refuses with no repo root at all", func(t *testing.T) {
		got, reason := computeLocalCIDigest(&configuration.Configuration{CheckoutIsAnalyzedProject: true}, "")
		if got != "" || reason == "" {
			t.Fatalf("got (%q, %q)", got, reason)
		}
	})

	t.Run("nil conf is handled", func(t *testing.T) {
		if got, reason := computeLocalCIDigest(nil, ""); got != "" || reason == "" {
			t.Fatalf("got (%q, %q)", got, reason)
		}
	})

	t.Run("honours a ci_config_path override", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "ci"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ci", "main.yml"), []byte("stages:\n  - build\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, reason := computeLocalCIDigest(&configuration.Configuration{
			CheckoutIsAnalyzedProject: true, GitRepoRoot: dir, CIConfigPathOverride: "ci/main.yml",
		}, "")
		if reason != "" {
			t.Fatalf("unexpected reason %q", reason)
		}
		if got == wantDigest {
			t.Fatal("a different root path must digest differently: the path is part of the hashed stream")
		}
		if got == "" {
			t.Fatal("want a digest")
		}
	})

	// An over-cap traversal must report the abort reason rather than a
	// digest, so the resolve request omits the pair and the platform
	// resolves fresh.
	t.Run("a traversal past the file cap aborts with a reason", func(t *testing.T) {
		dir := t.TempDir()
		for i := 0; i <= cidigest.MaxFiles; i++ {
			name := filepath.Join(dir, "step"+strconv.Itoa(i)+".yml")
			body := "include:\n  - local: 'step" + strconv.Itoa(i+1) + ".yml'\n"
			if i == cidigest.MaxFiles {
				body = "job:\n  script: echo done\n"
			}
			if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		got, reason := computeLocalCIDigest(&configuration.Configuration{
			CheckoutIsAnalyzedProject: true, GitRepoRoot: dir, CIConfigPathOverride: "step0.yml",
		}, "")
		if got != "" {
			t.Fatalf("an aborted traversal must yield NO digest, got %q", got)
		}
		if reason != "overflow" {
			t.Fatalf("reason: got %q, want \"overflow\"", reason)
		}
	})
}

// TestSetupPlatformMode_NilWithoutTheFlag is the default-behaviour guard:
// with no --platform, platform mode is never entered and conf.PlatformRun
// stays nil, which every downstream path reads as standalone.
func TestSetupPlatformMode_NilWithoutTheFlag(t *testing.T) {
	restore := platformURL
	t.Cleanup(func() { platformURL = restore })

	for _, v := range []string{"", "   ", platformSentinelURL} {
		platformURL = v
		if got := setupPlatformMode(testProvider(t), &configuration.Configuration{}); got != nil {
			t.Fatalf("platformURL=%q must not enter platform mode, got %+v", v, got)
		}
	}
}

// TestReportPlatformMode_AlwaysReportsProvenance pins that the platform
// block prints on EVERY platform-mode run, not only under --verbose.
//
// These lines are the provenance of the verdict that follows: which policies
// applied, how old the snapshot was, which CI configuration was evaluated. A
// reader who cannot see them cannot tell a clean report from one produced
// against a stale or absent config — and reaching for --verbose to find out
// floods the terminal with debug logging for every job and every API call,
// which is how this was discovered.
func TestReportPlatformMode_AlwaysReportsProvenance(t *testing.T) {
	restoreVerbose := verbose
	t.Cleanup(func() { verbose = restoreVerbose })

	healthy := &platform.RunContext{
		Endpoint: "https://p.example.com",
		Context: &platform.ProjectContext{Policies: []platform.Policy{
			{ID: "1", Name: "P", Enforcement: platform.EnforcementReport},
		}},
		Config: &platform.ConfigResolution{Source: platform.SourceSnapshot, Digest: platform.DigestMatch, Valid: true},
	}

	for _, v := range []bool{false, true} {
		verbose = v
		out := captureStderr(t, func() { reportPlatformMode(healthy) })
		for _, want := range []string{"policies: 1 resolved", "platform snapshot"} {
			if !strings.Contains(out, want) {
				t.Fatalf("verbose=%v: output missing %q:\n%s", v, want, out)
			}
		}
	}

	// An unavailable configuration silently turns controls into
	// not_evaluable, so its reason is part of the same always-on block.
	verbose = false
	unavailable := &platform.RunContext{
		Endpoint: "https://p.example.com",
		Context:  healthy.Context,
		Config:   &platform.ConfigResolution{Source: platform.SourceUnavailable, Reason: platform.ReasonResolverBusy},
	}
	out := captureStderr(t, func() { reportPlatformMode(unavailable) })
	if !strings.Contains(out, "resolver_busy") || !strings.Contains(out, "not_evaluable") {
		t.Fatalf("an unavailable config must name its reason and consequence:\n%s", out)
	}
}

// TestReportPlatformMode_FailedContextIsAlwaysReported: a context that
// could not be fetched means the project's policies were not applied.
// Staying silent would let an operator believe they were.
func TestReportPlatformMode_FailedContextIsAlwaysReported(t *testing.T) {
	restoreVerbose := verbose
	t.Cleanup(func() { verbose = restoreVerbose })
	verbose = false

	rc := &platform.RunContext{Endpoint: "https://p.example.com", ContextErr: errTestContext{}}
	out := captureStderr(t, func() { reportPlatformMode(rc) })
	if !strings.Contains(out, "context: NOT fetched") {
		t.Fatalf("a failed context fetch must always be reported:\n%s", out)
	}
}

func TestReportPlatformMode_StandaloneIsSilent(t *testing.T) {
	if out := captureStderr(t, func() { reportPlatformMode(nil) }); strings.TrimSpace(out) != "" {
		t.Fatalf("standalone mode must print nothing:\n%s", out)
	}
}

type errTestContext struct{}

func (errTestContext) Error() string { return "403 Forbidden: not the attributed project" }

// TestPlatformAnalyzedSha covers where the resolve request's sha comes from.
//
// Outside CI there is no commit variable, and the resolve endpoint refuses an
// empty sha — so a remote scan used to degrade to not_evaluable for a reason
// that had nothing to do with the platform. The snapshot's anchor supplies one,
// but only for the ref it was resolved at.
func TestPlatformAnalyzedSha(t *testing.T) {
	p := testProvider(t)
	env := p.CIEnvVars().CommitSHA
	anchor := &platform.ResolutionAnchor{Ref: "main", Sha: "anchorsha"}

	t.Run("the CI environment wins when present", func(t *testing.T) {
		t.Setenv(env, "cisha")
		if got, fromAnchor := platformAnalyzedSha(p, &configuration.Configuration{}, anchor); got != "cisha" || fromAnchor {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("falls back to the anchor for the default branch", func(t *testing.T) {
		t.Setenv(env, "")
		if got, fromAnchor := platformAnalyzedSha(p, &configuration.Configuration{}, anchor); got != "anchorsha" || !fromAnchor {
			t.Fatalf("got %q, want the anchor's sha", got)
		}
	})

	t.Run("falls back when --branch names the anchor's own ref", func(t *testing.T) {
		t.Setenv(env, "")
		conf := &configuration.Configuration{Branch: "main"}
		if got, fromAnchor := platformAnalyzedSha(p, conf, anchor); got != "anchorsha" || !fromAnchor {
			t.Fatalf("got %q", got)
		}
	})

	// The important one: handing back the default branch's config for a run
	// that asked for another branch is the wrong-config verdict the digest
	// exists to prevent.
	t.Run("refuses to reuse the anchor for a DIFFERENT branch", func(t *testing.T) {
		t.Setenv(env, "")
		conf := &configuration.Configuration{Branch: "feature-x"}
		if got, _ := platformAnalyzedSha(p, conf, anchor); got != "" {
			t.Fatalf("got %q, want no sha: the anchor describes %q, not %q", got, anchor.Ref, conf.Branch)
		}
	})

	t.Run("no anchor and no CI env yields no sha", func(t *testing.T) {
		t.Setenv(env, "")
		if got, _ := platformAnalyzedSha(p, &configuration.Configuration{}, nil); got != "" {
			t.Fatalf("got %q", got)
		}
		empty := &platform.ResolutionAnchor{Ref: "main"}
		if got, _ := platformAnalyzedSha(p, &configuration.Configuration{}, empty); got != "" {
			t.Fatalf("got %q", got)
		}
	})
}

// TestReportPlatformOutcome covers the end-of-run line. A full report is over
// a hundred lines, so the pre-collection warning scrolls off screen and what
// remains is an ordinary-looking verdict produced without the project's
// policies. Repeating it last is what stops someone acting on that.
func TestReportPlatformOutcome(t *testing.T) {
	t.Run("standalone prints nothing", func(t *testing.T) {
		if out := captureStderr(t, func() { reportPlatformOutcome(nil) }); strings.TrimSpace(out) != "" {
			t.Fatalf("got %q", out)
		}
	})

	t.Run("an engaged run prints nothing", func(t *testing.T) {
		rc := &platform.RunContext{Endpoint: "https://p.example.com", Context: &platform.ProjectContext{}}
		if out := captureStderr(t, func() { reportPlatformOutcome(rc) }); strings.TrimSpace(out) != "" {
			t.Fatalf("a run that engaged must not warn: %q", out)
		}
	})

	t.Run("a requested but unengaged run names the cause and the consequence", func(t *testing.T) {
		rc := &platform.RunContext{Endpoint: "https://p.example.com", ContextErr: errTestContext{}}
		out := captureStderr(t, func() { reportPlatformOutcome(rc) })
		for _, want := range []string{
			"did NOT engage",             // that it happened
			"not the attributed project", // the underlying cause, verbatim
			"policies were applied",      // what it cost the run
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("output missing %q:\n%s", want, out)
			}
		}
	})
}

// TestCheckoutGateSeparatesTwoQuestions pins the distinction platform mode's
// digest depends on.
//
// "Is the checkout the analyzed project?" is a fact about the repository.
// "Should the CI configuration be read off disk?" is a policy about what the
// operator asked for, and naming a project answers it with no.
//
// Collapsing the two disabled the digest in the one place it exists for. The
// GitLab CI component passes the project path as PLUMBER_ANALYZE_PROJECT,
// and an env value is applied by calling Flags().Set, so the flag reads as
// explicitly set. A CI job therefore had IsLocalProject false while standing
// in a full checkout of exactly that project - no digest, so never a match
// against the platform's anchor, so never the snapshot path, so never the
// include attribution that comes with it.
func TestCheckoutGateSeparatesTwoQuestions(t *testing.T) {
	const url = "https://gitlab.com"
	const path = "group/project"
	matching := gitLabRemoteInfo{repoRoot: "/src/project", remoteURL: url, projectPath: path}

	// buildGitLabConf reads the package-level projectPath the flag layer
	// resolved into.
	saved := projectPath
	projectPath = path
	t.Cleanup(func() { projectPath = saved })

	cases := []struct {
		name              string
		flags             analyzeFlags
		remote            gitLabRemoteInfo
		wantCheckoutMatch bool
		wantLocalConfig   bool
	}{
		{
			name:              "plain local run: both true",
			remote:            matching,
			wantCheckoutMatch: true,
			wantLocalConfig:   true,
		},
		{
			// The CI case. The checkout is the project; the operator named
			// it anyway.
			name:              "project named explicitly, standing in that project",
			flags:             analyzeFlags{projectFromFlag: true},
			remote:            matching,
			wantCheckoutMatch: true,
			wantLocalConfig:   false,
		},
		{
			name:              "host named explicitly, standing in that project",
			flags:             analyzeFlags{gitlabURLFromFlag: true},
			remote:            matching,
			wantCheckoutMatch: true,
			wantLocalConfig:   false,
		},
		{
			// A different project's checkout must never be digested: a
			// coincidental match would evaluate one project against
			// another's configuration.
			name:              "standing in a different project",
			remote:            gitLabRemoteInfo{repoRoot: "/src/other", remoteURL: url, projectPath: "group/other"},
			wantCheckoutMatch: false,
			wantLocalConfig:   false,
		},
		{
			name:              "same path on a different host",
			remote:            gitLabRemoteInfo{repoRoot: "/src/project", remoteURL: "https://gitlab.example.com", projectPath: path},
			wantCheckoutMatch: false,
			wantLocalConfig:   false,
		},
		{
			name:              "not in a git repository at all",
			remote:            gitLabRemoteInfo{},
			wantCheckoutMatch: false,
			wantLocalConfig:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf := buildGitLabConf(url, "glpat-x", tc.flags, tc.remote, nil, nil, nil)
			if conf.CheckoutIsAnalyzedProject != tc.wantCheckoutMatch {
				t.Errorf("CheckoutIsAnalyzedProject = %v, want %v", conf.CheckoutIsAnalyzedProject, tc.wantCheckoutMatch)
			}
			if conf.IsLocalProject != tc.wantLocalConfig {
				t.Errorf("IsLocalProject = %v, want %v", conf.IsLocalProject, tc.wantLocalConfig)
			}
		})
	}
}
