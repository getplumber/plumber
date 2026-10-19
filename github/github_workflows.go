package github

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
	yamlv3 "gopkg.in/yaml.v3"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/runners"
	"github.com/getplumber/plumber/utils"
)

const githubWorkflowsSubdir = ".github/workflows"

// maxWorkflowFileBytes bounds a single workflow / dependabot file read.
const maxWorkflowFileBytes = 1 << 20 // 1 MiB

// resolveWithinRoot joins relParts onto rootDir and returns the path only when
// it resolves inside rootDir, with symlinks resolved on both sides. ok is false
// when the path escapes the repository (e.g. a committed symlink), so the
// caller ignores it rather than reading outside the checkout.
func resolveWithinRoot(rootDir string, relParts ...string) (string, bool) {
	rootReal := rootDir
	if r, err := filepath.EvalSymlinks(rootDir); err == nil {
		rootReal = r
	}
	joined := filepath.Join(append([]string{rootReal}, relParts...)...)
	targetReal := joined
	if r, err := filepath.EvalSymlinks(joined); err == nil {
		targetReal = r
	}
	rel, err := filepath.Rel(rootReal, targetReal)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return joined, false
	}
	return joined, true
}

const (
	fmtReadErr = "read %s: %w"
	fmtFileErr = "%s: %w"
)

// collectWorkflowJobs reads every .yml/.yaml file under
// <rootDir>/.github/workflows/ and returns the parsed jobs, sorted by
// name. A missing workflows directory — or one that resolves outside
// the repository (e.g. a committed symlink) — is not an error: the
// scan simply carries no jobs, and the caller still collects the
// repository-level artifacts (dependabot, Renovate, security policy,
// Dockerfiles) that do not depend on that directory. An unreadable file
// lands in partialErrors so the caller can surface it without aborting
// the whole scan. A file that reads fine but does not parse as a
// workflow (GitHub itself refuses to run it: an undefined anchor, a
// tab-indented block, a duplicate key) is not a collection failure: it
// is returned as an invalid workflow, reported through ISSUE-423
// (monorepo issue #517).
func collectWorkflowJobs(rootDir string) (jobs []ir.Job, files []ir.AnalyzedWorkflow, invalid []ir.InvalidWorkflow, partialErrors []error, err error) {
	dir, ok := resolveWithinRoot(rootDir, githubWorkflowsSubdir)
	if !ok {
		return nil, nil, nil, nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil, nil, nil
		}
		return nil, nil, nil, nil, fmt.Errorf(fmtReadErr, dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, readErr := utils.ReadFileLimit(path, maxWorkflowFileBytes)
		if readErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf(fmtFileErr, name, readErr))
			continue
		}
		// Retain the file for the JSON report's analyzed-CI-config block,
		// under its repo-relative path (#443).
		rel := githubWorkflowsSubdir + "/" + name
		files = append(files, ir.AnalyzedWorkflow{Path: rel, Content: string(data)})
		fileJobs, parseErr := parseGitHubWorkflowJobs(data, workflowBaseName(name), path)
		if parseErr != nil {
			invalid = append(invalid, ir.InvalidWorkflow{Path: rel, Error: parseErr.Error()})
			continue
		}
		jobs = append(jobs, fileJobs...)
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].Name < jobs[j].Name
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(invalid, func(i, j int) bool { return invalid[i].Path < invalid[j].Path })
	return jobs, files, invalid, partialErrors, nil
}

// ScanGitHubWorkflowsWithProgress reads every .yml/.yaml file under
// <rootDir>/.github/workflows/ and aggregates them into a single
// NormalizedPipeline. Job names are namespaced by the workflow file base
// name ("ci/lint", "release/build", ...) so two workflows can expose
// identically-named jobs without clashing in the IR.
//
// A missing workflows directory is not an error: the returned pipeline
// simply carries no jobs. An individual unreadable file is returned in
// partialErrors so the caller can surface it without aborting the whole
// scan; a file that reads fine but does not parse as a workflow is
// returned on the pipeline's InvalidWorkflows instead (#517).
//
// The caller is notified through progressFn as the scan works. The
// progress total is sized so the bar advances monotonically end-to-end:
//
//	step 1                 Scanning workflow files
//	step 2..(1+N)          Resolving action <n>      (N unique refs)
//	step 2+N               Scan complete
//
// The last step (policy evaluation) is reported by the caller
// (RunGitHubAnalysis) using the same total so the bar keeps
// climbing. progressFn may be nil; callers that don't care about
// progress simply pass nil.
func ScanGitHubWorkflowsWithProgress(projectPath, defaultBranch, rootDir, apiHost string, enrichActionMetadata, scanMutableExec bool, progressFn ProgressFunc) (pipeline *ir.NormalizedPipeline, partialErrors []error, err error) {
	pipeline = &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		ProjectPath:   projectPath,
		DefaultBranch: defaultBranch,
	}
	// Producer-side check: if the scanned repo is itself an action whose
	// own source fetches mutable remote code, flag it. Read from the
	// local checkout; computed even when the repo has no workflows. Gated
	// on the control being active so a disabled control does no scanning.
	if scanMutableExec {
		pipeline.SelfActionMutableExec = ScanLocalSelfAction(rootDir)
	}
	jobs, workflowFiles, invalidWorkflows, partialErrors, err := collectWorkflowJobs(rootDir)
	if err != nil {
		return nil, nil, err
	}
	pipeline.Jobs = jobs
	pipeline.InvalidWorkflows = invalidWorkflows
	var client *GitHubMetadataClient
	if enrichActionMetadata {
		client = NewGitHubMetadataClientForHost(apiHost)
	}
	defs := definitionFetcherForHost(apiHost, client)
	// The resolved pipeline (spec 2026-10-16 section 4.1) is built right
	// after the workflows collectWorkflowJobs parsed, before the reusable
	// callers are linked and before the enrichment, which then runs over
	// the closure unchanged.
	resolveNestedActions(pipeline, defs, nestedScope{projectPath: projectPath, readLocal: diskReader(rootDir), localOnDisk: true})
	linkReusableCallers(pipeline.Jobs, projectPath)
	pipeline.AnalyzedWorkflows = workflowFiles
	if dcfg, derr := scanDependabotConfig(rootDir); derr != nil {
		partialErrors = append(partialErrors, derr)
	} else if dcfg != nil {
		pipeline.Dependabot = dcfg
	}
	pipeline.RenovateConfigPath = scanRenovateConfig(rootDir)
	pipeline.SecurityPolicyPath = scanSecurityPolicy(rootDir)
	pipeline.Dockerfiles = scanDockerfiles(rootDir)
	// Reserve 3 leading/trailing steps around the per-action phase:
	// "Scanning" at step 1, "Evaluating policies" at step (total-1)
	// emitted by the caller (RunGitHubAnalysis), and a final "Scan
	// complete" at total.
	n := countUniqueActionRefs(pipeline)
	total := n + 3
	report(progressFn, 1, total, "Scanning workflow files")
	if enrichActionMetadata {
		enrichActions(pipeline, client, defs, scanMutableExec, wrapProgress(progressFn, total))
	}
	return pipeline, partialErrors, nil
}

// countUniqueActionRefs returns the number of distinct `owner/
// repo@ref` step-level references the pipeline carries. Used to
// size the progress bar; duplicates only count once because the
// metadata client caches every lookup.
func countUniqueActionRefs(pipeline *ir.NormalizedPipeline) int {
	seen := map[string]struct{}{}
	for i := range pipeline.Jobs {
		for k := range pipeline.Jobs[i].Uses {
			seen[pipeline.Jobs[i].Uses[k].Uses] = struct{}{}
		}
	}
	return len(seen)
}

// wrapProgress adapts the per-enrichment-step callback (done, N,
// message) into the global progress scale so the bar keeps
// climbing. The enrichment owns slots 2..(1+N); its inner `done`
// counter is offset by +1 and its total is overridden to the
// pipeline-wide grand total.
func wrapProgress(fn ProgressFunc, grandTotal int) ProgressFunc {
	if fn == nil {
		return nil
	}
	return func(done, _ int, message string) {
		fn(done+1, grandTotal, message)
	}
}

// wrapProgressRemote is the remote-mode counterpart of wrapProgress.
// The remote scan already consumed slots 1..(1+N) for the listing
// and per-file fetch phase (N = pipeline.WorkflowFileCount), so the
// enrichment phase that follows occupies slots (2+N)..(1+N+M). The
// inner counter from enrichActions is offset by
// (1+N), the total is set to the pipeline-wide grand total returned
// by TotalProgressStepsForPipeline so the bar keeps climbing
// smoothly into the trailing caller-owned slots.
func wrapProgressRemote(fn ProgressFunc, pipeline *ir.NormalizedPipeline) ProgressFunc {
	if fn == nil || pipeline == nil {
		return nil
	}
	offset := 1 + pipeline.WorkflowFileCount
	grandTotal := TotalProgressStepsForPipeline(pipeline)
	return func(done, _ int, message string) {
		fn(offset+done, grandTotal, message)
	}
}

// TotalProgressStepsForPipeline returns the grand total the caller
// (RunGitHubAnalysis / RunGitHubAnalysisRemote) should use when
// emitting its own progress updates for the post-scan phases, so the
// bar stays in sync with what the collector already reported.
//
// Layout in slots, both modes:
//
//	1                    "Scanning" (local) or "Listing" (remote)
//	2..(1+N)             per-file fetch ticks (remote only;
//	                     WorkflowFileCount is 0 in local mode)
//	(2+N)..(1+N+M)       per-action enrichment ticks (M = unique refs)
//	(2+N+M)              "Resolving branch protection"
//	(3+N+M)              "Evaluating policies"
//	(4+N+M)              "Analysis complete"
//
// Total = N + M + 4. WorkflowFileCount is populated by
// ScanGitHubWorkflowsRemote; local scans leave it at zero so the
// formula collapses to M + 4 there.
func TotalProgressStepsForPipeline(pipeline *ir.NormalizedPipeline) int {
	if pipeline == nil {
		return 4
	}
	return pipeline.WorkflowFileCount + countUniqueActionRefs(pipeline) + 4
}

// ProgressFunc is the signature callers use to observe the progress
// of long-running collector operations — currently the GitHub API
// enrichment phase.
type ProgressFunc func(step, total int, message string)

func report(fn ProgressFunc, step, total int, message string) {
	if fn != nil {
		fn(step, total, message)
	}
}

// enrichActions walks every job's steps[].uses and
// populates Action.Metadata from the GitHub REST API. Uses a shared
// client so duplicate `owner/repo@ref` references across workflows
// cost a single lookup. Also resolves the tag named in a trailing
// `# vX.Y.Z` comment so ref-version-mismatch can compare claim vs
// reality.
//
// When progressFn is non-nil, emits a "Resolving <uses>" step for
// every unique reference so the caller's spinner can track the
// long phase. Duplicate refs only emit once because the client
// caches and the enrichment loop iterates actions left to right.
// scanMutableExec gates the per-action source fetch that powers
// actionsMustNotExecuteMutableRemoteCode (ISSUE-714). When false, the
// collector skips resolveMutableExec entirely — up to ~7 sequential HTTP
// requests per unique action — so disabling the control removes its
// scan-time and rate-limit cost instead of merely hiding the findings.
//
// The metadata client and the definition fetcher are supplied rather
// than constructed, so tests can drive the collector-to-IR handoff
// through a stubbed transport (enrichActionsWithClient). Every field the
// policies read crosses from GitHubMetadata into ir.ActionMetadata
// here, and a field dropped in that copy silently disables the rule
// that consumes it while every other test stays green.
func enrichActions(pipeline *ir.NormalizedPipeline, client *GitHubMetadataClient, defs *definitionFetcher, scanMutableExec bool, progressFn ProgressFunc) {
	if !client.Available() {
		// Returning silently here was the widest silent pass on this
		// provider: no action gets .Metadata, so every rule that reads it
		// simply never fires, and nine controls report passed over an
		// enrichment that did not run. The cause was already recorded on
		// the client and never read.
		//
		// The warning goes on the same channel the per-action ones use, so
		// the renderer and the JSON/SARIF writers surface it exactly as
		// they already surface a blocked tag list (ISSUE-228).
		if reason := client.UnavailableReason(); reason != "" {
			pipeline.AdvisoryWarnings = append(pipeline.AdvisoryWarnings, reason)
		}
		return
	}
	// Pre-count unique refs for accurate N/total ratios.
	uniqueRefs := map[string]struct{}{}
	for i := range pipeline.Jobs {
		for k := range pipeline.Jobs[i].Uses {
			if a := pipeline.Jobs[i].Uses[k]; !a.Nested || !defs.refuses(a.Uses) {
				uniqueRefs[a.Uses] = struct{}{}
			}
		}
	}
	total := len(uniqueRefs)
	seen := map[string]struct{}{}
	mreCache := map[string]*ir.MutableRemoteExec{}
	done := 0
	for i := range pipeline.Jobs {
		job := &pipeline.Jobs[i]
		for k := range job.Uses {
			action := &job.Uses[k]
			if action.Nested && defs.refuses(action.Uses) {
				// A nested reference past the budget, or outside GitHub's
				// grammar, is never read: neither its metadata nor its
				// source (spec 2026-10-16 section 4.3, R8).
				continue
			}
			if _, already := seen[action.Uses]; !already {
				done++
				seen[action.Uses] = struct{}{}
				report(progressFn, done, total, fmt.Sprintf("Resolving action %s", action.Uses))
			}
			meta := client.Resolve(action.Uses)
			var mre *ir.MutableRemoteExec
			if scanMutableExec {
				mre = resolveMutableExec(action.Uses, defs, mreCache)
			}
			if isZeroMetadata(meta) && action.Comment == "" && mre == nil {
				continue
			}
			amd := &ir.ActionMetadata{
				RepoArchived:       meta.RepoArchived,
				RefExists:          meta.RefExists,
				RefKnownAbsent:     meta.RefKnownAbsent,
				RefKind:            meta.RefKind,
				RefCommitSha:       meta.RefCommitSha,
				TagSha:             meta.TagSha,
				LatestTag:          meta.LatestTag,
				LatestReleaseSha:   meta.LatestReleaseSha,
				RefIsAmbiguous:     meta.RefIsAmbiguous,
				Advisories:         meta.Advisories,
				AdvisorySeverities: meta.AdvisorySeverities,
				StargazersCount:    meta.StargazersCount,
				MutableRemoteExec:  mre,
				RedirectedOwner:    meta.RedirectedOwner,
			}
			if action.Comment != "" {
				amd.CommentVersion = extractVersionFromComment(action.Comment)
				if amd.CommentVersion != "" {
					if ownerRepo := ownerRepoFromUses(action.Uses); ownerRepo != "" {
						amd.CommentTagSha = client.ResolveTagSha(ownerRepo, amd.CommentVersion)
					}
				}
			}
			action.Metadata = amd
		}
	}
	// Surface any action whose known-CVE check could not be completed
	// (pinned commit unresolvable, tag list blocked) so the renderer and
	// output writers can show a "could not verify" warning instead of a
	// silent pass (ISSUE-228).
	pipeline.AdvisoryWarnings = append(pipeline.AdvisoryWarnings, client.DegradedChecks()...)
}

// ownerRepoFromUses extracts "owner/repo" from a uses: value,
// dropping any sub-path (composite-action reference) and @ref tail.
func ownerRepoFromUses(uses string) string {
	at := strings.Index(uses, "@")
	if at < 0 {
		return ""
	}
	head := uses[:at]
	parts := strings.SplitN(head, "/", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// commentVersionRegex matches the version token in a trailing
// `# vX.Y.Z` comment. Accepts `v4.1.0`, `4.1.0`, `v4` — returns the
// first match including any `v` prefix, which is the canonical tag
// form most actions use.
var commentVersionRegex = regexp.MustCompile(`(?i)\bv?\d+(?:\.\d+)*(?:-[A-Za-z0-9.-]+)?\b`)

func extractVersionFromComment(comment string) string {
	return commentVersionRegex.FindString(comment)
}

// ghDependabotConfig mirrors the subset of .github/dependabot.yml the
// dependabot-* policies care about. `updates[].insecure-external-code-
// execution` is the critical toggle: "allow" lets Dependabot run
// install / postinstall hooks during version resolution. `cooldown:`
// is captured only to its presence — the exact thresholds are
// policy-irrelevant for the missing-cooldown check.
type ghDependabotConfig struct {
	Updates []struct {
		PackageEcosystem     string `yaml:"package-ecosystem"`
		InsecureExternalExec string `yaml:"insecure-external-code-execution"`
		Cooldown             any    `yaml:"cooldown"`
	} `yaml:"updates"`
}

// scanDependabotConfig reads .github/dependabot.yml (or .yaml) if it
// exists and surfaces the list of ecosystems that re-enable insecure
// external code execution. Missing file is not an error: the return
// is (nil, nil) and the pipeline simply carries no dependabot data.
func scanDependabotConfig(rootDir string) (*ir.DependabotConfig, error) {
	for _, name := range []string{"dependabot.yml", "dependabot.yaml"} {
		path, ok := resolveWithinRoot(rootDir, ".github", name)
		if !ok {
			continue
		}
		data, err := utils.ReadFileLimit(path, maxWorkflowFileBytes)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf(fmtReadErr, path, err)
		}
		var cfg ghDependabotConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		var insecure []string
		var missingCooldown []string
		for _, u := range cfg.Updates {
			if u.InsecureExternalExec == "allow" {
				insecure = append(insecure, u.PackageEcosystem)
			}
			if u.Cooldown == nil {
				missingCooldown = append(missingCooldown, u.PackageEcosystem)
			}
		}
		return &ir.DependabotConfig{
			Path:                      path,
			InsecureExecEcosystems:    insecure,
			MissingCooldownEcosystems: missingCooldown,
		}, nil
	}
	return nil, nil
}

// ghWorkflowHeader mirrors the top-level shape of a GitHub Actions
// workflow file. Using a typed struct with explicit yaml tags avoids the
// YAML 1.1 trap where `on:` would otherwise be parsed as the boolean
// true and silently dropped from a map[string]any root.
type ghWorkflowHeader struct {
	Name        string         `yaml:"name"`
	On          any            `yaml:"on"`
	Permissions any            `yaml:"permissions"`
	Concurrency any            `yaml:"concurrency"`
	Env         any            `yaml:"env"`
	CacheMode   any            `yaml:"cache-mode"`
	Jobs        map[string]any `yaml:"jobs"`
}

// parseGitHubWorkflowJobs extracts jobs.<name>.container, workflow-level
// permissions, and workflow triggers from a single workflow file. Jobs
// are emitted with a namespaced name (e.g. "ci/lint") and OriginFile
// set to the absolute workflow path. Workflow-level `permissions:` are
// propagated to every job that does not override them; `on:` triggers
// are propagated uniformly so trigger-focused policies can see them at
// the job level.
// workflowContext holds the workflow-level values that are shared across every
// job in the workflow. Grouping them avoids passing many parameters to the
// per-job builder.
type workflowContext struct {
	perms    any
	env      map[string]string
	triggers []string
	// hasTriggers is Job.WorkflowHasTriggers: true when the workflow's
	// `on:` key names at least one event (triggers is then non-empty
	// too), false when `on:` is absent or empty. Kept distinct from
	// len(triggers) > 0 at the call site only for the doc comment this
	// gives the field; the value is the same check.
	hasTriggers          bool
	pushBranches         []string
	pushBranchesIgnore   []string
	pushTags             []string
	pushTagsIgnore       []string
	workflowRunUpstreams []string
	triggerTypes         map[string][]string
	name                 string
	hasConcurrency       bool
	cacheMode            *ir.CacheModeDecl
	jobCacheModeLines    map[string]int
	jobLines             map[string]int
	usesLines            map[string][]int
	usesComments         map[string]string
}

// mergedEnv combines workflow-level, job-level, and step-level env maps into
// one map. Later entries win on key collision, mirroring GitHub's runtime
// precedence (step > job > workflow).
func mergedEnv(workflowEnv map[string]string, section map[string]any) map[string]string {
	var out map[string]string
	for _, src := range []map[string]string{
		workflowEnv,
		normalizeGitHubEnv(section["env"]),
		extractGitHubStepEnvs(section["steps"]),
	} {
		for k, v := range src {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}

// annotateUses attaches line numbers and comment pins to extracted uses refs.
func annotateUses(uses []ir.Action, usesLines []int, usesComments map[string]string) {
	for k := range uses {
		if c, ok := usesComments[uses[k].Uses]; ok {
			uses[k].Comment = c
		}
		if k < len(usesLines) {
			uses[k].Line = usesLines[k]
		}
	}
}

// stringOrList accepts the YAML forms GitHub allows for needs and the push
// filters: a scalar or a sequence. Non-string items are dropped, and a map
// comes back nil.
func stringOrList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// parseGitHubRunsOn reads a job's `runs-on:` value: a literal label, or a
// list of literal labels, read label by label; expression is true when
// the value, or any element of it, carries a `${{ ... }}` runtime
// expression, or the value is the `group:`/`labels:` object form this
// collector does not model (either way MarkInert can decide nothing
// about a retired runner from it). A plain absence (no `runs-on:` at
// all) answers (nil, false): nothing to check, not an expression.
func parseGitHubRunsOn(v any) (labels []string, expression bool) {
	switch t := v.(type) {
	case string:
		if strings.Contains(t, "${{") {
			return nil, true
		}
		return []string{t}, false
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if strings.Contains(s, "${{") {
				return nil, true
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, false
	case map[any]any, map[string]any:
		return nil, true
	}
	return nil, false
}

// cacheAndArtifactRefs derives the structured cache and artifact uses of a job
// from its actions steps: the official cache actions, the caching actions
// the cache poisoning control knows (builtinCacheRefs), and the official
// artifact actions.
func cacheAndArtifactRefs(uses []ir.Action, jobID string, runsOn []string, runsOnExpression bool) (caches []ir.CacheRef, artifacts []ir.ArtifactRef) {
	osName, arch := runnerOSArch(runsOn, runsOnExpression)
	for _, a := range uses {
		name := a.Uses
		if i := strings.Index(name, "@"); i >= 0 {
			name = name[:i]
		}
		withStr := func(key string) string {
			if s, ok := a.With[key].(string); ok {
				return s
			}
			return ""
		}
		withPaths := func(key string) []string {
			s := withStr(key)
			if s == "" {
				return nil
			}
			var out []string
			for _, line := range strings.Split(s, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					out = append(out, line)
				}
			}
			return out
		}
		step := func(ref ir.CacheRef) ir.CacheRef {
			ref.Uses, ref.Line = a.Uses, a.Line
			return ref
		}
		// The step's path list, read once: every entry of the step shares
		// it, so a long path block and many restore-keys lines cost their
		// sum, never their product.
		paths := withPaths("path")
		// restoreFallbacks is one restore entry per restore-keys line: when
		// the exact key misses, the action restores the most recent cache
		// whose key starts with one of them, so each prefix is its own way in
		// for whoever saved a matching key.
		restoreFallbacks := func() []ir.CacheRef {
			var out []ir.CacheRef
			for _, prefix := range withPaths("restore-keys") {
				out = append(out, step(ir.CacheRef{Key: prefix, Paths: paths, Mode: "restore", Prefix: true}))
			}
			return out
		}
		switch name {
		case "actions/cache":
			caches = append(caches, step(ir.CacheRef{Key: withStr("key"), Paths: paths, Mode: "both"}))
			caches = append(caches, restoreFallbacks()...)
		case "actions/cache/restore":
			caches = append(caches, step(ir.CacheRef{Key: withStr("key"), Paths: paths, Mode: "restore"}))
			caches = append(caches, restoreFallbacks()...)
		case "actions/cache/save":
			caches = append(caches, step(ir.CacheRef{Key: withStr("key"), Paths: paths, Mode: "save"}))
		case "actions/upload-artifact":
			artName := withStr("name")
			if artName == "" {
				artName = "artifact" // the action's documented default
			}
			artifacts = append(artifacts, ir.ArtifactRef{Name: artName, Paths: paths, Mode: "produce"})
		case "actions/upload-pages-artifact":
			artName := withStr("name")
			if artName == "" {
				artName = "github-pages" // the action's documented default
			}
			artifacts = append(artifacts, ir.ArtifactRef{Name: artName, Paths: paths, Mode: "produce"})
		case "actions/deploy-pages":
			artName := withStr("artifact_name")
			if artName == "" {
				artName = "github-pages"
			}
			artifacts = append(artifacts, ir.ArtifactRef{Name: artName, Mode: "consume"})
		case "actions/download-artifact":
			artifacts = append(artifacts, ir.ArtifactRef{Name: withStr("name"), Pattern: withStr("pattern"), Mode: "consume", CrossRun: withStr("run-id") != ""})
		default:
			for _, ref := range builtinCacheRefs(strings.ToLower(name), a.With, jobID, osName, arch) {
				caches = append(caches, step(ref))
			}
		}
	}
	return caches, artifacts
}

// runnerOSArch resolves the OS and architecture a job's runs-on labels
// name, when runsOn is exactly one literal label one of the hosted
// runner families recognizes: "ubuntu-*" -> Linux, "macos-*" -> macOS
// (its architecture, macOSArch), "windows-*" -> Windows (its
// architecture, labelArch). A matrix (`runs-on: ${{ matrix.os }}`), an
// expression, zero or more than one label, or a label this program does
// not recognize resolves neither OS nor arch: guessing wrong is worse
// than leaving the cache key's os/arch part open (control/cachekeys.go
// then matches it against anything, never asserting equal or different
// without evidence). The OS itself is read off the prefix alone (a
// "-large"/"-xlarge"/"-intel" variant is still that OS); only the arch
// is this strict about the label's exact shape.
func runnerOSArch(runsOn []string, runsOnExpression bool) (osName, arch string) {
	if runsOnExpression || len(runsOn) != 1 {
		return "", ""
	}
	label := strings.ToLower(runsOn[0])
	switch {
	case strings.HasPrefix(label, "ubuntu-"):
		return "Linux", labelArch(label)
	case strings.HasPrefix(label, "windows-"):
		return "Windows", labelArch(label)
	case strings.HasPrefix(label, "macos-"):
		return "macOS", macOSArch(label)
	}
	return "", ""
}

// labelArch is ARM64 when the label itself names an ARM runner ("-arm",
// "arm64": GitHub's Linux and Windows ARM hosted labels, e.g.
// "ubuntu-24.04-arm"), X64 for a plain hosted label
// (runners.PlainHostedLabel, the same parser the preinstalled-tool guard
// reads the image with), no arch part at all for every other shape: a
// "-large"/"-xlarge" variant or anything this program does not
// recognize as one of the two.
func labelArch(label string) string {
	if strings.Contains(label, "arm64") || strings.Contains(label, "-arm") {
		return "ARM64"
	}
	if _, plain := runners.PlainHostedLabel(label); plain {
		return "X64"
	}
	return ""
}

// macOSArch is the architecture a macos-* label resolves to: ARM64 when
// the label names it explicitly ("-arm", "arm64"); for a plain hosted
// label (runners.PlainHostedLabel), by the runner's numbered generation: macos-13
// and earlier were Intel (X64), macos-14 and later (Apple Silicon) and
// the unversioned "macos-latest" (which tracks the current default, now
// past 14) are ARM64; every other shape ("-large", "-xlarge", "-intel",
// anything with an extra suffix) gives no arch part at all, never a
// guess (a label such as "macos-15-intel" is exactly this case: its
// numbered generation would read ARM64, but the "-intel" suffix says
// otherwise, so this program asserts neither).
func macOSArch(label string) string {
	if strings.Contains(label, "arm64") || strings.Contains(label, "-arm") {
		return "ARM64"
	}
	if _, plain := runners.PlainHostedLabel(label); !plain {
		return ""
	}
	if n, err := strconv.Atoi(strings.TrimPrefix(label, "macos-")); err == nil && n <= 13 {
		return "X64"
	}
	return "ARM64"
}

// cacheRefParts builds a CacheRef.Parts map from the per-action extras
// (manager, version, job, key: dropped empty) and the job's own os/arch,
// nil when none of them resolved to anything.
func cacheRefParts(osName, arch string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range extra {
		if v != "" {
			out[k] = v
		}
	}
	if osName != "" {
		out["os"] = osName
	}
	if arch != "" {
		out["arch"] = arch
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// literalVersionInput reads a version input's resolved value: empty when
// the step instead names a version file (node-version-file,
// python-version-file, go-version-file: the version then lives in a file
// this program does not read), when the input is empty, or when it is a
// runtime expression this program cannot resolve to one literal value.
func literalVersionInput(version, versionFile string) string {
	if versionFile != "" || version == "" || strings.Contains(version, "${{") {
		return ""
	}
	return version
}

// literalInput returns v unless it still carries a `${{ ... }}`
// expression (a `cache: ${{ matrix.cache }}` input, say): a resolved
// value never contains expression syntax, so anything that does was
// never really resolved to one literal manager name.
func literalInput(v string) string {
	if strings.Contains(v, "${{") {
		return ""
	}
	return v
}

// builtinCacheRefs is the cache of a caching action that keys its cache
// itself, saved and restored unless an input literally turns saving off,
// with Family the name a reader recognizes and Key what two jobs must share
// to reach each other's cache. Expressions in an input are kept as
// written. Nil when the action is none of them or its cache is off.
//
//   - Swatinem/rust-cache: prefix-key (default v0-rust), then shared-key
//     when given, else the key input when given followed by the job id
//     (unless add-job-id-key: false), the family leaving the job id out;
//     the toolchain and lock file hashes stay in the run-time part of the
//     key, so the entry is a prefix; save-if: false restores only.
//   - actions/setup-node, setup-python, setup-java (opt-in with cache: a
//     manager), setup-dotnet (opt-in with cache: true), setup-go (on
//     unless cache: false): "<action>-<manager>", or "<action>" for a
//     boolean, then cache-dependency-path in parentheses when given. The
//     action restores the exact key of the manager and of the dependency
//     files' hash: no prefix.
//   - gradle/actions/setup-gradle, gradle/gradle-build-action: "gradle",
//     off with cache-disabled: true, restore only with cache-read-only: true.
//   - pnpm/action-setup (opt-in with cache): the action name.
//   - docker/build-push-action with a type=gha cache: one entry per scope
//     (default buildkit) in cache-from (restored) and cache-to (saved).
func builtinCacheRefs(name string, with map[string]any, jobID, osName, arch string) []ir.CacheRef {
	in := func(key string) string {
		switch v := with[key].(type) {
		case string:
			return strings.TrimSpace(v)
		case bool:
			return strconv.FormatBool(v)
		}
		return ""
	}
	isFalse := func(key string) bool { return strings.EqualFold(in(key), "false") }
	isTrue := func(key string) bool { return strings.EqualFold(in(key), "true") }
	family := func(key string) ir.CacheRef { return ir.CacheRef{Key: key, Family: key, Mode: "both", Prefix: true} }
	exact := func(fam string) []ir.CacheRef {
		key := fam
		var paths []string
		for _, line := range strings.Split(in("cache-dependency-path"), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				paths = append(paths, line)
			}
		}
		if len(paths) > 0 {
			key += " (" + strings.Join(paths, ", ") + ")"
		}
		return []ir.CacheRef{{Key: key, Family: fam, Mode: "both"}}
	}
	short := name[strings.LastIndex(name, "/")+1:]
	switch name {
	case "swatinem/rust-cache":
		key := in("prefix-key")
		if key == "" {
			key = "v0-rust"
		}
		ref := family(key)
		extra := map[string]string{}
		if shared := in("shared-key"); shared != "" {
			ref = family(key + "-" + shared)
			if !strings.Contains(shared, "${{") {
				extra["key"] = shared
			}
		} else {
			if k := in("key"); k != "" {
				ref = family(key + "-" + k)
				if !strings.Contains(k, "${{") {
					extra["key"] = k
				}
			}
			if !isFalse("add-job-id-key") && jobID != "" {
				ref.Key += "-" + jobID
				extra["job"] = jobID
			}
		}
		if isFalse("save-if") {
			ref.Mode = "restore"
		}
		ref.Parts = cacheRefParts(osName, arch, extra)
		return []ir.CacheRef{ref}
	case "actions/setup-node", "actions/setup-python", "actions/setup-java", "actions/setup-dotnet":
		if in("cache") == "" || isFalse("cache") {
			return nil
		}
		manager := ""
		fam := short
		if !isTrue("cache") {
			manager = in("cache")
			fam = short + "-" + manager
		}
		refs := exact(fam)
		extra := map[string]string{"manager": literalInput(manager)}
		switch name {
		case "actions/setup-node":
			extra["version"] = literalVersionInput(in("node-version"), in("node-version-file"))
		case "actions/setup-python":
			extra["version"] = literalVersionInput(in("python-version"), in("python-version-file"))
		}
		refs[0].Parts = cacheRefParts(osName, arch, extra)
		return refs
	case "actions/setup-go":
		if isFalse("cache") {
			return nil
		}
		refs := exact(short)
		refs[0].Parts = cacheRefParts(osName, arch, map[string]string{"version": literalVersionInput(in("go-version"), in("go-version-file"))})
		return refs
	case "gradle/actions/setup-gradle", "gradle/gradle-build-action":
		if isTrue("cache-disabled") {
			return nil
		}
		ref := family("gradle")
		if isTrue("cache-read-only") {
			ref.Mode = "restore"
		}
		ref.Parts = cacheRefParts(osName, arch, nil)
		return []ir.CacheRef{ref}
	case "pnpm/action-setup":
		if in("cache") == "" || isFalse("cache") {
			return nil
		}
		ref := family(name)
		ref.Parts = cacheRefParts(osName, arch, nil)
		return []ir.CacheRef{ref}
	case "docker/build-push-action":
		return buildxGhaCaches(name, in("cache-from"), in("cache-to"))
	}
	return nil
}

// buildxGhaCaches is one entry per gha cache scope a buildx step reads
// (cache-from) or writes (cache-to): the scope keys the cache, two scopes
// are two caches.
func buildxGhaCaches(name, from, to string) []ir.CacheRef {
	restored, saved := ghaScopes(from), ghaScopes(to)
	modes := map[string]string{}
	var order []string
	for _, sc := range restored {
		if _, ok := modes[sc]; !ok {
			order = append(order, sc)
		}
		modes[sc] = "restore"
	}
	for _, sc := range saved {
		switch modes[sc] {
		case "restore":
			modes[sc] = "both"
		case "":
			order = append(order, sc)
			modes[sc] = "save"
		}
	}
	sort.Strings(order)
	var out []ir.CacheRef
	for _, sc := range order {
		out = append(out, ir.CacheRef{Key: name + " (scope=" + sc + ")", Family: name, Mode: modes[sc]})
	}
	return out
}

// ghaScopes is the scope of every type=gha entry of a cache-from or
// cache-to input (one entry per line), buildkit when an entry names none.
func ghaScopes(input string) []string {
	var out []string
	for _, line := range strings.Split(input, "\n") {
		attrs := map[string]string{}
		for _, part := range strings.Split(strings.TrimSpace(line), ",") {
			k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
			attrs[strings.ToLower(k)] = strings.TrimSpace(v)
		}
		if !strings.EqualFold(attrs["type"], "gha") {
			continue
		}
		scope := attrs["scope"]
		if scope == "" {
			scope = "buildkit"
		}
		out = append(out, scope)
	}
	return out
}

// buildJob converts one raw YAML job section into an ir.Job.
func buildJob(jobName string, section map[string]any, wfCtx workflowContext, namespace, originFile string) ir.Job {
	job := ir.Job{
		Name:                   namespace + "/" + jobName,
		OriginFile:             originFile,
		OriginLine:             wfCtx.jobLines[jobName],
		Triggers:               wfCtx.triggers,
		WorkflowHasTriggers:    wfCtx.hasTriggers,
		PushBranches:           wfCtx.pushBranches,
		PushBranchesIgnore:     wfCtx.pushBranchesIgnore,
		PushTags:               wfCtx.pushTags,
		PushTagsIgnore:         wfCtx.pushTagsIgnore,
		WorkflowRunWorkflows:   wfCtx.workflowRunUpstreams,
		TriggerTypes:           wfCtx.triggerTypes,
		WorkflowName:           wfCtx.name,
		WorkflowHasConcurrency: wfCtx.hasConcurrency,
	}
	if _, ok := section["concurrency"]; ok {
		job.JobHasConcurrency = true
	}
	if raw, ok := section["cache-mode"]; ok {
		job.CacheMode = cacheModeDecl(raw, wfCtx.jobCacheModeLines[jobName], "job")
	} else if wfCtx.cacheMode != nil {
		decl := *wfCtx.cacheMode
		job.CacheMode = &decl
	}
	// continue-on-error: true maps to allowFailure. Only literal booleans
	// are honoured — runtime expressions are unpredictable statically.
	if v, ok := section["continue-on-error"].(bool); ok && v {
		job.AllowFailure = true
	}
	if img, ok := parseGitHubContainer(section["container"]); ok {
		job.Image = &img
		job.ImageRef = containerImageRef(section["container"])
		job.MatrixImages = matrixImages(containerImageRef(section["container"]), section)
	}
	if runsOn, expression := parseGitHubRunsOn(section["runs-on"]); expression {
		job.RunsOnExpression = true
	} else if len(runsOn) > 0 {
		job.RunsOn = runsOn
	}
	if jobPerms, present := section["permissions"]; present {
		job.Permissions = normalizeGitHubPermissions(jobPerms)
	} else if wfCtx.perms != nil {
		job.Permissions = normalizeGitHubPermissions(wfCtx.perms)
	}
	if scripts, scriptIfs := extractGitHubRunScripts(section["steps"]); len(scripts) > 0 {
		job.Scripts = scripts
		for _, cond := range scriptIfs {
			if cond != "" {
				job.ScriptIfs = scriptIfs
				break
			}
		}
	}
	if env := mergedEnv(wfCtx.env, section); env != nil {
		job.Variables = env
	}
	if uses := extractGitHubUses(section["steps"]); len(uses) > 0 {
		annotateUses(uses, wfCtx.usesLines[jobName], wfCtx.usesComments)
		job.Uses = uses
	}
	if jobUses, ok := section["uses"].(string); ok && jobUses != "" {
		job.ReusableWorkflowUses = jobUses
		if secretsVal, ok := section["secrets"].(string); ok && secretsVal == "inherit" {
			job.SecretsInherit = true
		}
		if m, ok := ghCastStringMap(section["secrets"]); ok && len(m) > 0 {
			job.ReusableSecrets = map[string]string{}
			for k, v := range m {
				job.ReusableSecrets[k] = ghStringify(v)
			}
		}
		if m, ok := ghCastStringMap(section["with"]); ok && len(m) > 0 {
			job.ReusableWith = m
		}
	}
	if conds := collectGitHubJobConditions(section); len(conds) > 0 {
		job.Conditions = conds
	}
	if cond, ok := section["if"].(string); ok {
		job.If = cond
	}
	job.Dead = constantFalse(section["if"])
	if env := extractGitHubJobEnvironment(section["environment"]); env != "" {
		job.Environment = env
	}
	// Needs is qualified with the same namespace prefix as Name above, so a
	// bare `needs: [lint]` in workflow "ci" becomes ["ci/lint"] and matches
	// the Job.Name a path assembler would look it up by.
	for _, need := range stringOrList(section["needs"]) {
		job.Needs = append(job.Needs, namespace+"/"+need)
	}
	job.Caches, job.Artifacts = cacheAndArtifactRefs(job.Uses, jobName, job.RunsOn, job.RunsOnExpression)
	job.Artifacts = matrixArtifacts(job.Artifacts, section)
	if job.ReusableWorkflowUses != "" {
		job.MatrixCombinations = matrixCombinations(section)
	}
	return job
}

// matrixArtifacts replaces an artifact whose name is built from
// `${{ matrix.KEY }}` values the job's matrix lists as literals with one
// artifact per combination the matrix runs, so an upload or a download is
// matched on the names it really takes. A name holding any other
// expression stays as written.
func matrixArtifacts(refs []ir.ArtifactRef, section map[string]any) []ir.ArtifactRef {
	combos := matrixCombinations(section)
	if len(combos) == 0 {
		return refs
	}
	var out []ir.ArtifactRef
	for _, ref := range refs {
		names := expandMatrixRef(ref.Name, combos)
		if len(names) == 0 {
			out = append(out, ref)
			continue
		}
		for _, name := range names {
			r := ref
			r.Name = name
			out = append(out, r)
		}
	}
	return out
}

// firstDuplicateYAMLKey parses data into a yaml.v3 node tree, which keeps
// every key-value pair in document order including a repeated key, and
// walks it looking for the first mapping that carries the same key twice.
// Returns nil when the document does not parse this way at all (a syntax
// error, say): that is a failure the typed decode right after this call
// reports in its own words, so this pre-check only adds a new failure
// mode, never hides one.
func firstDuplicateYAMLKey(data []byte) error {
	var doc yamlv3.Node
	if err := yamlv3.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return duplicateKeyIn(&doc)
}

// duplicateKeyIn is firstDuplicateYAMLKey's recursive step over one node.
// Keys are compared by their source text, the way GitHub's parser sees
// them, not by the value YAML 1.1 resolves them to: `on` and "on" are the
// same key, while `no` and `off` stay two keys even though gopkg.in/yaml.v2
// reads both as false (PR #560 review). The walk descends through
// nested mappings and through sequences, so a duplicate inside one step of
// a job's `steps:` list is caught too. An alias is not followed: the node
// it points to is walked where its anchor is defined, and a `<<` merge key
// is one ordinary key, so a merge plus an override is not a duplicate.
func duplicateKeyIn(n *yamlv3.Node) error {
	switch n.Kind {
	case yamlv3.DocumentNode, yamlv3.SequenceNode:
		for _, c := range n.Content {
			if err := duplicateKeyIn(c); err != nil {
				return err
			}
		}
	case yamlv3.MappingNode:
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			k := yamlKeyIdentity(key)
			if seen[k] {
				return fmt.Errorf("line %d: mapping key %q already defined", key.Line, k)
			}
			seen[k] = true
			if err := duplicateKeyIn(n.Content[i+1]); err != nil {
				return err
			}
		}
	}
	return nil
}

// yamlKeyIdentity is the text a mapping key is compared by: a scalar's
// unquoted source text, an alias's target, and for a sequence or a mapping
// used as a key (legal YAML, never a workflow) its re-rendered form.
func yamlKeyIdentity(key *yamlv3.Node) string {
	if key.Kind == yamlv3.AliasNode && key.Alias != nil {
		key = key.Alias
	}
	if key.Kind == yamlv3.ScalarNode {
		return key.Value
	}
	out, err := yamlv3.Marshal(key)
	if err != nil {
		return fmt.Sprintf("%d:%s", key.Kind, key.Value)
	}
	return strings.TrimSpace(string(out))
}

func parseGitHubWorkflowJobs(data []byte, namespace, originFile string) ([]ir.Job, error) {
	// A duplicate mapping key anywhere in the document (the same `on:`
	// twice, the same `runs-on:` twice under one job, ...) makes GitHub's
	// own YAML parser refuse the file outright, but the typed decode just
	// below silently keeps the last value: gopkg.in/yaml.v2 does not
	// reject a duplicate key when unmarshalling into a struct (PR #560,
	// thread 2). Caught here with a lightweight pre-check, before
	// the typed decode, rather than switching that decode to
	// UnmarshalStrict, which would also reject every workflow field this
	// parser does not itself model.
	if err := firstDuplicateYAMLKey(data); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	// Not wrapped: every gopkg.in/yaml.v2 error already starts with
	// "yaml: ", which is the message an invalid workflow reports (#517).
	var wf ghWorkflowHeader
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, err
	}
	if len(wf.Jobs) == 0 {
		return nil, nil
	}

	pushBranches, pushBranchesIgnore, pushTags, pushTagsIgnore := extractGitHubPushFilters(wf.On)
	wfCacheModeLine, jobCacheModeLines := scanGitHubCacheModeLines(data)
	triggers := extractGitHubTriggers(wf.On)
	wfCtx := workflowContext{
		cacheMode:            cacheModeDecl(wf.CacheMode, wfCacheModeLine, "workflow"),
		jobCacheModeLines:    jobCacheModeLines,
		perms:                wf.Permissions,
		env:                  normalizeGitHubEnv(wf.Env),
		triggers:             triggers,
		hasTriggers:          len(triggers) > 0,
		pushBranches:         pushBranches,
		pushBranchesIgnore:   pushBranchesIgnore,
		pushTags:             pushTags,
		pushTagsIgnore:       pushTagsIgnore,
		workflowRunUpstreams: extractGitHubWorkflowRunUpstreams(wf.On),
		triggerTypes:         extractGitHubTriggerTypes(wf.On),
		name:                 wf.Name,
		hasConcurrency:       wf.Concurrency != nil,
		jobLines:             scanGitHubJobLines(data),
		usesLines:            scanGitHubUsesLines(data),
		usesComments:         scanGitHubUsesComments(data),
	}

	jobs := make([]ir.Job, 0, len(wf.Jobs))
	for jobName, v := range wf.Jobs {
		section, ok := ghCastStringMap(v)
		if !ok {
			continue
		}
		jobs = append(jobs, buildJob(jobName, section, wfCtx, namespace, originFile))
	}
	return jobs, nil
}

// constantFalseCondition is a job-level if: that is the constant false,
// bare or wrapped in an expression, any spacing and case.
var constantFalseCondition = regexp.MustCompile(`(?i)^\s*(\$\{\{\s*false\s*\}\}|false)\s*$`)

// constantFalse reports whether a job-level if: value never lets the job
// run: the YAML boolean false, or a string reading false (`'false'`,
// `${{ false }}`).
func constantFalse(v any) bool {
	switch x := v.(type) {
	case bool:
		return !x
	case string:
		return constantFalseCondition.MatchString(x)
	}
	return false
}

// extractGitHubJobEnvironment normalises the two accepted forms of
// `environment:`:
//
//	environment: production           # shorthand string
//	environment: { name: production } # long form
//
// The url sub-field of the long form is ignored — only the name gates
// deployment approvals.
func extractGitHubJobEnvironment(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[any]any:
		m, _ := ghCastStringMap(x)
		if name, ok := m["name"].(string); ok {
			return name
		}
	}
	return ""
}

// collectGitHubJobConditions gathers every `if:` expression attached to
// a job or one of its steps. The raw string is preserved (template
// expressions, booleans, whatever) so Rego policies can pattern-match
// without a dedicated parser. Non-string values are stringified via
// fmt.Sprint so a bare `if: true` surfaces as "true" rather than being
// dropped.
func collectGitHubJobConditions(section map[string]any) []string {
	var out []string
	if v, ok := section["if"]; ok {
		if s := ghStringify(v); s != "" {
			out = append(out, s)
		}
	}
	steps, ok := section["steps"].([]any)
	if !ok {
		return out
	}
	for _, s := range steps {
		step, ok := ghCastStringMap(s)
		if !ok {
			continue
		}
		if v, ok := step["if"]; ok {
			if str := ghStringify(v); str != "" {
				out = append(out, str)
			}
		}
	}
	return out
}

func ghStringify(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

// scanGitHubUsesComments walks the raw workflow bytes and returns a
// map of `uses` value -> trailing `# comment`. yaml.v2 discards
// comments during parse, so we recover them here. Used by
// ref-version-mismatch (ISSUE-708): a `@<sha> # v4.1.0` comment
// tells the reviewer which version the SHA is supposed to be; the
// policy verifies the claim against the actual tag metadata.
func scanGitHubUsesComments(data []byte) map[string]string {
	out := map[string]string{}
	// Match: `uses: owner/repo@ref # comment` with any indentation
	// and optional quotes. We also accept `- uses:` forms.
	re := regexp.MustCompile(`^\s*-?\s*uses:\s*["']?([^"'\s#]+)["']?\s*#\s*(.+?)\s*$`)
	for _, line := range strings.Split(string(data), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// Last wins on duplicates — identical `uses` refs in the
		// same file are expected to carry the same comment.
		out[m[1]] = m[2]
	}
	return out
}

// scanGitHubUsesLines walks the raw workflow bytes and returns, for
// each job name, the 1-based line numbers of every `uses:` directive
// inside that job, in file order. The yaml.v2 unmarshaller flattens
// steps into plain maps without preserving positions, so the
// collector re-scans the bytes and pairs each `[]ir.Action` entry
// with the matching line by positional index. Fires for
// ISSUE-701/110/111/114 where the reviewer needs the exact step, not
// the enclosing job header.
func scanGitHubUsesLines(data []byte) map[string][]int {
	out := map[string][]int{}
	jobHeader := regexp.MustCompile(`^  ([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(#.*)?$`)
	usesRe := regexp.MustCompile(`^\s*-?\s*uses:\s*["']?[^"'\s#]+`)
	lines := strings.Split(string(data), "\n")
	inJobs := false
	currentJob := ""
	for i, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "jobs:" {
			inJobs = true
			continue
		}
		if !inJobs {
			continue
		}
		if len(trimmed) > 0 && !strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, "\t") {
			break
		}
		if m := jobHeader.FindStringSubmatch(line); m != nil {
			currentJob = m[1]
			continue
		}
		if currentJob != "" && usesRe.MatchString(line) {
			out[currentJob] = append(out[currentJob], i+1)
		}
	}
	return out
}

// scanGitHubJobLines returns a map from job name to its 1-based line
// number in the workflow source. Used to attach a file:line hint to
// findings so editors can jump straight to the offending job. The
// scan is deliberately simple: walk the raw bytes, find the first
// line after `jobs:` that starts with two spaces followed by
// `<name>:`. YAML nesting beyond the canonical 2-space job header
// form is not modeled — if the file uses tabs or deeper indentation
// the line simply stays at 0 and the renderer omits the :line suffix.
func scanGitHubJobLines(data []byte) map[string]int {
	out := map[string]int{}
	lines := strings.Split(string(data), "\n")
	inJobs := false
	jobHeader := regexp.MustCompile(`^  ([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(#.*)?$`)
	for i, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "jobs:" {
			inJobs = true
			continue
		}
		if !inJobs {
			continue
		}
		// A non-indented non-empty line closes the jobs block.
		if len(trimmed) > 0 && !strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, "\t") {
			break
		}
		if m := jobHeader.FindStringSubmatch(line); m != nil {
			if _, seen := out[m[1]]; !seen {
				out[m[1]] = i + 1
			}
		}
	}
	return out
}

// extractGitHubUses walks `jobs.<name>.steps[]` and collects every step
// that invokes a reusable action via `uses:`, together with the raw
// `with:` block. Inline `run:` steps are ignored (they land in
// Scripts via extractGitHubRunScripts). The `with:` map values are
// kept as-is so policies can distinguish strings, booleans and
// numbers (e.g. `persist-credentials: false` — the YAML boolean,
// not the string "false").
func extractGitHubUses(v any) []ir.Action {
	stepsList, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]ir.Action, 0, len(stepsList))
	for _, s := range stepsList {
		stepMap, ok := ghCastStringMap(s)
		if !ok {
			continue
		}
		uses, ok := stepMap["uses"].(string)
		if !ok || uses == "" {
			continue
		}
		action := ir.Action{Uses: uses}
		if name, ok := stepMap["name"].(string); ok {
			action.Name = name
		}
		if cond, ok := stepMap["if"].(string); ok {
			action.If = cond
		}
		if withMap, ok := ghCastStringMap(stepMap["with"]); ok {
			action.With = withMap
		}
		out = append(out, action)
	}
	return out
}

// extractGitHubStepEnvs walks steps[].env and returns a flat map
// of every name → value pair it finds. Same shape as
// normalizeGitHubEnv so the caller can merge the two.
func extractGitHubStepEnvs(v any) map[string]string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for _, s := range list {
		step, ok := ghCastStringMap(s)
		if !ok {
			continue
		}
		stepEnvs := normalizeGitHubEnv(step["env"])
		for k, val := range stepEnvs {
			out[k] = val
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeGitHubEnv converts a workflow/job `env:` block into the
// map[string]string shape the IR carries. YAML scalar values (strings,
// booleans, numbers) are all stringified so policies can compare
// uniformly against literal strings like "true".
func normalizeGitHubEnv(v any) map[string]string {
	m, ok := v.(map[any]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		ks, ok := k.(string)
		if !ok {
			continue
		}
		out[ks] = fmt.Sprintf("%v", val)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// extractGitHubRunScripts walks `jobs.<name>.steps[]` and collects every
// inline shell script declared via `run:`. Steps using `uses:` (actions)
// are ignored — their behavior lives in the referenced action, not in
// the workflow file. Empty `run:` blocks are dropped. The second slice
// carries each collected script's step-level `if:` expression ("" when
// the step is unconditional), aligned index for index with the first.
func extractGitHubRunScripts(v any) ([]string, []string) {
	stepsList, ok := v.([]any)
	if !ok {
		return nil, nil
	}
	scripts := make([]string, 0, len(stepsList))
	ifs := make([]string, 0, len(stepsList))
	for _, s := range stepsList {
		stepMap, ok := ghCastStringMap(s)
		if !ok {
			continue
		}
		if run, ok := stepMap["run"].(string); ok && run != "" {
			scripts = append(scripts, run)
			cond, _ := stepMap["if"].(string)
			ifs = append(ifs, cond)
		}
	}
	return scripts, ifs
}

// extractGitHubTriggers returns the sorted list of event names declared
// under `on:`. The YAML value can be a string ("push"), a list
// (["push", "pull_request"]) or a map keyed by event name with optional
// filters — only the event names are preserved; their configuration is
// dropped for now.
func extractGitHubTriggers(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	case map[any]any:
		out := make([]string, 0, len(t))
		for k := range t {
			if s, ok := k.(string); ok {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// extractGitHubPushFilters reads on.push.branches, branches-ignore, tags and
// tags-ignore. Each return slice is nil when `on:` carries no push entry at
// all, when push is written as a bare string/list element (no filter map),
// or when the filter map does not declare that particular key: all four
// mean "no filter", not "matches nothing". The map form keyed by event name
// is the only shape that can carry filters; the bare string/list forms
// never do.
func extractGitHubPushFilters(v any) (branches, branchesIgnore, tags, tagsIgnore []string) {
	m, ok := v.(map[any]any)
	if !ok {
		return nil, nil, nil, nil
	}
	pushMap, ok := m["push"].(map[any]any)
	if !ok {
		return nil, nil, nil, nil
	}
	ps, ok := ghCastStringMap(pushMap)
	if !ok {
		return nil, nil, nil, nil
	}
	return stringOrList(ps["branches"]), stringOrList(ps["branches-ignore"]), stringOrList(ps["tags"]), stringOrList(ps["tags-ignore"])
}

// extractGitHubWorkflowRunUpstreams reads on.workflow_run.workflows: the
// upstream workflows whose runs trigger this one. Nil when `on:` has no
// workflow_run entry in the map form (the only form that can name an
// upstream) or the entry names none.
func extractGitHubWorkflowRunUpstreams(v any) []string {
	m, ok := v.(map[any]any)
	if !ok {
		return nil
	}
	run, ok := ghCastStringMap(m["workflow_run"])
	if !ok {
		return nil
	}
	return stringOrList(run["workflows"])
}

// extractGitHubTriggerTypes reads on.<event>.types for every event of the
// map form of on:, keyed by event name, as written. An event without a
// types: filter has no entry, and neither has any event of the string or
// list forms (no filter there: every type fires). Nil when no event
// carries one.
func extractGitHubTriggerTypes(v any) map[string][]string {
	m, ok := v.(map[any]any)
	if !ok {
		return nil
	}
	var out map[string][]string
	for k, cfg := range m {
		event, ok := k.(string)
		if !ok {
			continue
		}
		section, ok := ghCastStringMap(cfg)
		if !ok {
			continue
		}
		types := stringOrList(section["types"])
		if len(types) == 0 {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		out[event] = types
	}
	return out
}

// normalizeGitHubPermissions converts YAML's untyped map[any]any into a
// JSON-friendly shape so it survives the round-trip into Rego's input.
// String shortcuts ("write-all", "read-all") are returned as-is. Maps
// become map[string]string.
func normalizeGitHubPermissions(v any) any {
	switch p := v.(type) {
	case nil:
		return nil
	case string:
		return p
	case map[any]any:
		out := make(map[string]string, len(p))
		for k, vv := range p {
			ks, kok := k.(string)
			vs, vok := vv.(string)
			if kok && vok {
				out[ks] = vs
			}
		}
		return out
	default:
		return nil
	}
}

// parseGitHubContainer accepts both the `container: "name:tag"` shortcut
// and the `container: { image: "name:tag", ... }` long form. When the
// long form carries a `credentials.password`, the raw value (including
// `${{ secrets.X }}` templates, which stay as strings) is forwarded on
// the IR so policies can distinguish a hard-coded literal from a
// secret reference.
func parseGitHubContainer(v any) (ir.Image, bool) {
	switch c := v.(type) {
	case string:
		return splitImageRef(c), true
	case map[any]any:
		m, _ := ghCastStringMap(c)
		img, ok := m["image"].(string)
		if !ok {
			return ir.Image{}, false
		}
		out := splitImageRef(img)
		if creds, ok := ghCastStringMap(m["credentials"]); ok {
			if pw, ok := creds["password"].(string); ok {
				out.CredentialsPassword = pw
			}
		}
		return out, true
	}
	return ir.Image{}, false
}

// splitImageRef parses a GitHub Actions image reference into an ir.Image,
// folding Docker Hub registry-host aliases to docker.io.
func splitImageRef(ref string) ir.Image {
	// Fold Docker Hub registry-host aliases (registry.hub.docker.com,
	// index.docker.io, registry-1.docker.io) to docker.io so trustedUrls
	// patterns match regardless of which Hub hostname was used. GitHub refs
	// keep the registry host inside Name, so we normalise the name string.
	ref = utils.FoldDockerHubAliasInName(ref)
	// Digest form takes precedence: "alpine@sha256:..."
	if at := strings.Index(ref, "@"); at > 0 {
		return ir.Image{Name: ref[:at], Digest: ref[at+1:]}
	}
	if colon := strings.LastIndex(ref, ":"); colon > 0 {
		return ir.Image{Name: ref[:colon], Tag: ref[colon+1:]}
	}
	return ir.Image{Name: ref}
}

func ghCastStringMap(v any) (map[string]any, bool) {
	m, ok := v.(map[any]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(m))
	for k, vv := range m {
		if ks, ok := k.(string); ok {
			out[ks] = vv
		}
	}
	return out, true
}

func workflowBaseName(fileName string) string {
	if idx := strings.LastIndex(fileName, "."); idx > 0 {
		return fileName[:idx]
	}
	return fileName
}
