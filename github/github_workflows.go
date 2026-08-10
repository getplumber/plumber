package github

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/internal/ir"
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
// Dockerfiles) that do not depend on that directory. Individual
// unreadable or unparseable files land in partialErrors so the caller
// can surface them without aborting the whole scan.
func collectWorkflowJobs(rootDir string) (jobs []ir.Job, partialErrors []error, err error) {
	dir, ok := resolveWithinRoot(rootDir, githubWorkflowsSubdir)
	if !ok {
		return nil, nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf(fmtReadErr, dir, err)
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
		fileJobs, parseErr := parseGitHubWorkflowJobs(data, workflowBaseName(name), path)
		if parseErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf(fmtFileErr, name, parseErr))
			continue
		}
		jobs = append(jobs, fileJobs...)
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].Name < jobs[j].Name
	})
	return jobs, partialErrors, nil
}

// ScanGitHubWorkflowsWithProgress reads every .yml/.yaml file under
// <rootDir>/.github/workflows/ and aggregates them into a single
// NormalizedPipeline. Job names are namespaced by the workflow file base
// name ("ci/lint", "release/build", ...) so two workflows can expose
// identically-named jobs without clashing in the IR.
//
// A missing workflows directory is not an error: the returned pipeline
// simply carries no jobs. Individual unreadable or unparseable files are
// returned in partialErrors so the caller can surface them without
// aborting the whole scan.
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
	jobs, partialErrors, err := collectWorkflowJobs(rootDir)
	if err != nil {
		return nil, nil, err
	}
	pipeline.Jobs = jobs
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
		enrichActionsWithAPIMetadata(pipeline, apiHost, scanMutableExec, wrapProgress(progressFn, total))
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
// inner counter from enrichActionsWithAPIMetadata is offset by
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

// enrichActionsWithAPIMetadata walks every job's steps[].uses and
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
func enrichActionsWithAPIMetadata(pipeline *ir.NormalizedPipeline, apiHost string, scanMutableExec bool, progressFn ProgressFunc) {
	enrichActionsWithClient(pipeline, NewGitHubMetadataClientForHost(apiHost), scanMutableExec, progressFn)
}

// enrichActionsWithClient is enrichActionsWithAPIMetadata with the
// metadata client supplied rather than constructed, so tests can drive
// the collector-to-IR handoff through a stubbed transport. Every field
// the policies read crosses from GitHubMetadata into ir.ActionMetadata
// here, and a field dropped in that copy silently disables the rule
// that consumes it while every other test stays green.
func enrichActionsWithClient(pipeline *ir.NormalizedPipeline, client *GitHubMetadataClient, scanMutableExec bool, progressFn ProgressFunc) {
	if !client.Available() {
		return
	}
	// Pre-count unique refs for accurate N/total ratios.
	uniqueRefs := map[string]struct{}{}
	for i := range pipeline.Jobs {
		for k := range pipeline.Jobs[i].Uses {
			uniqueRefs[pipeline.Jobs[i].Uses[k].Uses] = struct{}{}
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
			if _, already := seen[action.Uses]; !already {
				done++
				seen[action.Uses] = struct{}{}
				report(progressFn, done, total, fmt.Sprintf("Resolving action %s", action.Uses))
			}
			meta := client.Resolve(action.Uses)
			var mre *ir.MutableRemoteExec
			if scanMutableExec {
				mre = resolveMutableExec(action.Uses, mreCache)
			}
			if isZeroMetadata(meta) && action.Comment == "" && mre == nil {
				continue
			}
			amd := &ir.ActionMetadata{
				RepoArchived:      meta.RepoArchived,
				RefExists:         meta.RefExists,
				RefKnownAbsent:    meta.RefKnownAbsent,
				RefKind:           meta.RefKind,
				RefCommitSha:      meta.RefCommitSha,
				TagSha:            meta.TagSha,
				LatestTag:         meta.LatestTag,
				LatestReleaseSha:  meta.LatestReleaseSha,
				RefIsAmbiguous:    meta.RefIsAmbiguous,
				Advisories:        meta.Advisories,
				StargazersCount:   meta.StargazersCount,
				MutableRemoteExec: mre,
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
	pipeline.AdvisoryWarnings = client.DegradedChecks()
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
	perms          any
	env            map[string]string
	triggers       []string
	name           string
	hasConcurrency bool
	jobLines       map[string]int
	usesLines      map[string][]int
	usesComments   map[string]string
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

// buildJob converts one raw YAML job section into an ir.Job.
func buildJob(jobName string, section map[string]any, wfCtx workflowContext, namespace, originFile string) ir.Job {
	job := ir.Job{
		Name:                   namespace + "/" + jobName,
		OriginFile:             originFile,
		OriginLine:             wfCtx.jobLines[jobName],
		Triggers:               wfCtx.triggers,
		WorkflowName:           wfCtx.name,
		WorkflowHasConcurrency: wfCtx.hasConcurrency,
	}
	if _, ok := section["concurrency"]; ok {
		job.JobHasConcurrency = true
	}
	// continue-on-error: true maps to allowFailure. Only literal booleans
	// are honoured — runtime expressions are unpredictable statically.
	if v, ok := section["continue-on-error"].(bool); ok && v {
		job.AllowFailure = true
	}
	if img, ok := parseGitHubContainer(section["container"]); ok {
		job.Image = &img
	}
	if jobPerms, present := section["permissions"]; present {
		job.Permissions = normalizeGitHubPermissions(jobPerms)
	} else if wfCtx.perms != nil {
		job.Permissions = normalizeGitHubPermissions(wfCtx.perms)
	}
	if scripts := extractGitHubRunScripts(section["steps"]); len(scripts) > 0 {
		job.Scripts = scripts
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
	}
	if conds := collectGitHubJobConditions(section); len(conds) > 0 {
		job.Conditions = conds
	}
	if env := extractGitHubJobEnvironment(section["environment"]); env != "" {
		job.Environment = env
	}
	return job
}

func parseGitHubWorkflowJobs(data []byte, namespace, originFile string) ([]ir.Job, error) {
	var wf ghWorkflowHeader
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if len(wf.Jobs) == 0 {
		return nil, nil
	}

	wfCtx := workflowContext{
		perms:          wf.Permissions,
		env:            normalizeGitHubEnv(wf.Env),
		triggers:       extractGitHubTriggers(wf.On),
		name:           wf.Name,
		hasConcurrency: wf.Concurrency != nil,
		jobLines:       scanGitHubJobLines(data),
		usesLines:      scanGitHubUsesLines(data),
		usesComments:   scanGitHubUsesComments(data),
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
// the workflow file. Empty `run:` blocks are dropped.
func extractGitHubRunScripts(v any) []string {
	stepsList, ok := v.([]any)
	if !ok {
		return nil
	}
	scripts := make([]string, 0, len(stepsList))
	for _, s := range stepsList {
		stepMap, ok := ghCastStringMap(s)
		if !ok {
			continue
		}
		if run, ok := stepMap["run"].(string); ok && run != "" {
			scripts = append(scripts, run)
		}
	}
	return scripts
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
