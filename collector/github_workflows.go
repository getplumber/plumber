package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/internal/ir"
)

const githubWorkflowsSubdir = ".github/workflows"

// ScanGitHubWorkflows reads every .yml/.yaml file under
// <rootDir>/.github/workflows/ and aggregates them into a single
// NormalizedPipeline. Job names are namespaced by the workflow file base
// name ("ci/lint", "release/build", ...) so two workflows can expose
// identically-named jobs without clashing in the IR.
//
// A missing workflows directory is not an error: the returned pipeline
// simply carries no jobs. Individual unreadable or unparseable files are
// returned in partialErrors so the caller can surface them without
// aborting the whole scan.
func ScanGitHubWorkflows(projectPath, defaultBranch, rootDir, apiHost string, enrichActionMetadata bool) (pipeline *ir.NormalizedPipeline, partialErrors []error, err error) {
	pipeline = &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		ProjectPath:   projectPath,
		DefaultBranch: defaultBranch,
	}

	dir := filepath.Join(rootDir, githubWorkflowsSubdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return pipeline, nil, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf("%s: %w", name, readErr))
			continue
		}
		jobs, parseErr := parseGitHubWorkflowJobs(data, workflowBaseName(name), path)
		if parseErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf("%s: %w", name, parseErr))
			continue
		}
		pipeline.Jobs = append(pipeline.Jobs, jobs...)
	}

	sort.Slice(pipeline.Jobs, func(i, j int) bool {
		return pipeline.Jobs[i].Name < pipeline.Jobs[j].Name
	})
	if dcfg, derr := scanDependabotConfig(rootDir); derr != nil {
		partialErrors = append(partialErrors, derr)
	} else if dcfg != nil {
		pipeline.Dependabot = dcfg
	}
	pipeline.RenovateConfigPath = scanRenovateConfig(rootDir)
	pipeline.SecurityPolicyPath = scanSecurityPolicy(rootDir)
	pipeline.Dockerfiles = scanDockerfiles(rootDir)
	// Enrich actions with GitHub API metadata (archived repo, ref
	// kind, tag SHA). Best-effort: if gh is not authenticated, the
	// client operates in degraded mode and leaves metadata empty.
	if enrichActionMetadata {
		enrichActionsWithAPIMetadata(pipeline, apiHost, nil)
	}
	return pipeline, partialErrors, nil
}

// ScanGitHubWorkflowsWithProgress mirrors ScanGitHubWorkflows but
// notifies the caller through progressFn as it works. The progress
// total is sized so the bar advances monotonically end-to-end:
//
//	step 1                 Scanning workflow files
//	step 2..(1+N)          Resolving action <n>      (N unique refs)
//	step 2+N               Scan complete
//
// The last step (policy evaluation) is reported by the caller
// (RunGitHubAnalysis) using the same total so the bar keeps
// climbing. progressFn may be nil; callers that don't care about
// progress should call the plain ScanGitHubWorkflows variant.
func ScanGitHubWorkflowsWithProgress(projectPath, defaultBranch, rootDir, apiHost string, enrichActionMetadata bool, progressFn ProgressFunc) (pipeline *ir.NormalizedPipeline, partialErrors []error, err error) {
	pipeline = &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		ProjectPath:   projectPath,
		DefaultBranch: defaultBranch,
	}
	dir := filepath.Join(rootDir, githubWorkflowsSubdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return pipeline, nil, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf("%s: %w", name, readErr))
			continue
		}
		jobs, parseErr := parseGitHubWorkflowJobs(data, workflowBaseName(name), path)
		if parseErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf("%s: %w", name, parseErr))
			continue
		}
		pipeline.Jobs = append(pipeline.Jobs, jobs...)
	}
	sort.Slice(pipeline.Jobs, func(i, j int) bool {
		return pipeline.Jobs[i].Name < pipeline.Jobs[j].Name
	})
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
		enrichActionsWithAPIMetadata(pipeline, apiHost, wrapProgress(progressFn, total))
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

// TotalProgressStepsForPipeline returns the grand total the caller
// (RunGitHubAnalysis) should use when emitting its own progress
// update for the policy-evaluation phase, so it keeps the bar in
// sync with what the collector reported.
func TotalProgressStepsForPipeline(pipeline *ir.NormalizedPipeline) int {
	if pipeline == nil {
		return 3
	}
	return countUniqueActionRefs(pipeline) + 3
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
func enrichActionsWithAPIMetadata(pipeline *ir.NormalizedPipeline, apiHost string, progressFn ProgressFunc) {
	client := NewGitHubMetadataClientForHost(apiHost)
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
			if isZeroMetadata(meta) && action.Comment == "" {
				continue
			}
			amd := &ir.ActionMetadata{
				RepoArchived:     meta.RepoArchived,
				RefExists:        meta.RefExists,
				RefKind:          meta.RefKind,
				TagSha:           meta.TagSha,
				LatestTag:        meta.LatestTag,
				LatestReleaseSha: meta.LatestReleaseSha,
				RefIsAmbiguous:   meta.RefIsAmbiguous,
				Advisories:       meta.Advisories,
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
		path := filepath.Join(rootDir, ".github", name)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", path, err)
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
	Jobs        map[string]any `yaml:"jobs"`
}

// parseGitHubWorkflowJobs extracts jobs.<name>.container, workflow-level
// permissions, and workflow triggers from a single workflow file. Jobs
// are emitted with a namespaced name (e.g. "ci/lint") and OriginFile
// set to the absolute workflow path. Workflow-level `permissions:` are
// propagated to every job that does not override them; `on:` triggers
// are propagated uniformly so trigger-focused policies can see them at
// the job level.
func parseGitHubWorkflowJobs(data []byte, namespace, originFile string) ([]ir.Job, error) {
	var wf ghWorkflowHeader
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if len(wf.Jobs) == 0 {
		return nil, nil
	}

	workflowPerms := normalizeGitHubPermissions(wf.Permissions)
	triggers := extractGitHubTriggers(wf.On)
	jobLines := scanGitHubJobLines(data)
	usesLines := scanGitHubUsesLines(data)
	usesComments := scanGitHubUsesComments(data)
	workflowHasConcurrency := wf.Concurrency != nil

	jobs := make([]ir.Job, 0, len(wf.Jobs))
	for jobName, v := range wf.Jobs {
		section, ok := ghCastStringMap(v)
		if !ok {
			continue
		}
		job := ir.Job{
			Name:                   namespace + "/" + jobName,
			OriginFile:             originFile,
			OriginLine:             jobLines[jobName],
			Triggers:               triggers,
			WorkflowName:           wf.Name,
			WorkflowHasConcurrency: workflowHasConcurrency,
		}
		if _, hasJobConcurrency := section["concurrency"]; hasJobConcurrency {
			job.JobHasConcurrency = true
		}
		// `continue-on-error: true` at the job level is GitHub's
		// equivalent of GitLab's `allow_failure: true`: the workflow
		// reports green even if the job's exit code is non-zero. The
		// security_jobs_weakened rego rule reads job.allowFailure
		// without a provider distinction, so map directly. Only the
		// literal boolean is honoured — a `${{ matrix.experimental
		// }}` expression evaluates at runtime and we cannot say
		// statically whether it weakens the job, so we stay quiet.
		if v, ok := section["continue-on-error"].(bool); ok && v {
			job.AllowFailure = true
		}
		if img, ok := parseGitHubContainer(section["container"]); ok {
			job.Image = &img
		}
		if jobPerms, present := section["permissions"]; present {
			job.Permissions = normalizeGitHubPermissions(jobPerms)
		} else if workflowPerms != nil {
			job.Permissions = workflowPerms
		}
		if scripts := extractGitHubRunScripts(section["steps"]); len(scripts) > 0 {
			job.Scripts = scripts
		}
		// Aggregate job-level `env:` with every step-level `env:` into
		// a single Variables map. The semantics differ at runtime
		// (step-level envs only apply to their own step), but the
		// rego policies pattern-match over template expressions in
		// value strings — not over runtime scope — so folding them
		// together gives a complete surface to scan. Later entries
		// overwrite earlier ones on collisions; that is acceptable
		// because the patterns we look for are present or absent
		// regardless of which binding wins the collision.
		envVars := normalizeGitHubEnv(section["env"])
		for k, v := range extractGitHubStepEnvs(section["steps"]) {
			if envVars == nil {
				envVars = map[string]string{}
			}
			envVars[k] = v
		}
		if envVars != nil {
			job.Variables = envVars
		}
		if uses := extractGitHubUses(section["steps"]); len(uses) > 0 {
			jobUsesLines := usesLines[jobName]
			for k := range uses {
				if c, ok := usesComments[uses[k].Uses]; ok {
					uses[k].Comment = c
				}
				if k < len(jobUsesLines) {
					uses[k].Line = jobUsesLines[k]
				}
			}
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
		jobs = append(jobs, job)
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
// ref-version-mismatch (ISSUE-110): a `@<sha> # v4.1.0` comment
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
// ISSUE-104/110/111/114 where the reviewer needs the exact step, not
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

func splitImageRef(ref string) ir.Image {
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
