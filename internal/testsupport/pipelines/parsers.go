package pipelines

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/internal/ir"
)

// reservedTopLevelKeys are GitLab CI top-level keys that must not be
// interpreted as jobs by ParseGitLabCI.
var reservedTopLevelKeys = map[string]struct{}{
	"stages":        {},
	"variables":     {},
	"default":       {},
	"include":       {},
	"workflow":      {},
	"image":         {},
	"services":      {},
	"before_script": {},
	"after_script":  {},
	"cache":         {},
}

// ParseGitLabCI is a deliberately narrow parser that extracts what the rule
// and situation tests read: jobs with their image, services, variables,
// allow_failure, when, script, rules and only/except. It is the test-time
// substitute for the full collector, which depends on the GitLab API.
// Limitations: no include/extend resolution, no default propagation, no
// variable expansion. Extend as new rules require it; GitLabFromFiles is the
// production reading when a test needs everything.
func ParseGitLabCI(t *testing.T, data []byte) *ir.NormalizedPipeline {
	t.Helper()

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse yaml: %v", err)
	}

	var jobs []ir.Job
	for key, value := range raw {
		if _, reserved := reservedTopLevelKeys[key]; reserved {
			continue
		}
		section, ok := toStringMap(value)
		if !ok {
			continue
		}
		job := ir.Job{Name: key}
		if img, ok := parseImageField(section["image"]); ok {
			job.Image = &img
		}
		if svc := parseServicesField(section["services"]); len(svc) > 0 {
			job.Services = svc
		}
		if vars := parseVariablesField(section["variables"]); len(vars) > 0 {
			job.Variables = vars
			// Fixtures are user-authored .gitlab-ci.yml files: every
			// `variables:` block on a job is the project's own. Mirror
			// the production collector by exposing them as
			// LocalVariables too so policies that distinguish "user
			// wrote this" from merged-in upstream see them.
			job.LocalVariables = vars
		}
		if af, ok := section["allow_failure"].(bool); ok {
			job.AllowFailure = af
		}
		if w, ok := section["when"].(string); ok {
			job.When = w
		}
		if scripts := parseScriptsField(section["script"]); len(scripts) > 0 {
			job.Scripts = scripts
		}
		if rules := parseRulesField(section["rules"]); len(rules) > 0 {
			job.Rules = rules
		}
		if only := parseOnlyExceptField(section["only"]); len(only) > 0 {
			job.Only = only
		}
		if except := parseOnlyExceptField(section["except"]); len(except) > 0 {
			job.Except = except
		}
		jobs = append(jobs, job)
	}

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Name < jobs[j].Name })
	return &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Jobs: jobs}
}

// parseServicesField accepts the GitLab services polymorphic form: a list of
// strings or a list of {name: ...} maps.
func parseServicesField(v any) []ir.Image {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]ir.Image, 0, len(list))
	for _, item := range list {
		switch s := item.(type) {
		case string:
			out = append(out, splitNameTag(s))
		case map[any]any:
			m, _ := toStringMap(s)
			if name, ok := m["name"].(string); ok {
				out = append(out, splitNameTag(name))
			}
		}
	}
	return out
}

// parseScriptsField normalises the GitLab script: block into a list.
func parseScriptsField(v any) []string {
	switch s := v.(type) {
	case string:
		return []string{s}
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// parseVariablesField stringifies the variables map for policy consumption.
func parseVariablesField(v any) map[string]string {
	m, ok := toStringMap(v)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
			continue
		}
		out[k] = fmt.Sprintf("%v", val)
	}
	return out
}

// parseRulesField normalizes the GitLab `rules:` block into the
// []map[string]any shape ir.Job.Rules carries (each entry a raw
// {if, when, ...} map).
func parseRulesField(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		m, ok := toStringMap(item)
		if !ok {
			continue
		}
		rule := make(map[string]any, len(m))
		for k, val := range m {
			rule[k] = val
		}
		out = append(out, rule)
	}
	return out
}

// parseOnlyExceptField normalizes the GitLab legacy only:/except: block into
// a flat list of string refs, the way gitlab/gitlab_ir.go's
// extractGitLabOnlyExcept does in production: a list of strings passes
// through as-is, the map form ({refs: [...], ...}) flattens to its refs list.
func parseOnlyExceptField(v any) []string {
	if m, ok := toStringMap(v); ok {
		return parseOnlyExceptField(m["refs"])
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ParseGitHubWorkflow is the GitHub counterpart of ParseGitLabCI: workflow
// `on:` triggers and push filters propagated to every job, workflow and job
// permissions, the merged env, job-level `if:`, `container:`, step `uses:`
// with their `with:` maps, `run:` bodies, the artifacts derived from
// upload/download steps, `environment:`, `needs:` and `secrets: inherit`.
// originFile is set on every job, as the collector sets the workflow file
// path, so a test can merge several fixture files into one pipeline and
// still tell them apart. Job names stay bare (the collector namespaces them
// by workflow file; GitHubFromFiles is that reading).
func ParseGitHubWorkflow(t *testing.T, data []byte, originFile string) *ir.NormalizedPipeline {
	t.Helper()

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse yaml: %v", err)
	}

	triggers := parseOnTriggers(raw["on"])
	workflowPerms := parseGitHubPermissions(raw["permissions"])
	workflowEnv := parseGitHubEnv(raw["env"])
	pushBranches, pushBranchesIgnore, pushTags, pushTagsIgnore := parseGitHubPushFilters(raw["on"])

	jobsMap, ok := toStringMap(raw["jobs"])
	if !ok {
		t.Fatalf("workflow is missing a top-level jobs: mapping")
	}

	var jobs []ir.Job
	for name, v := range jobsMap {
		section, ok := toStringMap(v)
		if !ok {
			continue
		}
		job := ir.Job{
			Name:               name,
			Triggers:           triggers,
			OriginFile:         originFile,
			PushBranches:       pushBranches,
			PushBranchesIgnore: pushBranchesIgnore,
			PushTags:           pushTags,
			PushTagsIgnore:     pushTagsIgnore,
		}
		if img, ok := parseGitHubContainer(section["container"]); ok {
			job.Image = &img
		}
		if jobIf, ok := section["if"].(string); ok {
			job.If = jobIf
		}
		uses, scripts := parseGitHubSteps(section["steps"])
		if len(uses) > 0 {
			job.Uses = uses
			job.Artifacts = parseGitHubArtifacts(uses)
		}
		if len(scripts) > 0 {
			job.Scripts = scripts
		}
		if jobUses, ok := section["uses"].(string); ok && jobUses != "" {
			job.ReusableWorkflowUses = jobUses
		}
		// permissions: the job's own block, when present, otherwise the
		// workflow-level block it inherits. Mirrors buildJob in
		// github/github_workflows.go.
		if jobPerms, present := section["permissions"]; present {
			job.Permissions = parseGitHubPermissions(jobPerms)
		} else {
			job.Permissions = workflowPerms
		}
		job.Environment = parseGitHubEnvironment(section["environment"])
		job.Needs = parseGitHubNeeds(section["needs"])
		// variables: the merged env, workflow then job then step, later
		// entries winning on key collision. Mirrors mergedEnv in
		// github/github_workflows.go.
		if env := mergedGitHubEnv(workflowEnv, section); env != nil {
			job.Variables = env
		}
		if secretsVal, ok := section["secrets"].(string); ok && secretsVal == "inherit" {
			job.SecretsInherit = true
		}
		jobs = append(jobs, job)
	}

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Name < jobs[j].Name })
	return &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: jobs}
}

// parseGitHubPermissions normalises the `permissions:` block (the
// "write-all"/"read-all" string shortcut, or a map of scope to level) into
// the shape ir.Job.Permissions carries. Mirrors normalizeGitHubPermissions
// in github/github_workflows.go.
func parseGitHubPermissions(v any) any {
	switch p := v.(type) {
	case nil:
		return nil
	case string:
		return p
	case map[any]any:
		out := make(map[string]any, len(p))
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

// parseGitHubEnvironment normalises the two accepted `environment:` forms
// (the `environment: production` shorthand and the `environment: {name:
// production}` long form) into the job's environment name. Mirrors
// extractGitHubJobEnvironment in github/github_workflows.go.
func parseGitHubEnvironment(v any) string {
	switch env := v.(type) {
	case string:
		return env
	case map[any]any:
		if m, ok := toStringMap(env); ok {
			if name, ok := m["name"].(string); ok {
				return name
			}
		}
	}
	return ""
}

// parseGitHubNeeds normalises `needs:` (a bare job name or a list of job
// names) into the flat list ir.Job.Needs carries. Job names are not
// namespaced here, so needs entries stay bare job names and still match
// job.name: what matters is that both sides use the same convention.
func parseGitHubNeeds(v any) []string {
	switch n := v.(type) {
	case string:
		return []string{n}
	case []any:
		out := make([]string, 0, len(n))
		for _, item := range n {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// parseGitHubEnv normalises a flat `env:` map (workflow-level or job-level)
// into a string map. Mirrors normalizeGitHubEnv in
// github/github_workflows.go.
func parseGitHubEnv(v any) map[string]string {
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

// parseGitHubStepEnvs walks `jobs.<name>.steps` and merges every step's own
// `env:` block, later steps winning on key collision. Mirrors
// extractGitHubStepEnvs in github/github_workflows.go.
func parseGitHubStepEnvs(v any) map[string]string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for _, item := range list {
		step, ok := toStringMap(item)
		if !ok {
			continue
		}
		for k, val := range parseGitHubEnv(step["env"]) {
			out[k] = val
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergedGitHubEnv combines the workflow-level, job-level and step-level env
// maps into one, later entries winning on key collision (step > job >
// workflow), matching GitHub's own runtime precedence. Mirrors mergedEnv in
// github/github_workflows.go.
func mergedGitHubEnv(workflowEnv map[string]string, section map[string]any) map[string]string {
	var out map[string]string
	for _, src := range []map[string]string{
		workflowEnv,
		parseGitHubEnv(section["env"]),
		parseGitHubStepEnvs(section["steps"]),
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

// parseGitHubArtifacts derives the job's structured artifact uses from its
// actions/upload-artifact and actions/download-artifact steps. Mirrors the
// artifact half of cacheAndArtifactRefs in github/github_workflows.go
// (caches are left unparsed here; GitHubFromFiles reads them).
func parseGitHubArtifacts(uses []ir.Action) []ir.ArtifactRef {
	var out []ir.ArtifactRef
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
		switch name {
		case "actions/upload-artifact":
			artName := withStr("name")
			if artName == "" {
				artName = "artifact" // the action's documented default
			}
			out = append(out, ir.ArtifactRef{Name: artName, Mode: "produce"})
		case "actions/download-artifact":
			out = append(out, ir.ArtifactRef{Name: withStr("name"), Mode: "consume"})
		}
	}
	return out
}

// parseOnTriggers normalises the workflow `on:` section (string, list of
// strings, or map keyed by event name) into the flat event-name list
// ir.Job.Triggers carries.
func parseOnTriggers(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[any]any:
		out := make([]string, 0, len(val))
		for k := range val {
			if s, ok := k.(string); ok {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// parseGitHubPushFilters mirrors github/github_workflows.go's
// extractGitHubPushFilters: on.push.branches/branches-ignore/tags/
// tags-ignore, each a glob pattern list exactly as written, all nil when
// `on:` carries no push entry at all, when push is written as a bare
// string/list element (no filter map), or when the filter map does not
// declare that particular key.
func parseGitHubPushFilters(v any) (branches, branchesIgnore, tags, tagsIgnore []string) {
	m, ok := toStringMap(v)
	if !ok {
		return nil, nil, nil, nil
	}
	pushMap, ok := toStringMap(m["push"])
	if !ok {
		return nil, nil, nil, nil
	}
	return pushFilterList(pushMap["branches"]), pushFilterList(pushMap["branches-ignore"]), pushFilterList(pushMap["tags"]), pushFilterList(pushMap["tags-ignore"])
}

// pushFilterList mirrors github/github_workflows.go's stringOrList: a
// push filter value is either a bare string or a list of strings.
func pushFilterList(v any) []string {
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

// parseGitHubSteps walks `jobs.<name>.steps` and splits each step into
// either a `uses:` action (with its `with:` map) or a `run:` script body.
func parseGitHubSteps(v any) ([]ir.Action, []string) {
	list, ok := v.([]any)
	if !ok {
		return nil, nil
	}
	var uses []ir.Action
	var scripts []string
	for _, item := range list {
		step, ok := toStringMap(item)
		if !ok {
			continue
		}
		if u, ok := step["uses"].(string); ok && u != "" {
			uses = append(uses, ir.Action{Uses: u, With: parseWithMap(step["with"])})
			continue
		}
		if run, ok := step["run"].(string); ok && run != "" {
			scripts = append(scripts, run)
		}
	}
	return uses, scripts
}

// parseWithMap normalises a step's `with:` block into the map[string]any
// shape ir.Action.With carries.
func parseWithMap(v any) map[string]any {
	m, ok := toStringMap(v)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, val := range m {
		out[k] = val
	}
	return out
}

// parseImageField accepts both the `image: "name:tag"` shorthand and the
// `image: { name: "...", tag: "..." }` long form.
func parseImageField(v any) (ir.Image, bool) {
	switch img := v.(type) {
	case string:
		return splitNameTag(img), true
	case map[any]any:
		m, _ := toStringMap(img)
		name, _ := m["name"].(string)
		tag, _ := m["tag"].(string)
		if name == "" {
			return ir.Image{}, false
		}
		if tag == "" && strings.Contains(name, ":") {
			// Sometimes the whole reference lands in `name`.
			return splitNameTag(name), true
		}
		return ir.Image{Name: name, Tag: tag}, true
	default:
		return ir.Image{}, false
	}
}

func splitNameTag(ref string) ir.Image {
	// Digest form takes precedence: "alpine@sha256:..."
	if at := strings.Index(ref, "@"); at > 0 {
		return ir.Image{Name: ref[:at], Digest: ref[at+1:]}
	}
	if idx := strings.LastIndex(ref, ":"); idx > 0 {
		return ir.Image{Name: ref[:idx], Tag: ref[idx+1:]}
	}
	return ir.Image{Name: ref}
}

// parseGitHubContainer accepts both `container: "name:tag"` and
// `container: { image: "name:tag" }`.
func parseGitHubContainer(v any) (ir.Image, bool) {
	switch c := v.(type) {
	case string:
		return splitNameTag(c), true
	case map[any]any:
		m, _ := toStringMap(c)
		if img, ok := m["image"].(string); ok {
			return splitNameTag(img), true
		}
	}
	return ir.Image{}, false
}

// toStringMap normalizes the yaml.v2 untyped map form to map[string]any.
func toStringMap(v any) (map[string]any, bool) {
	m, ok := v.(map[any]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(m))
	for k, vv := range m {
		ks, ok := k.(string)
		if !ok {
			continue
		}
		out[ks] = vv
	}
	return out, true
}
