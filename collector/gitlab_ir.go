package collector

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
)

// overridesRegex matches CI/CD keywords that, when redefined on a job
// inherited from an include/component/template, meaningfully override
// the upstream behaviour. Kept in sync with control/utils.go.
var overridesRegex = regexp.MustCompile(`(?i)"(after_script|allow_failure|artifacts|before_script|cache|coverage|dast_configuration|dependencies|environment|identity|image|inherit|interruptible|manual_confirmation|needs|pages|parallel|release|resource_group|retry|rules|script|secrets|services|stage|tags|timeout|trigger|when)":`)

// ToNormalizedPipeline projects the GitLab collector outputs onto a
// provider-agnostic IR. Phase 1b: only the fields required by the first
// rule ported to Rego (image/mutable_tag) are mapped. Additional fields
// (services, includes, branch protection, etc.) will be filled in as
// each rule is migrated.
//
// This function is pure: no I/O, no external state. It is safe to call
// from tests with hand-built fixtures.
func ToNormalizedPipeline(
	projectPath string,
	defaultBranch string,
	ciConfigPath string,
	origin *GitlabPipelineOriginData,
	images *GitlabPipelineImageData,
	protection *GitlabProtectionAnalysisData,
) *ir.NormalizedPipeline {
	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		ProjectPath:   projectPath,
		DefaultBranch: defaultBranch,
	}

	imagesByJob := indexImagesByJob(images)
	pipeline.Jobs = buildJobs(origin, imagesByJob, ciConfigPath)
	pipeline.Includes = buildIncludes(origin)
	pipeline.Branches = buildBranches(protection)
	if origin != nil && origin.MergedConf != nil {
		if globals := extractGitLabVariables(origin.MergedConf.GlobalVariables); len(globals) > 0 {
			pipeline.GlobalVariables = globals
		}
	}
	if origin != nil && origin.Conf != nil {
		if globals := extractGitLabVariables(origin.Conf.GlobalVariables); len(globals) > 0 {
			pipeline.LocalGlobalVariables = globals
		}
	}

	return pipeline
}

// buildBranches flattens the GitLab protection API response into
// ir.Branch entries. Each repository branch is matched against the
// declared protection patterns; when a pattern matches, its settings
// are attached so policies can reason about them.
func buildBranches(protection *GitlabProtectionAnalysisData) []ir.Branch {
	if protection == nil || len(protection.Branches) == 0 {
		return nil
	}
	out := make([]ir.Branch, 0, len(protection.Branches))
	for _, name := range protection.Branches {
		branch := ir.Branch{Name: name}
		for i := range protection.BranchProtections {
			p := &protection.BranchProtections[i]
			if !gitlab.BranchMatchesPattern(p.ProtectionPattern, name) {
				continue
			}
			branch.Protected = true
			branch.ProtectionPattern = p.ProtectionPattern
			branch.AllowForcePush = p.AllowForcePush
			branch.CodeOwnerApprovalRequired = p.CodeOwnerApprovalRequired
			// GitLab serialises the access lists as arrays of role
			// entries. The scalar `MinXxxAccessLevel` field on the
			// upstream model stays zero because no API path populates
			// it; reduce the arrays to a single int — the minimum
			// access level required — so policies and consumers see
			// the effective bar v0.2.x reported.
			branch.MinPushAccessLevel = _minAccessLevel(p.PushAccessLevels)
			branch.MinMergeAccessLevel = _minAccessLevel(p.MergeAccessLevels)
			break
		}
		out = append(out, branch)
	}
	return out
}

// _minAccessLevel returns the smallest accessLevel found in the list,
// matching how GitLab itself surfaces the "minimum required level"
// for push or merge rules. Returns 0 when the list is empty.
func _minAccessLevel(levels []gitlab.BranchProtectionAccessLevel) int {
	min := 0
	for i, l := range levels {
		if i == 0 || l.AccessLevel < min {
			min = l.AccessLevel
		}
	}
	return min
}

// buildIncludes flattens pipelineOriginData.Origins into a list of
// ir.Include entries. The Ref field carries the version the project
// currently pins the include to; Current carries the upstream latest
// version resolved by the collector (or empty if no Plumber metadata
// is available for this origin). Path/AltPath expose normalized forms
// for policy-side comparison, and OverriddenJobs enumerates the jobs
// redefined locally with forbidden CI/CD keys.
func buildIncludes(origin *GitlabPipelineOriginData) []ir.Include {
	if origin == nil || len(origin.Origins) == 0 {
		return nil
	}
	out := make([]ir.Include, 0, len(origin.Origins))
	for i := range origin.Origins {
		o := &origin.Origins[i]
		inc := ir.Include{
			Kind:          o.OriginType,
			Source:        o.GitlabIncludeOrigin.Location,
			Ref:           o.Version,
			Current:       o.PlumberOrigin.LatestVersion,
			Nested:        o.Nested,
			ComponentName: o.GitlabComponent.ComponentName,
			OriginHash:    o.OriginHash,
		}
		if inc.Source == "" && o.GitlabComponent.ComponentIncludePath != "" {
			inc.Source = o.GitlabComponent.ComponentIncludePath
		}
		if inc.Current == "" && o.GitlabComponent.ComponentLatestVersion != "" {
			inc.Current = o.GitlabComponent.ComponentLatestVersion
		}
		if inc.Source != "" {
			inc.Path = utils.CleanOriginPath(inc.Source)
			// Template matching also accepts the extension-less form.
			trimmed := strings.TrimSuffix(inc.Path, ".yml")
			trimmed = strings.TrimSuffix(trimmed, ".yaml")
			if trimmed != inc.Path {
				inc.AltPath = trimmed
			}
		}
		if o.FromPlumber && o.PlumberOrigin.Path != "" && o.PlumberOrigin.Path != inc.Path {
			// Plumber-augmented templates carry an authoritative path
			// that differs from the raw GitLab include location.
			if inc.Path == "" {
				inc.Path = o.PlumberOrigin.Path
			} else if inc.AltPath == "" || inc.AltPath == inc.Path {
				inc.AltPath = o.PlumberOrigin.Path
			}
		}
		inc.OverriddenJobs = CollectOverriddenJobs(o, origin)
		out = append(out, inc)
	}
	return out
}

// CollectOverriddenJobs returns the jobs inherited from origin that were
// locally redefined with forbidden CI/CD keys. The IR uses it to expose
// override metadata to Rego policies; the PBOM generator reuses it so
// both paths share the same rule for what counts as an override.
func CollectOverriddenJobs(o *GitlabPipelineOriginDataFull, data *GitlabPipelineOriginData) []ir.OverriddenJob {
	if o == nil || data == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []ir.OverriddenJob
	for _, job := range o.Jobs {
		if !job.IsOverridden || seen[job.Name] {
			continue
		}
		seen[job.Name] = true
		keys := forbiddenOverrideKeys(data.JobHardcodedContent[job.Name])
		if len(keys) == 0 {
			continue
		}
		out = append(out, ir.OverriddenJob{Name: job.Name, Keys: keys})
	}
	return out
}

func forbiddenOverrideKeys(job interface{}) []string {
	if job == nil {
		return nil
	}
	serializable := convertOverrideSerializable(job)
	jobJSON, err := json.Marshal(serializable)
	if err != nil {
		return nil
	}
	matches := overridesRegex.FindAllSubmatch(jobJSON, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var keys []string
	for _, m := range matches {
		key := string(m[1])
		if seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
	}
	return keys
}

func convertOverrideSerializable(input interface{}) interface{} {
	switch v := input.(type) {
	case map[interface{}]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, value := range v {
			keyStr, ok := key.(string)
			if !ok {
				keyStr = fmt.Sprintf("%v", key)
			}
			result[keyStr] = convertOverrideSerializable(value)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, value := range v {
			result[key] = convertOverrideSerializable(value)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = convertOverrideSerializable(item)
		}
		return result
	default:
		return v
	}
}

func indexImagesByJob(images *GitlabPipelineImageData) map[string]ir.Image {
	if images == nil {
		return nil
	}
	out := make(map[string]ir.Image, len(images.Images))
	for _, info := range images.Images {
		out[info.Job] = imageFromInfo(info)
	}
	return out
}

func imageFromInfo(info GitlabPipelineImageInfo) ir.Image {
	// info.Link may be "registry/name:tag" or "registry/name@sha256:..."
	// info.Tag / info.Registry are already split by the collector.
	img := ir.Image{
		Name:     info.Name,
		Tag:      info.Tag,
		Registry: info.Registry,
	}
	if idx := strings.Index(info.Link, "@"); idx >= 0 {
		img.Digest = info.Link[idx+1:]
	}
	return img
}

func buildJobs(origin *GitlabPipelineOriginData, imagesByJob map[string]ir.Image, ciConfigPath string) []ir.Job {
	if origin == nil || len(origin.JobMap) == 0 {
		return nil
	}
	// The raw CI YAML carries only the root-file job headers; jobs
	// pulled in via include/component have a different source file
	// that the collector does not track per-job yet. Scanning the
	// root string at least covers hardcoded jobs, which is the main
	// class of findings users click through.
	lineByJob := scanGitLabJobLines(origin.ConfString)
	originKindByJob := indexJobOriginKind(origin)
	overrideKeysByJob := indexOverrideKeys(origin)
	jobs := make([]ir.Job, 0, len(origin.JobMap))
	for name, data := range origin.JobMap {
		if data == nil {
			continue
		}
		job := ir.Job{Name: name}
		if img, ok := imagesByJob[name]; ok {
			job.Image = &img
		}
		switch {
		case origin.JobHardcodedMap != nil && origin.JobHardcodedMap[name]:
			job.OriginKind = "hardcoded"
		case originKindByJob[name] != "":
			job.OriginKind = originKindByJob[name]
		}
		if data.IsOverridden {
			job.Overridden = true
			if keys := overrideKeysByJob[name]; len(keys) > 0 {
				job.OverriddenKeys = keys
			}
		}
		if line, ok := lineByJob[name]; ok {
			job.OriginFile = ciConfigPath
			job.OriginLine = line
		}
		enrichFromMergedConf(&job, name, origin.MergedConf)
		enrichLocalVariables(&job, name, origin.Conf)
		jobs = append(jobs, job)
	}
	// Deterministic order so the IR (and downstream findings) do not
	// depend on Go's randomized map iteration.
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Name < jobs[j].Name })
	return jobs
}

// scanGitLabJobLines returns a map from top-level job name to its
// 1-based line number in raw. Job headers are lines that start in
// column 1 with `<name>:`. Reserved GitLab keys (stages, variables,
// include, workflow, default, image, services, before_script,
// after_script, cache) are skipped. Anchors, YAML refs and nested
// jobs are not modeled — this is a lightweight hint, not a parser.
func scanGitLabJobLines(raw string) map[string]int {
	out := map[string]int{}
	if raw == "" {
		return out
	}
	reserved := map[string]struct{}{
		"stages": {}, "variables": {}, "default": {}, "include": {},
		"workflow": {}, "image": {}, "services": {}, "before_script": {},
		"after_script": {}, "cache": {},
	}
	header := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.:-]*)\s*:\s*(#.*)?$`)
	for i, line := range strings.Split(raw, "\n") {
		m := header.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if _, skip := reserved[name]; skip {
			continue
		}
		if _, seen := out[name]; seen {
			continue
		}
		out[name] = i + 1
	}
	return out
}

// indexOverrideKeys returns a map of job name -> list of CI/CD keys
// the project redefined when overriding an upstream definition.
// Reuses CollectOverriddenJobs so the IR's per-job marker stays in
// sync with the PBOM's "overriddenKeys" surface — both paths share
// one definition of "what counts as an override".
func indexOverrideKeys(origin *GitlabPipelineOriginData) map[string][]string {
	if origin == nil {
		return nil
	}
	out := make(map[string][]string)
	for i := range origin.Origins {
		o := &origin.Origins[i]
		for _, ov := range CollectOverriddenJobs(o, origin) {
			if _, seen := out[ov.Name]; seen {
				continue
			}
			out[ov.Name] = ov.Keys
		}
	}
	return out
}

// indexJobOriginKind walks origin.Origins and returns a map of job
// name -> origin type ("component", "template", "local", "remote",
// "project"). Plumber tracks how each job entered the merged config;
// rules that should not punish projects for using upstream catalogs
// (e.g. job_variable_override) consult this map to skip imported
// jobs. Hardcoded jobs are handled via JobHardcodedMap and stay
// out of this index.
func indexJobOriginKind(origin *GitlabPipelineOriginData) map[string]string {
	if origin == nil || len(origin.Origins) == 0 {
		return nil
	}
	out := make(map[string]string)
	for i := range origin.Origins {
		o := &origin.Origins[i]
		for _, job := range o.Jobs {
			if _, seen := out[job.Name]; seen {
				continue
			}
			out[job.Name] = o.OriginType
		}
	}
	return out
}

// enrichLocalVariables sets job.LocalVariables to the variables block
// authored directly in the project's CI file. Read from the raw,
// pre-merge conf so upstream-component / template-defined variables
// stay out: that distinction is what variable-override policies
// (ISSUE-205) need to avoid punishing projects for variables their
// catalogs already ship. When the project did not declare a local
// `variables:` block on this job (or did not redeclare the job at
// all), the field is left nil.
func enrichLocalVariables(job *ir.Job, name string, conf *gitlab.GitlabCIConf) {
	if conf == nil {
		return
	}
	rawJob, ok := conf.GitlabJobs[name]
	if !ok {
		return
	}
	data, err := yaml.Marshal(rawJob)
	if err != nil {
		return
	}
	var parsed gitlab.GitlabJob
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return
	}
	if vars := extractGitLabVariables(parsed.Variables); len(vars) > 0 {
		job.LocalVariables = vars
	}
}

// enrichFromMergedConf harvests the GitLab CI merged configuration to
// populate job.Services, job.Variables and job.Scripts. The merged
// conf holds each job as an opaque interface{}; we YAML-round-trip it
// into gitlab.GitlabJob so we can read the typed fields.
func enrichFromMergedConf(job *ir.Job, name string, conf *gitlab.GitlabCIConf) {
	if conf == nil {
		return
	}
	rawJob, ok := conf.GitlabJobs[name]
	if !ok {
		return
	}
	data, err := yaml.Marshal(rawJob)
	if err != nil {
		return
	}
	var parsed gitlab.GitlabJob
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return
	}
	if svc := extractGitLabServices(parsed.Services); len(svc) > 0 {
		job.Services = svc
	}
	if vars := extractGitLabVariables(parsed.Variables); len(vars) > 0 {
		job.Variables = vars
	}
	// Concatenate `before_script`, `script` and `after_script` so
	// every shell line — including hooks — is visible to scripts-
	// scanning rules. The runtime executes all three blocks in the
	// same shell context, which is also where shell-reparse and
	// variable-injection patterns live. Track the source block per
	// line so policies can echo it back in their findings.
	var scripts []string
	var blocks []string
	for _, pair := range []struct {
		name string
		raw  any
	}{
		{"before_script", parsed.BeforeScript},
		{"script", parsed.Script},
		{"after_script", parsed.AfterScript},
	} {
		for _, line := range extractGitLabScripts(pair.raw) {
			scripts = append(scripts, line)
			blocks = append(blocks, pair.name)
		}
	}
	if len(scripts) > 0 {
		job.Scripts = scripts
		job.ScriptBlocks = blocks
	}
	if af, ok := parsed.AllowFailure.(bool); ok {
		job.AllowFailure = af
	}
	if w, ok := parsed.When.(string); ok {
		job.When = w
	}
	if rules := extractGitLabRules(parsed.Rules); len(rules) > 0 {
		job.Rules = rules
	}
}

// extractGitLabRules normalises the polymorphic `rules:` block into a
// slice of {key: any} maps. yaml.v2 nests as map[interface{}]any
// while v3 uses map[string]any; convert recursively to the latter so
// the IR can be JSON-marshalled (Go's json package refuses non-string
// map keys) and policies see a single shape.
func extractGitLabRules(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, entry := range list {
		if m, ok := normalizeYAMLValue(entry).(map[string]any); ok && len(m) > 0 {
			out = append(out, m)
		}
	}
	return out
}

// normalizeYAMLValue recursively walks a value coming out of yaml.v2
// and rewrites every map[interface{}]interface{} as map[string]any
// so the result is JSON-marshallable.
func normalizeYAMLValue(v any) any {
	switch x := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]any, len(x))
		for k, val := range x {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			out[ks] = normalizeYAMLValue(val)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalizeYAMLValue(val)
		}
		return out
	case []interface{}:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = normalizeYAMLValue(item)
		}
		return out
	}
	return v
}

// extractGitLabServices normalizes the polymorphic services: block
// (list of strings, list of {name: …} maps) into a flat list of
// ir.Image entries.
func extractGitLabServices(v any) []ir.Image {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]ir.Image, 0, len(list))
	for _, item := range list {
		switch s := item.(type) {
		case string:
			out = append(out, splitServiceRef(s))
		case map[any]any:
			if name, ok := s["name"].(string); ok {
				out = append(out, splitServiceRef(name))
			}
		}
	}
	return out
}

// extractGitLabVariables collapses the YAML-typed variables map into a
// string→string map so Rego sees everything as plain strings.
func extractGitLabVariables(v map[string]any) map[string]string {
	if len(v) == 0 {
		return nil
	}
	out := make(map[string]string, len(v))
	for k, val := range v {
		out[k] = fmt.Sprintf("%v", val)
	}
	return out
}

// extractGitLabScripts flattens the polymorphic `script:` block (can
// be a single string or a list) into a list of script lines.
func extractGitLabScripts(v any) []string {
	switch s := v.(type) {
	case string:
		return []string{s}
	case []any:
		out := make([]string, 0, len(s))
		for _, line := range s {
			if str, ok := line.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func splitServiceRef(ref string) ir.Image {
	if idx := strings.LastIndex(ref, ":"); idx > 0 {
		return ir.Image{Name: ref[:idx], Tag: ref[idx+1:]}
	}
	return ir.Image{Name: ref}
}
