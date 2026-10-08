package github

import (
	"encoding/json"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
)

// maxReusableDepth bounds a chain of reusable workflow calls, past GitHub's
// own limit (four levels of nesting under the top workflow), so a cycle
// in a broken repository cannot loop.
const maxReusableDepth = 10

// inputExpr matches one `${{ inputs.NAME }}` and one
// `${{ fromJSON(inputs.NAME) }}`, any spacing.
var (
	inputExpr         = regexp.MustCompile(`\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}`)
	fromJSONInputExpr = regexp.MustCompile(`^\s*\$\{\{\s*fromJSON\(\s*inputs\.([A-Za-z0-9_-]+)\s*\)\s*\}\}\s*$`)
	secretRefExpr     = regexp.MustCompile(`^\s*\$\{\{\s*secrets\.([A-Za-z0-9_-]+)\s*\}\}\s*$`)
	// expressionOnly is a text that is one expression and nothing else: an
	// image a caller passes this way names no image, only another job's
	// output.
	expressionOnly = regexp.MustCompile(`^\s*\$\{\{[^}]*\}\}\s*$`)
)

// linkReusableCallers wires the reusable workflows of the repository to
// their calls: every job of a called workflow gets the calls that run it
// (Job.Callers, resolved up a chain of calls), every calling job the jobs
// it runs (Job.ReusableCallees) and the artifacts they upload or download,
// their inputs replaced by what the call passes, and a container built
// from an input resolves to the image each call passes (Job.MatrixImages).
// Only workflows of the repository itself are linked: a call to another
// repository's workflow has no job here.
func linkReusableCallers(jobs []ir.Job, projectPath string) {
	l := &reusableLinker{
		jobs:     jobs,
		byFile:   map[string][]int{},
		callers:  map[string][]ir.ReusableCaller{},
		visiting: map[string]bool{},
		artDone:  map[int][]ir.ArtifactRef{},
	}
	for i := range jobs {
		f := workflowFileOf(jobs[i].OriginFile)
		l.byFile[f] = append(l.byFile[f], i)
	}
	for i := range jobs {
		if f := localWorkflowFile(jobs[i].ReusableWorkflowUses, projectPath); f != "" {
			l.calls = append(l.calls, reusableCall{caller: i, file: f})
		}
	}
	if len(l.calls) == 0 {
		return
	}
	for i := range jobs {
		if !slices.Contains(jobs[i].Triggers, "workflow_call") {
			continue
		}
		jobs[i].Callers = l.callersOf(workflowFileOf(jobs[i].OriginFile), 0)
		l.resolveImages(i)
	}
	for _, c := range l.calls {
		jobs[c.caller].ReusableCallees = l.calleesOf(c.file, 0)
	}
	resolved := map[int][]ir.ArtifactRef{}
	for _, c := range l.calls {
		resolved[c.caller] = l.callArtifacts(c.caller, 0)
	}
	for i, arts := range resolved {
		jobs[i].Artifacts = append(jobs[i].Artifacts, arts...)
	}
}

type reusableCall struct {
	caller int
	file   string
}

type reusableLinker struct {
	jobs     []ir.Job
	byFile   map[string][]int
	calls    []reusableCall
	callers  map[string][]ir.ReusableCaller
	visiting map[string]bool
	artDone  map[int][]ir.ArtifactRef
}

// workflowFileOf is the workflow file a job comes from, by its base name:
// local scans record an absolute path, remote ones a repository-relative
// one, and a call names the file under .github/workflows/.
func workflowFileOf(originFile string) string {
	return path.Base(strings.ReplaceAll(originFile, "\\", "/"))
}

// localWorkflowFile is the workflow file a job-level uses: calls when it is
// a workflow of the repository itself (`./.github/workflows/x.yml`, or
// `owner/repo/.github/workflows/x.yml@ref` naming the repository), "" for
// any other reference.
func localWorkflowFile(uses, projectPath string) string {
	if uses == "" {
		return ""
	}
	ref, _, _ := strings.Cut(uses, "@")
	if rest, ok := strings.CutPrefix(ref, "./.github/workflows/"); ok {
		return rest
	}
	if projectPath != "" {
		prefix := strings.ToLower(projectPath) + "/.github/workflows/"
		if strings.HasPrefix(strings.ToLower(ref), prefix) {
			return ref[len(prefix):]
		}
	}
	return ""
}

// callersOf is every call of the workflow file, one entry per chain of
// calls when the calling job's own workflow is itself called.
func (l *reusableLinker) callersOf(file string, depth int) []ir.ReusableCaller {
	if out, ok := l.callers[file]; ok {
		return out
	}
	if depth > maxReusableDepth || l.visiting[file] {
		return nil
	}
	l.visiting[file] = true
	defer delete(l.visiting, file)
	var out []ir.ReusableCaller
	for _, c := range l.calls {
		if c.file != file {
			continue
		}
		cj := l.jobs[c.caller]
		base := ir.ReusableCaller{
			Job:            cj.Name,
			Permissions:    cj.Permissions,
			Triggers:       withoutWorkflowCall(cj.Triggers),
			SecretsInherit: cj.SecretsInherit,
			Secrets:        cj.ReusableSecrets,
			With:           cj.ReusableWith,
		}
		var ups []ir.ReusableCaller
		if slices.Contains(cj.Triggers, "workflow_call") {
			ups = l.callersOf(workflowFileOf(cj.OriginFile), depth+1)
		}
		if len(ups) == 0 {
			out = append(out, base)
			continue
		}
		for _, up := range ups {
			out = append(out, chainCall(base, up))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Job < out[j].Job })
	l.callers[file] = out
	return out
}

// chainCall is a call made from a called workflow, seen through the call
// above it: the token and the events of the top of the chain, the inputs
// and the secrets it forwards replaced by what that call passes.
func chainCall(base, up ir.ReusableCaller) ir.ReusableCaller {
	out := base
	if out.Permissions == nil {
		out.Permissions = up.Permissions
	}
	out.Triggers = sortedUnion(base.Triggers, up.Triggers)
	out.With = substituteInputsMap(base.With, up.With)
	switch {
	case base.SecretsInherit && up.SecretsInherit:
	case base.SecretsInherit:
		out.SecretsInherit, out.Secrets = false, up.Secrets
	case !up.SecretsInherit && len(base.Secrets) > 0:
		out.Secrets = map[string]string{}
		for k, v := range base.Secrets {
			if m := secretRefExpr.FindStringSubmatch(v); m != nil {
				v = up.Secrets[m[1]]
			}
			if v != "" {
				out.Secrets[k] = v
			}
		}
	}
	return out
}

// calleesOf is every job the workflow file runs: its own jobs and those of
// the workflows they call in turn, sorted.
func (l *reusableLinker) calleesOf(file string, depth int) []string {
	if depth > maxReusableDepth {
		return nil
	}
	seen := map[string]bool{}
	for _, i := range l.byFile[file] {
		seen[l.jobs[i].Name] = true
		for _, c := range l.calls {
			if c.caller == i {
				for _, n := range l.calleesOf(c.file, depth+1) {
					seen[n] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// callArtifacts is the artifacts the jobs a call runs upload or download,
// their inputs replaced by what the calling job passes, and an input the
// caller builds from its matrix by its value in each combination the
// matrix runs: in the caller's run they are the caller's own.
func (l *reusableLinker) callArtifacts(caller, depth int) []ir.ArtifactRef {
	if out, ok := l.artDone[caller]; ok {
		return out
	}
	if depth > maxReusableDepth {
		return nil
	}
	cj := l.jobs[caller]
	var out []ir.ArtifactRef
	for _, c := range l.calls {
		if c.caller != caller {
			continue
		}
		for _, i := range l.byFile[c.file] {
			arts := append([]ir.ArtifactRef{}, l.jobs[i].Artifacts...)
			arts = append(arts, l.callArtifacts(i, depth+1)...)
			for _, a := range arts {
				a.Name = substituteInputs(a.Name, cj.ReusableWith)
				a.Pattern = substituteInputs(a.Pattern, cj.ReusableWith)
				names := expandMatrixRef(a.Name, cj.MatrixCombinations)
				if len(names) == 0 {
					out = append(out, a)
					continue
				}
				for _, n := range names {
					r := a
					r.Name = n
					out = append(out, r)
				}
			}
		}
	}
	l.artDone[caller] = out
	return out
}

// resolveImages lists, for a called job whose container is built from an
// input, the image each call passes, in MatrixImages (the images the
// image controls judge in place of the reference as written).
func (l *reusableLinker) resolveImages(i int) {
	j := &l.jobs[i]
	if j.ImageRef == "" || !strings.Contains(j.ImageRef, "inputs.") || len(j.MatrixImages) > 0 {
		return
	}
	seen := map[string]bool{}
	var refs []string
	for _, c := range j.Callers {
		ref := resolveImageInput(j.ImageRef, c.With)
		if ref == "" || strings.Contains(ref, "inputs.") || seen[ref] || expressionOnly.MatchString(ref) {
			continue
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		j.MatrixImages = append(j.MatrixImages, splitImageRef(ref))
	}
}

// resolveImageInput is the image reference ref names once the call's
// inputs are in: `${{ fromJSON(inputs.x) }}` reads the image of the JSON
// container the call passes (or the JSON string), `${{ inputs.x }}` the
// text it passes. "" when the call passes nothing usable.
func resolveImageInput(ref string, with map[string]any) string {
	if m := fromJSONInputExpr.FindStringSubmatch(ref); m != nil {
		raw, ok := with[m[1]].(string)
		if !ok {
			return ""
		}
		var obj map[string]any
		if json.Unmarshal([]byte(raw), &obj) == nil {
			img, _ := obj["image"].(string)
			return img
		}
		var str string
		if json.Unmarshal([]byte(raw), &str) == nil {
			return str
		}
		return ""
	}
	out := substituteInputs(ref, with)
	if out == ref {
		return ""
	}
	return out
}

// substituteInputs replaces each `${{ inputs.x }}` of s by the scalar the
// call passes for x; an input the call does not pass stays as written.
func substituteInputs(s string, with map[string]any) string {
	if s == "" || len(with) == 0 {
		return s
	}
	return inputExpr.ReplaceAllStringFunc(s, func(m string) string {
		name := inputExpr.FindStringSubmatch(m)[1]
		if v, ok := with[name]; ok {
			if str, ok := scalarString(v); ok {
				return str
			}
		}
		return m
	})
}

func substituteInputsMap(with, up map[string]any) map[string]any {
	if len(with) == 0 {
		return with
	}
	out := make(map[string]any, len(with))
	for k, v := range with {
		if s, ok := v.(string); ok {
			out[k] = substituteInputs(s, up)
			continue
		}
		out[k] = v
	}
	return out
}

func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool, int, int64, float64:
		return ghStringify(x), true
	}
	return "", false
}

func withoutWorkflowCall(triggers []string) []string {
	var out []string
	for _, t := range triggers {
		if t != "workflow_call" {
			out = append(out, t)
		}
	}
	return out
}

func sortedUnion(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
