// Package opa wraps the Open Policy Agent runtime for Plumber's rule engine.
// Each policy is a Rego module evaluated against an ir.NormalizedPipeline and
// emits violations through the shared "deny" rule.
//
// This is the Phase 0 scaffold: it can load in-memory modules and return
// findings. Embedded policy discovery, user-policy overrides, and reporter
// integration land in later phases.
package opa

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/getplumber/plumber/internal/ir"
)

// Finding is a single rule violation emitted by a policy.
// File and Line, when populated, point at the exact location of the
// offending job in the source workflow/pipeline file so editors and
// terminals can render a clickable file:line link.
//
// Data carries policy-specific structured payload (variable name,
// affected image link, location, …) emitted by the Rego rule next
// to the canonical fields. It serialises inline at the top level so
// downstream consumers can read both the human message and the
// machine-parseable evidence on the same finding object.
type Finding struct {
	Code     string `json:"-"`
	Severity string `json:"-"`
	Message  string `json:"-"`
	Job      string `json:"-"`
	File     string `json:"-"`
	Line     int    `json:"-"`
	// URL is a clickable pointer to the offending file/line, populated at
	// output time (not by Rego). In CI it is the remote blob URL on the
	// host forge; locally it is the absolute filesystem path with the
	// :line suffix that VS Code / iTerm recognise as a source reference.
	// Empty when no useful link can be built (missing file/line, etc.).
	URL string `json:"-"`
	// Fingerprint is a stable, line-independent identifier for this finding,
	// stamped once by StampFingerprints so every output format carries the same
	// value and a consumer can track the same finding across runs even as line
	// numbers drift. Empty until stamped, and for codeless findings.
	Fingerprint string         `json:"-"`
	Data        map[string]any `json:"-"`
}

// MarshalJSON flattens the canonical fields and the Data payload into
// a single object so structured keys appear at the top level (the
// shape pre-Rego consumers parsed). Empty canonical fields are
// omitted, mirroring the previous `omitempty` tags.
func (f Finding) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	for k, v := range f.Data {
		out[k] = v
	}
	if f.Code != "" {
		out["code"] = f.Code
	}
	if f.Severity != "" {
		out["severity"] = f.Severity
	}
	if f.Message != "" {
		out["message"] = f.Message
	}
	if f.Job != "" {
		out["job"] = f.Job
	}
	if f.File != "" {
		out["file"] = f.File
	}
	if f.Line != 0 {
		out["line"] = f.Line
	}
	if f.URL != "" {
		out["url"] = f.URL
	}
	if f.Fingerprint != "" {
		out["fingerprint"] = f.Fingerprint
	}
	return json.Marshal(out)
}

// computeFingerprint derives a stable, line-independent identifier from a
// finding's identity: its code, file, context (job), and message. The message
// carries the concrete subject the rule flagged (the action ref, image,
// variable, ...), so the fingerprint distinguishes different findings of the
// same code in the same file/job. Line and URL are deliberately excluded
// because they move when unrelated code above the finding is edited, so the
// fingerprint survives that drift and lets a consumer follow the same finding
// across runs. Codeless findings get no fingerprint.
// fingerprintSubjectKeys lists the structured payload keys that say what a
// finding is ABOUT, in priority order; the first one present wins. Preferring
// these over the prose message is what makes the fingerprint survive a message
// rewording: the subject (an action ref, a branch, an image, a variable, a
// script line) is the thing the rule actually flagged.
//
// Volatile payload is deliberately excluded, because it changes for reasons
// unrelated to the finding and would make it look new: advisories grows as CVEs
// are published, latestVersion moves whenever upstream releases, metadata is
// refetched every run, and reasons/status track current settings rather than
// identity.
var fingerprintSubjectKeys = []string{
	"uses", "branchName", "componentName", "image", "serviceImage",
	"link", "tag", "variableName", "scriptLine", "detail",
}

// fingerprintSubject returns the finding's structured subject, falling back to
// the message for rules that emit none. The key name is included so two
// different keys holding the same value cannot collide.
func fingerprintSubject(f Finding) string {
	for _, k := range fingerprintSubjectKeys {
		if v, ok := f.Data[k].(string); ok && v != "" {
			return k + "=" + v
		}
	}
	return f.Message
}

func computeFingerprint(f Finding) string {
	if f.Code == "" {
		return ""
	}
	id := f.Code + "\n" + f.File + "\n" + f.Job + "\n" + fingerprintSubject(f)
	// A step name, when the workflow provides one, is appended as the final
	// discriminator: two steps in the same job that reference the same action
	// produce an identical code/file/job/message and would otherwise collide
	// (observed on grafana/grafana, where one action appears twice in a job).
	// Appended only when known, so findings without a step keep their
	// identifier unchanged.
	if step, ok := f.Data["step"].(string); ok && step != "" {
		id += "\n" + step
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])[:16]
}

// StampFingerprints sets Fingerprint on every finding in place. Call it once,
// after findings are finalized, so all output writers read the same value.
func StampFingerprints(findings []Finding) {
	for i := range findings {
		findings[i].Fingerprint = computeFingerprint(findings[i])
	}
}

// UnmarshalJSON splits an incoming flat object into the canonical
// fields and the Data bag. Unknown keys land in Data so they survive
// a round-trip even when added by future rules.
func (f *Finding) UnmarshalJSON(b []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["code"].(string); ok {
		f.Code = v
		delete(raw, "code")
	}
	if v, ok := raw["severity"].(string); ok {
		f.Severity = v
		delete(raw, "severity")
	}
	if v, ok := raw["message"].(string); ok {
		f.Message = v
		delete(raw, "message")
	}
	if v, ok := raw["fingerprint"].(string); ok {
		f.Fingerprint = v
		delete(raw, "fingerprint")
	}
	if v, ok := raw["job"].(string); ok {
		f.Job = v
		delete(raw, "job")
	}
	if v, ok := raw["file"].(string); ok {
		f.File = v
		delete(raw, "file")
	}
	if v, ok := raw["line"].(float64); ok {
		f.Line = int(v)
		delete(raw, "line")
	}
	if v, ok := raw["url"].(string); ok {
		f.URL = v
		delete(raw, "url")
	}
	if len(raw) > 0 {
		f.Data = raw
	}
	return nil
}

// Engine evaluates Rego policies against an IR pipeline.
type Engine struct {
	modules map[string]string
}

// New returns an Engine with no policies loaded.
func New() *Engine {
	return &Engine{modules: make(map[string]string)}
}

// LoadModule registers a Rego module under the given logical name. The name
// must match the module's package path (the "deny" rule is queried at
// data.<name>.deny).
func (e *Engine) LoadModule(name, source string) {
	e.modules[name] = source
}

// LoadFromFS loads every .rego file at the root of fsys. The module's
// logical name is the file's base name without its extension. Nested
// subdirectories are ignored for now; the concern-based layout lands
// with the first real policies in Phase 2.
func (e *Engine) LoadFromFS(fsys fs.FS) error {
	return e.LoadFromFSFiltered(fsys, nil)
}

// LoadFromFSFiltered is LoadFromFS with an optional skip predicate.
// When skip is non-nil and returns true for a (filename, content)
// pair, that file is excluded from the engine — it never executes,
// never produces findings, never costs evaluation time. Used to
// gate dev-side benched policies out of production runs without
// touching the policy files themselves.
func (e *Engine) LoadFromFSFiltered(fsys fs.FS, skip func(filename string, content []byte) bool) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("read policies dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fileName := entry.Name()
		if !strings.HasSuffix(fileName, ".rego") {
			continue
		}
		content, err := fs.ReadFile(fsys, fileName)
		if err != nil {
			return fmt.Errorf("read policy %q: %w", fileName, err)
		}
		if skip != nil && skip(fileName, content) {
			continue
		}
		e.LoadModule(strings.TrimSuffix(fileName, ".rego"), string(content))
	}
	return nil
}

// Evaluate runs every loaded policy against pipeline and returns the
// aggregated findings. Policies see a two-field input:
//
//	input.pipeline  — the NormalizedPipeline
//	input.config    — an arbitrary map forwarded from .plumber.yaml
//
// config may be nil. Pipeline must not be nil.
func (e *Engine) Evaluate(ctx context.Context, pipeline *ir.NormalizedPipeline, config map[string]any) ([]Finding, error) {
	if pipeline == nil {
		return nil, fmt.Errorf("evaluate: nil pipeline")
	}

	input, err := buildInput(pipeline, config)
	if err != nil {
		return nil, fmt.Errorf("evaluate: build input: %w", err)
	}

	names := make([]string, 0, len(e.modules))
	for name := range e.modules {
		names = append(names, name)
	}
	sort.Strings(names)

	var findings []Finding
	for _, name := range names {
		source := e.modules[name]
		moduleFindings, err := evalModule(ctx, name, source, input)
		if err != nil {
			return nil, fmt.Errorf("evaluate module %q: %w", name, err)
		}
		findings = append(findings, moduleFindings...)
	}
	enrichFindingsWithJobLocation(findings, pipeline)
	sortFindingsInPlace(findings)
	return findings, nil
}

// sortFindingsInPlace orders findings deterministically for stable JSON and CLI output.
func sortFindingsInPlace(findings []Finding) {
	slices.SortFunc(findings, compareFindings)
}

func compareFindings(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(a.Code, b.Code),
		cmp.Compare(a.Job, b.Job),
		cmp.Compare(a.File, b.File),
		cmp.Compare(a.Line, b.Line),
		cmp.Compare(a.Severity, b.Severity),
		cmp.Compare(a.Message, b.Message),
		bytes.Compare(marshalDataForSort(a.Data), marshalDataForSort(b.Data)),
	)
}

func marshalDataForSort(d map[string]any) []byte {
	if len(d) == 0 {
		return []byte("{}")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return []byte{}
	}
	return raw
}

// docURLBase is the canonical issues documentation root. Every
// finding gets a `docUrl` derived from its code so consumers (CI
// gates, dashboards, MR comments) can link back without hard-coding
// the format on their side.
const docURLBase = "https://getplumber.io/docs/cli/issues/"

// enrichFindingsWithJobLocation fills File and Line on every finding
// whose Job field matches a job in the pipeline — saves every policy
// from having to emit those fields manually. A policy may still set
// File/Line explicitly if it has a more precise location (e.g. a
// specific step line): in that case the explicit value wins. Also
// stamps `docUrl` on every finding's Data bag.
func enrichFindingsWithJobLocation(findings []Finding, pipeline *ir.NormalizedPipeline) {
	for i := range findings {
		f := &findings[i]
		if f.Code != "" {
			if f.Data == nil {
				f.Data = map[string]any{}
			}
			if _, has := f.Data["docUrl"]; !has {
				f.Data["docUrl"] = docURLBase + f.Code
			}
		}
	}
	if pipeline == nil {
		return
	}
	byName := make(map[string]*ir.Job, len(pipeline.Jobs))
	for i := range pipeline.Jobs {
		byName[pipeline.Jobs[i].Name] = &pipeline.Jobs[i]
	}
	for i := range findings {
		f := &findings[i]
		if f.Job == "" {
			continue
		}
		job, ok := byName[f.Job]
		if !ok {
			continue
		}
		// Resolve the step name for action-level findings. Rules emit the
		// action's own `uses:` line, so matching on it is exact within this
		// scan; what gets stored is the step NAME, which (unlike the line)
		// survives edits above it. Two steps in the same job referencing the
		// same action are otherwise indistinguishable, so this is what keeps
		// their fingerprints apart. Runs before the Line fallback below so a
		// job-level finding never matches an action by the job header line.
		if f.Line != 0 {
			for k := range job.Uses {
				if job.Uses[k].Line == f.Line && job.Uses[k].Name != "" {
					if f.Data == nil {
						f.Data = map[string]any{}
					}
					if _, has := f.Data["step"]; !has {
						f.Data["step"] = job.Uses[k].Name
					}
					break
				}
			}
		}
		if f.File == "" {
			f.File = job.OriginFile
		}
		if f.Line == 0 {
			f.Line = job.OriginLine
		}
	}
}

// buildInput JSON round-trips the IR so OPA sees a plain map (no Go pointers
// or tagged fields) and nests it under "pipeline" together with the caller
// config under "config".
func buildInput(pipeline *ir.NormalizedPipeline, config map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(pipeline)
	if err != nil {
		return nil, err
	}
	var pipelineMap map[string]any
	if err := json.Unmarshal(raw, &pipelineMap); err != nil {
		return nil, err
	}
	return map[string]any{
		"pipeline": pipelineMap,
		"config":   config,
	}, nil
}

func evalModule(ctx context.Context, name, source string, input map[string]any) ([]Finding, error) {
	r := rego.New(
		rego.Query(fmt.Sprintf("data.%s.deny", name)),
		rego.Module(name+".rego", source),
		rego.Input(input),
	)
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("marshal findings: %w", err)
	}
	var findings []Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("unmarshal findings: %w", err)
	}
	return findings, nil
}
