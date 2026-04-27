// Package opa wraps the Open Policy Agent runtime for Plumber's rule engine.
// Each policy is a Rego module evaluated against an ir.NormalizedPipeline and
// emits violations through the shared "deny" rule.
//
// This is the Phase 0 scaffold: it can load in-memory modules and return
// findings. Embedded policy discovery, user-policy overrides, and reporter
// integration land in later phases.
package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
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
	Code     string         `json:"-"`
	Severity string         `json:"-"`
	Message  string         `json:"-"`
	Job      string         `json:"-"`
	File     string         `json:"-"`
	Line     int            `json:"-"`
	Data     map[string]any `json:"-"`
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
	return json.Marshal(out)
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

	var findings []Finding
	for name, source := range e.modules {
		moduleFindings, err := evalModule(ctx, name, source, input)
		if err != nil {
			return nil, fmt.Errorf("evaluate module %q: %w", name, err)
		}
		findings = append(findings, moduleFindings...)
	}
	enrichFindingsWithJobLocation(findings, pipeline)
	return findings, nil
}

// docURLBase is the canonical issues documentation root. Every
// finding gets a `docUrl` derived from its code so consumers (CI
// gates, dashboards, MR comments) can link back without hard-coding
// the format on their side.
const docURLBase = "https://getplumber.io/docs/use-plumber/issues/"

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
