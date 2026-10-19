package capability

import (
	"fmt"

	"github.com/getplumber/plumber/capability/capdecl"
)

// Compiled is one declaration ready for matching: its name and its recognizers, compiled.
type Compiled struct {
	Name        string
	Recognizers []CompiledRecognizer
}

// CompiledRecognizer is one compiled recognizer: the declared tool (empty when the
// recognizer did not name one, in which case the matched pattern names the tool on the edge,
// spec 4.3) and its seven evidence fields, in the precedence order a matcher tries them in
// (spec 4.3): images, gitlab_include_template, gitlab_include_component,
// gitlab_include_project, gitlab_report_types, commands, wrapper_script.
type CompiledRecognizer struct {
	Tool   string
	Fields [7]CompiledField
}

// CompiledField is one evidence field of a compiled recognizer: its name (the bill's
// evidence vocabulary, spec 4.4) and its patterns. A pattern that failed to compile as a
// glob is never here: Compile already skipped it and warned once.
type CompiledField struct {
	Name     string
	Patterns []CompiledPattern
}

// CompiledPattern is one glob pattern, compiled, with its source text kept: the tool
// fallback needs it (spec 4.3, "the recognizer's tool when declared, else the pattern that
// matched") and so does a later warning that names the pattern. The matcher is
// capdecl.Glob, bounded by len(subject) * len(pattern) whatever the pattern.
type CompiledPattern struct {
	Source string
	Glob   *capdecl.Glob
}

// Compile compiles decls' patterns to capdecl.Glob, keeping the source text of each. A pattern
// that does not compile as a plain glob is skipped and, when warn is not nil, reported once
// through warn naming the capability, the recognizer's tool (or its declared order when the
// recognizer named no tool), the field and the pattern (spec 4.3: "a pattern that does not
// compile is refused at PUT and, from .plumber.yaml, skipped with one warning line").
// wrapper_script is not a declared field: its patterns are the recognizer's compiled
// commands, since spec 4.3 matches a wrapper script's lines against the recognizer's
// commands, not against a field of its own.
func Compile(decls []Declaration, warn func(string)) []Compiled {
	out := make([]Compiled, 0, len(decls))
	for _, d := range decls {
		c := Compiled{Name: d.Name}
		for _, r := range d.Recognizers {
			commands := compileField(d.Name, r.Tool, EvidenceCommands, r.Commands, warn)
			cr := CompiledRecognizer{
				Tool: r.Tool,
				Fields: [7]CompiledField{
					compileField(d.Name, r.Tool, EvidenceImages, r.Images, warn),
					compileField(d.Name, r.Tool, EvidenceGitlabIncludeTemplate, r.GitlabIncludeTemplate, warn),
					compileField(d.Name, r.Tool, EvidenceGitlabIncludeComponent, r.GitlabIncludeComponent, warn),
					compileField(d.Name, r.Tool, EvidenceGitlabIncludeProject, r.GitlabIncludeProject, warn),
					compileField(d.Name, r.Tool, EvidenceGitlabReportTypes, r.GitlabReportTypes, warn),
					commands,
					{Name: EvidenceWrapperScript, Patterns: commands.Patterns},
				},
			}
			c.Recognizers = append(c.Recognizers, cr)
		}
		out = append(out, c)
	}
	return out
}

// compileField compiles one recognizer field's patterns, skipping and warning about any
// that does not compile as a glob.
func compileField(capName, tool, field string, patterns []string, warn func(string)) CompiledField {
	cf := CompiledField{Name: field}
	for _, p := range patterns {
		g, err := capdecl.CompileGlob(p)
		if err != nil {
			if warn != nil {
				warn(fmt.Sprintf("capability %q: recognizer %q: field %q: pattern %q does not compile as a glob, skipped: %v", capName, tool, field, p, err))
			}
			continue
		}
		cf.Patterns = append(cf.Patterns, CompiledPattern{Source: p, Glob: g})
	}
	return cf
}
