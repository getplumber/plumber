// Package capdecl holds the pipeline capability declaration schema: the types a user (or
// the CLI's own built-in list) writes a capability in, their strict decode from YAML and
// tolerant decode from JSON, the bounds that make a declared list safe to compile and to
// store, and the bounded glob matcher its patterns compile to (spec sections 4.2, 4.3 and
// 4.6 of the pipeline capabilities design, revised 2026-10-17, in the Plumber monorepo).
//
// This package is a leaf: it imports nothing from this module. The capability package
// (which recognizes capabilities over a parsed pipeline and so imports gitlab, for the
// wrapper-script read) re-exports Declaration and these functions, and keeping the schema
// in a leaf leaves it importable from anywhere in the module without a cycle
// (capability -> gitlab -> configuration).
package capdecl

import (
	"encoding/json"
	"fmt"
	"regexp"
	"unicode"

	"gopkg.in/yaml.v2"
)

// Declaration names one capability ("this job does X") and the recognizers that reveal it.
// The same shape is written in .plumber.yaml (YAML), the CLI's built-in list (YAML) and the
// org setting served through /context (JSON).
type Declaration struct {
	Name        string       `yaml:"name" json:"name"`
	Recognizers []Recognizer `yaml:"recognizers" json:"recognizers"`
}

// Recognizer is a set of pattern lists that reveal one tool. A field is provider-neutral
// (Images, Commands) or GitLab-prefixed (GitlabReportTypes, GitlabIncludeTemplate,
// GitlabIncludeComponent, GitlabIncludeProject); each is optional, but a recognizer carries
// at least one pattern across them (Validate checks this). Tool is optional; when absent the
// matched pattern names the tool on the edge (spec 4.3).
type Recognizer struct {
	Tool                   string   `yaml:"tool,omitempty" json:"tool,omitempty"`
	Images                 []string `yaml:"images,omitempty" json:"images,omitempty"`
	Commands               []string `yaml:"commands,omitempty" json:"commands,omitempty"`
	GitlabReportTypes      []string `yaml:"gitlab_report_types,omitempty" json:"gitlab_report_types,omitempty"`
	GitlabIncludeTemplate  []string `yaml:"gitlab_include_template,omitempty" json:"gitlab_include_template,omitempty"`
	GitlabIncludeComponent []string `yaml:"gitlab_include_component,omitempty" json:"gitlab_include_component,omitempty"`
	GitlabIncludeProject   []string `yaml:"gitlab_include_project,omitempty" json:"gitlab_include_project,omitempty"`
}

// yamlDocument is the wrapper .plumber.yaml and the built-in list decode: a top-level
// `capabilities:` key holding the list.
type yamlDocument struct {
	Capabilities []Declaration `yaml:"capabilities"`
}

// DecodeYAML strictly decodes a `capabilities:` YAML document (.plumber.yaml, the CLI's
// built-in list) into a declaration list. An unknown key, at any level, is refused by name
// (yaml.UnmarshalStrict), so a typo never silently disables a recognizer (spec 4.2).
func DecodeYAML(data []byte) ([]Declaration, error) {
	var doc yamlDocument
	if err := yaml.UnmarshalStrict(data, &doc); err != nil {
		return nil, err
	}
	return doc.Capabilities, nil
}

// DecodeJSON decodes a bare JSON array of declarations (the org setting, served through
// /context) into a declaration list, tolerantly: an unknown key is ignored. The platform
// refused unknown keys at PUT already, so one the CLI does not know comes from a platform
// newer than the CLI (a recognizer field added later): the CLI keeps the fields it knows
// rather than dropping the whole list (spec 4.6). The caller validates the result
// (Validate). The strict decode is DecodeYAML's, for the file a user types.
func DecodeJSON(data []byte) ([]Declaration, error) {
	var decls []Declaration
	if err := json.Unmarshal(data, &decls); err != nil {
		return nil, err
	}
	return decls, nil
}

// nameGrammar is the capability name grammar (spec 4.1): 1 to 64 bytes of lowercase
// letters, digits, underscore or hyphen.
var nameGrammar = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// Validate checks decls against the bounds of spec 4.2, in the order of the spec's
// sentences: list count, name grammar, name uniqueness, recognizer count, at least one
// pattern per recognizer, tool bounds, per-field pattern count, per-pattern bounds. It
// returns one error naming the first violation, using the fixed sentences spec 4.6 gives
// the platform's own 422 body, so the same wording reaches a user from the file or from the
// setting. It never checks glob syntax: that is Compile's business (it skips and warns).
func Validate(decls []Declaration) error {
	const (
		maxCapabilities     = 50
		maxRecognizers      = 32
		maxPatternsPerField = 64
		maxToolBytes        = 64
		minPatternBytes     = 1
		maxPatternBytes     = 256
	)

	if len(decls) > maxCapabilities {
		return fmt.Errorf("at most %d capabilities", maxCapabilities)
	}

	for _, d := range decls {
		if !nameGrammar.MatchString(d.Name) {
			return fmt.Errorf("capability %q: a capability name must be 1 to 64 bytes of lowercase letters, digits, underscore or hyphen", d.Name)
		}
	}

	seen := make(map[string]bool, len(decls))
	for _, d := range decls {
		if seen[d.Name] {
			return fmt.Errorf("capability %q: capability names must be unique", d.Name)
		}
		seen[d.Name] = true
	}

	for _, d := range decls {
		if len(d.Recognizers) > maxRecognizers {
			return fmt.Errorf("capability %q: at most %d recognizers per capability", d.Name, maxRecognizers)
		}
	}

	for _, d := range decls {
		for i, r := range d.Recognizers {
			if countPatterns(r) == 0 {
				return fmt.Errorf("capability %q: recognizer %d: a recognizer must carry at least one pattern", d.Name, i)
			}
		}
	}

	for _, d := range decls {
		for i, r := range d.Recognizers {
			if r.Tool == "" {
				continue
			}
			if !validByteString(r.Tool, 1, maxToolBytes) {
				return fmt.Errorf("capability %q: recognizer %d: tool must be 1 to %d bytes without control characters", d.Name, i, maxToolBytes)
			}
		}
	}

	for _, d := range decls {
		for i, r := range d.Recognizers {
			for _, field := range fieldsOf(r) {
				if len(field.patterns) > maxPatternsPerField {
					return fmt.Errorf("capability %q: recognizer %d: field %q: at most %d patterns per field", d.Name, i, field.name, maxPatternsPerField)
				}
			}
		}
	}

	for _, d := range decls {
		for i, r := range d.Recognizers {
			for _, field := range fieldsOf(r) {
				for _, p := range field.patterns {
					if !validByteString(p, minPatternBytes, maxPatternBytes) {
						return fmt.Errorf("capability %q: recognizer %d: field %q: pattern %q: a pattern must be 1 to %d bytes without control characters", d.Name, i, field.name, p, maxPatternBytes)
					}
				}
			}
		}
	}

	return nil
}

// PruneEmptyRecognizers drops every recognizer that carries no pattern in the fields this
// CLI knows, calling dropped with the capability's name and the recognizer's index in the
// declared list for each one. It is for the served list only, after DecodeJSON and before
// Validate (spec 4.6): a recognizer the platform accepted with only a field of a platform
// newer than this CLI (a future github_actions) decodes here with zero patterns, and
// Validate would otherwise refuse the whole org list. A capability left with no recognizer
// keeps its name, which is the disable gesture (spec 4.2). The input is not modified.
func PruneEmptyRecognizers(decls []Declaration, dropped func(capability string, index int)) []Declaration {
	out := make([]Declaration, len(decls))
	for i, d := range decls {
		kept := make([]Recognizer, 0, len(d.Recognizers))
		for j, r := range d.Recognizers {
			if countPatterns(r) == 0 {
				dropped(d.Name, j)
				continue
			}
			kept = append(kept, r)
		}
		out[i] = Declaration{Name: d.Name, Recognizers: kept}
	}
	return out
}

// countPatterns is the number of patterns a recognizer carries across every field.
func countPatterns(r Recognizer) int {
	n := 0
	for _, f := range fieldsOf(r) {
		n += len(f.patterns)
	}
	return n
}

// declaredField names one pattern field of a recognizer for an error or a warning message.
type declaredField struct {
	name     string
	patterns []string
}

// fieldsOf lists a recognizer's pattern fields in the spec's precedence order (4.3):
// images, gitlab_include_template, gitlab_include_component, gitlab_include_project,
// gitlab_report_types, commands. wrapper_script is not a field of its own: it shares the
// commands patterns (spec 4.3).
func fieldsOf(r Recognizer) []declaredField {
	return []declaredField{
		{"images", r.Images},
		{"gitlab_include_template", r.GitlabIncludeTemplate},
		{"gitlab_include_component", r.GitlabIncludeComponent},
		{"gitlab_include_project", r.GitlabIncludeProject},
		{"gitlab_report_types", r.GitlabReportTypes},
		{"commands", r.Commands},
	}
}

// validByteString reports whether s is between min and max bytes (inclusive) and holds no
// control character (unicode.IsControl), rune by rune.
func validByteString(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
