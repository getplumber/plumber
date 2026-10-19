package capability

import "github.com/getplumber/plumber/capability/capdecl"

// Declaration re-exports capdecl.Declaration: the type a user capability, or the CLI's own
// built-in one, is written in (spec 4.2). It is declared here as a type alias, not a new
// type, so capability.Declaration and capdecl.Declaration stay interchangeable. The schema
// lives in the leaf package capdecl because capability imports gitlab (for the
// wrapper-script read of recognize.go) and gitlab imports configuration: a schema here could
// never be named by configuration. configuration keeps the .plumber.yaml key raw
// (PlumberConfig.Capabilities) and the provider decodes it through DecodeYAML below.
//
// The declaration's Recognizer type is not re-exported: code in this package that names it
// explicitly (rather than through a Declaration's Recognizers field) spells it out as
// capdecl.Recognizer, and the compiled form a matcher reads is CompiledRecognizer.
type Declaration = capdecl.Declaration

// Validate re-exports capdecl.Validate: the bounds of spec 4.2 (list count, name grammar,
// uniqueness, recognizer count, at least one pattern, tool bytes, per-field pattern count,
// per-pattern bytes), returning one error naming the first violation. It never checks glob
// syntax: that is Compile's business (it skips and warns).
func Validate(decls []Declaration) error { return capdecl.Validate(decls) }

// DecodeYAML re-exports capdecl.DecodeYAML: a strict decode of a `capabilities:` YAML
// document (.plumber.yaml, the CLI's built-in list), refusing an unknown key by name.
func DecodeYAML(data []byte) ([]Declaration, error) { return capdecl.DecodeYAML(data) }

// DecodeJSON re-exports capdecl.DecodeJSON: a tolerant decode of a bare JSON array of
// declarations (the org setting, served through /context), ignoring an unknown key so a
// field a newer platform serves never drops the fields the CLI knows (spec 4.6).
func DecodeJSON(data []byte) ([]Declaration, error) { return capdecl.DecodeJSON(data) }

// PruneEmptyRecognizers re-exports capdecl.PruneEmptyRecognizers: for the served list, after
// DecodeJSON and before Validate, it drops every recognizer with no pattern in the fields
// this CLI knows (one that only carried a field of a newer platform), reporting each through
// dropped; a capability left with none keeps its name (spec 4.2 and 4.6).
func PruneEmptyRecognizers(decls []Declaration, dropped func(capability string, index int)) []Declaration {
	return capdecl.PruneEmptyRecognizers(decls, dropped)
}
