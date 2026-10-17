package capability

import "github.com/getplumber/plumber/capability/capdecl"

// Declaration re-exports capdecl.Declaration: the type a user capability, or the CLI's own
// built-in one, is written in (spec 4.2). It is declared here as a type alias, not a new
// type, because configuration/plumberconfig.go needs the exact same type on
// PlumberConfig.Capabilities without importing this package: capability imports gitlab (for
// the wrapper-script read of recognize.go) and gitlab imports configuration, so
// configuration importing capability would cycle. configuration imports capdecl directly
// instead; the alias here keeps capability.Declaration and capdecl.Declaration
// interchangeable for every other caller.
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

// DecodeJSON re-exports capdecl.DecodeJSON: a strict decode of a bare JSON array of
// declarations (the org setting, served through /context), refusing an unknown key by name.
func DecodeJSON(data []byte) ([]Declaration, error) { return capdecl.DecodeJSON(data) }
