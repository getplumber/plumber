package capability

import (
	_ "embed"

	"github.com/getplumber/plumber/capability/capdecl"
)

// builtinYAML is the CLI's built-in capability list, in the schema of spec 4.2: the only
// built-in in this version is secret_detection, with the tools and sources verified at
// implementation time (spec 4.2). It is printed verbatim by `plumber capabilities defaults`
// so a user can copy and narrow it.
//
//go:embed builtin.yaml
var builtinYAML []byte

// BuiltinYAML returns the embedded builtin.yaml bytes, copied so a caller can never alter
// the list the CLI runs: what `plumber capabilities defaults` prints verbatim (spec 4.2).
func BuiltinYAML() []byte {
	return append([]byte(nil), builtinYAML...)
}

// Builtin returns the CLI's built-in capability list, decoded once and deep-copied on every
// call so a caller mutating the result never affects another caller or a later call (spec
// 4.2). It panics if the embedded builtin.yaml fails to decode: that can only happen if a
// change to builtin.yaml breaks its own schema, a build-time bug this test suite catches
// before it ships.
func Builtin() []Declaration {
	decls, err := DecodeYAML(builtinYAML)
	if err != nil {
		panic("capability: embedded builtin.yaml does not decode: " + err.Error())
	}
	return cloneDeclarations(decls)
}

// cloneDeclarations deep-copies decls so none of its backing arrays are shared with the
// caller. The recognizer type is named through capdecl (see declaration.go).
func cloneDeclarations(decls []capdecl.Declaration) []capdecl.Declaration {
	out := make([]capdecl.Declaration, len(decls))
	for i, d := range decls {
		out[i] = capdecl.Declaration{Name: d.Name, Recognizers: cloneRecognizers(d.Recognizers)}
	}
	return out
}

// cloneRecognizers deep-copies recs so none of its backing arrays are shared with the
// caller.
func cloneRecognizers(recs []capdecl.Recognizer) []capdecl.Recognizer {
	out := make([]capdecl.Recognizer, len(recs))
	for i, r := range recs {
		out[i] = capdecl.Recognizer{
			Tool:                   r.Tool,
			Images:                 append([]string(nil), r.Images...),
			Commands:               append([]string(nil), r.Commands...),
			GitlabReportTypes:      append([]string(nil), r.GitlabReportTypes...),
			GitlabIncludeTemplate:  append([]string(nil), r.GitlabIncludeTemplate...),
			GitlabIncludeComponent: append([]string(nil), r.GitlabIncludeComponent...),
			GitlabIncludeProject:   append([]string(nil), r.GitlabIncludeProject...),
		}
	}
	return out
}
