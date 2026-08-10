// Package defaultconfig embeds the shipped default Plumber configuration,
// the baseline every zero-config user gets.
//
// This file lives beside the YAML it embeds because //go:embed cannot reach
// outside its own package directory, and embedding the source in place is
// what keeps the module self-contained. The previous arrangement generated a
// copy into internal/defaultconfig/ with a cp step in every build path and
// git-ignored the result, so the file was absent from the published module
// zip and `go install` failed for every consumer while every build path here
// stayed green (getplumber/plumber#405).
//
// The source is defaultConfig/.plumber.yaml, NOT the repo-root .plumber.yaml
// (which is Plumber's own self-scan config). The two are independent
// artifacts (getplumber/plumber#352): editing Plumber's self-scan config
// never silently changes the shipped default.
package defaultconfig

import _ "embed"

//go:embed .plumber.yaml
var config []byte

// Get returns the embedded default configuration as a byte slice.
// The returned slice is shared across all callers and must not be modified,
// to avoid corrupting the embedded default for the rest of the process.
func Get() []byte {
	return config
}
