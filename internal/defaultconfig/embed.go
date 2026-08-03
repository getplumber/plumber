package defaultconfig

import (
	_ "embed"
)

// Config contains the embedded default configuration shipped in the binary —
// the baseline every zero-config user gets. The file is a verbatim copy of
// defaultConfig/.plumber.yaml, generated into place by a `cp` step in every
// build path (the Makefile `embed` target, the CI/release workflows, and the
// Dockerfile) immediately before `go build`. It is git-ignored.
//
// The source is defaultConfig/.plumber.yaml, NOT the repo-root .plumber.yaml
// (which is Plumber's own self-scan config). The two are independent artifacts
// (getplumber/plumber#352): editing Plumber's self-scan config never silently
// changes the shipped default.
//
//go:embed default.yaml
var Config []byte

// Get returns the embedded default configuration as a byte slice.
func Get() []byte {
	return Config
}
