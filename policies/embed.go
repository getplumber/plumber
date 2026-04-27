// Package policies exposes the built-in Rego policies shipped with Plumber.
// The directory contents are embedded at build time via //go:embed. Users
// can extend or override them at runtime via --policies (Phase 2+).
package policies

import "embed"

// FS holds every .rego file at the root of the policies/ directory.
// Nested subdirectories will be picked up once the concern-based layout
// (policies/image/, policies/pipeline/, ...) is introduced in Phase 2.
//
//go:embed *.rego
var FS embed.FS
