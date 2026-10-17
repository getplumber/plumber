// Package lib embeds the Rego library every policy module is compiled with
// (monorepo spec 2026-10-16 section 5: one shared provenance helper). A
// library module emits no finding and is never queried.
package lib

import "embed"

//go:embed *.rego
var FS embed.FS
