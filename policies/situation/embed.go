// Package situation embeds the Rego module that derives per-job situation
// facts (entry, privilege, impact) from the normalized pipeline. It is not a
// control: it emits no finding and is evaluated by Engine.EvaluateSituation,
// never by the deny loop.
package situation

import "embed"

//go:embed situation.rego
var SituationFS embed.FS

// SituationModule is the file name inside SituationFS.
const SituationModule = "situation.rego"
