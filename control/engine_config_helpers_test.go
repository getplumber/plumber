package control

import "github.com/getplumber/plumber/configuration"

// buildEngineConfig projects the controls for a run with no provider facts
// (GitHub, no instance URL). Test-only shorthand over buildEngineConfigForRun.
func buildEngineConfig(controls *configuration.ControlsConfig) map[string]any {
	return buildEngineConfigForRun(controls, configuration.ProviderGitHub, "")
}
