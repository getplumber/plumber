package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// The action-source scan behind actionsMustNotExecuteMutableRemoteCode
// (ISSUE-714/715) is expensive — up to ~7 sequential HTTP requests per
// unique action. shouldScanMutableExec must return true only when the
// control is actually active, so disabling it removes the scan cost and
// its environment-dependent rate-limit findings, not just the surfaced
// output (#299 review, blocker 3).
func TestShouldScanMutableExec(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	cfgWith := func(c *configuration.EnabledOnlyControlConfig) *configuration.Configuration {
		pc := &configuration.PlumberConfig{
			GitHub: &configuration.ProviderConfig{
				Controls: configuration.ControlsConfig{
					ActionsMustNotExecuteMutableRemoteCode: c,
				},
			},
		}
		return &configuration.Configuration{PlumberConfig: pc}
	}

	t.Run("enabled control scans", func(t *testing.T) {
		if !shouldScanMutableExec(cfgWith(&configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)})) {
			t.Fatal("expected scan when the control is enabled")
		}
	})

	t.Run("disabled control does not scan", func(t *testing.T) {
		if shouldScanMutableExec(cfgWith(&configuration.EnabledOnlyControlConfig{Enabled: boolPtr(false)})) {
			t.Fatal("expected no scan when the control is disabled")
		}
	})

	t.Run("absent control block does not scan", func(t *testing.T) {
		if shouldScanMutableExec(cfgWith(nil)) {
			t.Fatal("expected no scan when the control is absent from config")
		}
	})

	t.Run("nil config does not scan", func(t *testing.T) {
		if shouldScanMutableExec(nil) {
			t.Fatal("expected no scan when conf is nil")
		}
		if shouldScanMutableExec(&configuration.Configuration{}) {
			t.Fatal("expected no scan when PlumberConfig is nil")
		}
	})

	t.Run("--skip-controls excludes the control", func(t *testing.T) {
		conf := cfgWith(&configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)})
		conf.SkipControlsFilter = []string{controlMutableRemoteExec}
		if shouldScanMutableExec(conf) {
			t.Fatal("expected no scan when the control is in --skip-controls")
		}
	})

	t.Run("--controls without the control excludes it", func(t *testing.T) {
		conf := cfgWith(&configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)})
		conf.ControlsFilter = []string{"branchMustBeProtected"}
		if shouldScanMutableExec(conf) {
			t.Fatal("expected no scan when --controls omits the control")
		}
	})
}
