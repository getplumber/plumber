package cmd

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// applyVariableControls maps the two wizard booleans onto config:
// VarsProtectedEnabled -> CicdVariablesMustBeProtected and
// VarsMaskedEnabled -> CicdVariablesMustBeMasked. A field mix-up would silently
// produce a wrong .plumber.yaml from `plumber config init`, and no drift guard
// catches it (both controls ship disabled). This pins the mapping.
func TestApplyVariableControls_Mapping(t *testing.T) {
	t.Run("protected only sets only the protected control", func(t *testing.T) {
		gl := &configuration.ProviderConfig{}
		(&initWizardState{VarsProtectedEnabled: true}).applyVariableControls(gl)
		if gl.Controls.CicdVariablesMustBeProtected == nil || !gl.Controls.CicdVariablesMustBeProtected.IsEnabled() {
			t.Fatal("protected control should be enabled")
		}
		if gl.Controls.CicdVariablesMustBeMasked != nil {
			t.Fatal("masked control must stay unset when only protected was chosen (field mix-up)")
		}
	})
	t.Run("masked only sets only the masked control", func(t *testing.T) {
		gl := &configuration.ProviderConfig{}
		(&initWizardState{VarsMaskedEnabled: true}).applyVariableControls(gl)
		if gl.Controls.CicdVariablesMustBeMasked == nil || !gl.Controls.CicdVariablesMustBeMasked.IsEnabled() {
			t.Fatal("masked control should be enabled")
		}
		if gl.Controls.CicdVariablesMustBeProtected != nil {
			t.Fatal("protected control must stay unset when only masked was chosen (field mix-up)")
		}
	})
	t.Run("neither sets nothing", func(t *testing.T) {
		gl := &configuration.ProviderConfig{}
		(&initWizardState{}).applyVariableControls(gl)
		if gl.Controls.CicdVariablesMustBeProtected != nil || gl.Controls.CicdVariablesMustBeMasked != nil {
			t.Fatal("no variable controls should be set when neither was chosen")
		}
	})
}
