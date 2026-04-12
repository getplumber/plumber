package cmd

import (
	"testing"
)

func TestStarterPlumberConfigValidate(t *testing.T) {
	cfg := starterPlumberConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("starterPlumberConfig: %v", err)
	}
}

func TestInitWizardStateEmptyCategories(t *testing.T) {
	st := &initWizardState{}
	cfg := st.toPlumberConfig()
	if cfg.Version != "1.0" {
		t.Fatalf("version: got %q", cfg.Version)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestToPlumberConfigRequiredInclusions(t *testing.T) {
	st := &initWizardState{
		Categories:             []string{catComposition},
		CompositionChoices:     []string{compHardcoded},
		RequireComponents:      true,
		RequiredComponentsExpr: "components/sast/sast AND components/secret-detection/secret-detection",
		RequireTemplates:       true,
		RequiredTemplatesExpr:  "templates/security/sast",
	}
	cfg := st.toPlumberConfig()
	if cfg.Controls.PipelineMustIncludeComponent == nil || cfg.Controls.PipelineMustIncludeComponent.Required != st.RequiredComponentsExpr {
		t.Fatalf("component: %#v", cfg.Controls.PipelineMustIncludeComponent)
	}
	if cfg.Controls.PipelineMustIncludeTemplate == nil || cfg.Controls.PipelineMustIncludeTemplate.Required != st.RequiredTemplatesExpr {
		t.Fatalf("template: %#v", cfg.Controls.PipelineMustIncludeTemplate)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestToPlumberConfigRequiredSkippedWhenEmpty(t *testing.T) {
	st := &initWizardState{
		Categories:         []string{catComposition},
		CompositionChoices: []string{compHardcoded},
		RequireComponents:  true,
		// No expression — should be skipped.
	}
	cfg := st.toPlumberConfig()
	if cfg.Controls.PipelineMustIncludeComponent != nil {
		t.Fatalf("expected nil, got %#v", cfg.Controls.PipelineMustIncludeComponent)
	}
}
