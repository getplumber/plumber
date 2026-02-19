package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
)

func TestShouldRunControl(t *testing.T) {
	tests := []struct {
		name      string
		control   string
		conf      *configuration.Configuration
		shouldRun bool
	}{
		{
			name:      "no filters",
			control:   "branchMustBeProtected",
			conf:      &configuration.Configuration{},
			shouldRun: true,
		},
		{
			name:    "included control runs",
			control: "branchMustBeProtected",
			conf: &configuration.Configuration{
				ControlsFilter: []string{"branchMustBeProtected"},
			},
			shouldRun: true,
		},
		{
			name:    "controls filter excludes control",
			control: "includesMustBeUpToDate",
			conf: &configuration.Configuration{
				ControlsFilter: []string{"branchMustBeProtected"},
			},
			shouldRun: false,
		},
		{
			name:    "skip filter excludes control",
			control: "branchMustBeProtected",
			conf: &configuration.Configuration{
				SkipControlsFilter: []string{"branchMustBeProtected"},
			},
			shouldRun: false,
		},
		{
			name:    "skip still wins if both contain control",
			control: "branchMustBeProtected",
			conf: &configuration.Configuration{
				ControlsFilter:     []string{"branchMustBeProtected"},
				SkipControlsFilter: []string{"branchMustBeProtected"},
			},
			shouldRun: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldRunControl(tt.control, tt.conf)
			if got != tt.shouldRun {
				t.Fatalf("shouldRunControl(%q) = %v, want %v", tt.control, got, tt.shouldRun)
			}
		})
	}
}
