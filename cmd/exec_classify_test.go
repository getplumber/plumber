package cmd

import (
	"errors"
	"fmt"
	"testing"
)

// TestClassifyExecError locks in the error-class → (prefix, exit code, emit)
// mapping behind Execute, including the --print gate that suppresses the
// duplicated "Blocked:" reason when the full report was already shown.
func TestClassifyExecError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		printOutput bool
		wantPrefix  string
		wantCode    int
		wantEmit    bool
	}{
		{
			name:        "score gate with report shown is silent",
			err:         &ScoreGateError{PointsGate: true, Points: 64, MinPoints: 100, Letter: "C"},
			printOutput: true,
			wantPrefix:  "Blocked",
			wantCode:    1,
			wantEmit:    false,
		},
		{
			name:        "score gate with report suppressed emits reason",
			err:         &ScoreGateError{PointsGate: true, Points: 64, MinPoints: 100, Letter: "C"},
			printOutput: false,
			wantPrefix:  "Blocked",
			wantCode:    1,
			wantEmit:    true,
		},
		{
			name:        "compliance error behaves like the gate case (shown)",
			err:         &ComplianceError{Compliance: 80, Threshold: 100},
			printOutput: true,
			wantPrefix:  "Blocked",
			wantCode:    1,
			wantEmit:    false,
		},
		{
			name:        "compliance error behaves like the gate case (suppressed)",
			err:         &ComplianceError{Compliance: 80, Threshold: 100},
			printOutput: false,
			wantPrefix:  "Blocked",
			wantCode:    1,
			wantEmit:    true,
		},
		{
			name:        "degraded error is Incomplete/3 regardless of print (true)",
			err:         &DegradedError{Count: 2},
			printOutput: true,
			wantPrefix:  "Incomplete",
			wantCode:    3,
			wantEmit:    true,
		},
		{
			name:        "degraded error is Incomplete/3 regardless of print (false)",
			err:         &DegradedError{Count: 2},
			printOutput: false,
			wantPrefix:  "Incomplete",
			wantCode:    3,
			wantEmit:    true,
		},
		{
			name:        "incomplete-data error is Incomplete/3 regardless of print (true)",
			err:         &IncompleteDataError{Reasons: []string{"branch protection fetch failed"}},
			printOutput: true,
			wantPrefix:  "Incomplete",
			wantCode:    3,
			wantEmit:    true,
		},
		{
			name:        "incomplete-data error is Incomplete/3 regardless of print (false)",
			err:         &IncompleteDataError{Reasons: []string{"branch protection fetch failed"}},
			printOutput: false,
			wantPrefix:  "Incomplete",
			wantCode:    3,
			wantEmit:    true,
		},
		{
			name:        "plain error is Error/2",
			err:         errors.New("boom"),
			printOutput: true,
			wantPrefix:  "Error",
			wantCode:    2,
			wantEmit:    true,
		},
		{
			name:        "wrapped gate error still classifies as Blocked",
			err:         fmt.Errorf("context: %w", &ScoreGateError{NoControls: true}),
			printOutput: false,
			wantPrefix:  "Blocked",
			wantCode:    1,
			wantEmit:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, code, emit := classifyExecError(tt.err, tt.printOutput)
			if prefix != tt.wantPrefix || code != tt.wantCode || emit != tt.wantEmit {
				t.Errorf("classifyExecError(%v, printOutput=%v) = (%q, %d, %v), want (%q, %d, %v)",
					tt.err, tt.printOutput, prefix, code, emit, tt.wantPrefix, tt.wantCode, tt.wantEmit)
			}
		})
	}
}
