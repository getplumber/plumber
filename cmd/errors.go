package cmd

import "fmt"

// ComplianceError is returned when analysis completes successfully but the
// measured compliance score falls below the required threshold.
//
// It is distinct from a generic runtime error so that callers (e.g. Execute)
// can map it to a dedicated exit code:
//
//	0 – analysis passed (compliance ≥ threshold)
//	1 – compliance failure (compliance < threshold)
//	2 – runtime / configuration error
type ComplianceError struct {
	Compliance float64
	Threshold  float64
}

func (e *ComplianceError) Error() string {
	return fmt.Sprintf("compliance %.1f%% is below threshold %.1f%%", e.Compliance, e.Threshold)
}
