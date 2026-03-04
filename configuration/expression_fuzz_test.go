package configuration

import "testing"

// FuzzParseRequiredExpression exercises the expression parser with arbitrary inputs
// to detect panics, infinite loops, and unexpected crashes.
//
// Run with: go test -fuzz=FuzzParseRequiredExpression ./configuration/
func FuzzParseRequiredExpression(f *testing.F) {
	// Seed corpus with representative inputs
	seeds := []string{
		"",
		"   ",
		"components/sast/sast",
		"a AND b",
		"a OR b",
		"a AND b OR c",
		"(a AND b) OR c",
		"a AND (b OR c)",
		"((a AND b) OR (c AND d)) AND e",
		"a AND b AND c AND d AND e",
		"a OR b OR c OR d OR e",
		"AND",
		"OR",
		"()",
		"(((",
		")))",
		"a AND AND b",
		"a OR OR b",
		"a AND OR b",
		"(a AND b",
		"a AND b)",
		"a AND (b OR (c AND (d OR e)))",
		"components/sast/sast AND components/secret-detection/secret-detection",
		"a-b/c_d.e AND f/g",
		string([]byte{0x00, 0x01, 0x02}),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, expr string) {
		// The function should never panic — it should return an error for invalid input
		_, _ = ParseRequiredExpression(expr)
	})
}
