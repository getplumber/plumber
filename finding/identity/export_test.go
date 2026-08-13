package identity

import "testing"

// DeclareForTest installs a synthetic declaration for the duration of one
// test. It bridges the internal declarations table to the external
// identity_test package; _test.go placement keeps it out of builds.
func DeclareForTest(t *testing.T, code string, fields []string) {
	t.Helper()
	prev, had := declarations[code]
	declarations[code] = fields
	t.Cleanup(func() {
		if had {
			declarations[code] = prev
		} else {
			delete(declarations, code)
		}
	})
}
