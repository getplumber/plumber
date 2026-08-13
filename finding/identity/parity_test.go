package identity_test

import (
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/finding/identity"
)

// Every registered ISSUE code declares its identity fields, and every
// declaration names a registered code. A new code cannot merge without a
// declaration: this failure names it.
func TestEveryRegisteredCodeHasAnIdentityDeclaration(t *testing.T) {
	registered := map[string]bool{}
	for _, info := range control.AllCodes() {
		code := string(info.Code)
		registered[code] = true
		if _, ok := identity.Declared(code); !ok {
			t.Errorf("%s is registered in control/codes.go but has no identity declaration; add it to finding/identity/declarations.go (see docs/FINGERPRINT.md)", code)
		}
	}
	for _, code := range identity.DeclaredCodes() {
		if !registered[code] {
			t.Errorf("%s has an identity declaration but is not registered in control/codes.go; remove the stale entry", code)
		}
	}
}
