package configuration

import (
	"strings"
	"testing"
)

// Every control carries a one-sentence description: the CLI's own wording,
// exported so the platform console and docs never author a divergent copy
// (#458). Non-empty, sentence-shaped, and not a lazy DisplayName echo.
func TestEveryControlHasADescription(t *testing.T) {
	for _, e := range ControlsCatalog() {
		d := strings.TrimSpace(e.Description)
		if d == "" {
			t.Errorf("control %q has no Description", e.Name)
			continue
		}
		if !strings.HasSuffix(d, ".") {
			t.Errorf("control %q Description does not end with a period: %q", e.Name, d)
		}
		if d == e.DisplayName || d == e.DisplayName+"." {
			t.Errorf("control %q Description is just the DisplayName; write a real sentence", e.Name)
		}
	}
}
