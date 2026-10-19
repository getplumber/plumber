package capability

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/capability/capdecl"
)

// capturedLog (recognize_test.go) hooks the standard logger at debug level and restores it
// afterwards; reused here so FromFile's tests assert on the same warning the same way.

// Spec 4.2 and 4.6: FromFile is the one place the provider and `config view` both decode a
// .plumber.yaml `capabilities:` key the strict way and check its bounds, so the two can
// never read the key differently. Nil raw (no key declared) is nil, no warning.
func TestFromFile_NilRawIsNilNoWarning(t *testing.T) {
	hook := capturedLog(t)
	l := logrus.WithField("context", "test")
	if got := FromFile(nil, l); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
	if len(hook.AllEntries()) != 0 {
		t.Fatalf("entries = %+v, want none", hook.AllEntries())
	}
}

// A well-formed file value decodes to the declarations it holds.
func TestFromFile_WellFormedDecodes(t *testing.T) {
	raw := []Declaration{{Name: "corp-secrets", Recognizers: []capdecl.Recognizer{{Tool: "in-house", Commands: []string{"scan-secrets*"}}}}}
	l := logrus.WithField("context", "test")
	got := FromFile(raw, l)
	if len(got) != 1 || got[0].Name != "corp-secrets" {
		t.Fatalf("got %+v, want corp-secrets", got)
	}
}

// An invalid file value (fails Validate's bounds) warns once, naming the violation, and
// returns nil so the caller falls back to the built-in list.
func TestFromFile_InvalidFallsBackAndWarnsOnce(t *testing.T) {
	hook := capturedLog(t)
	raw := []Declaration{{Name: "SAST", Recognizers: []capdecl.Recognizer{{Tool: "semgrep", Commands: []string{"semgrep *"}}}}}
	l := logrus.WithField("context", "test")
	got := FromFile(raw, l)
	if got != nil {
		t.Fatalf("got %+v, want nil (fall back to built-in)", got)
	}
	var warns []*logrus.Entry
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			warns = append(warns, e)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("warnings = %d, want exactly one", len(warns))
	}
	if err, _ := warns[0].Data[logrus.ErrorKey].(error); err == nil || !strings.Contains(err.Error(), "a capability name must be 1 to 64 bytes") {
		t.Fatalf("warning error = %v, want the violation named", warns[0].Data[logrus.ErrorKey])
	}
	if !strings.Contains(warns[0].Message, "the built-in list is in force") {
		t.Fatalf("warning message = %q, want it to say the built-in list is in force", warns[0].Message)
	}
}

// A malformed value (wrong type for a field) fails the strict decode, which also warns once
// and falls back.
func TestFromFile_MalformedDecodeFallsBack(t *testing.T) {
	hook := capturedLog(t)
	raw := map[string]interface{}{"name": "secret_detection"} // a map, not a list
	l := logrus.WithField("context", "test")
	got := FromFile(raw, l)
	if got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
	warns := 0
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			warns++
		}
	}
	if warns != 1 {
		t.Fatalf("warnings = %d, want exactly one", warns)
	}
}
