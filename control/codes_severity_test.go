package control

import "testing"

func TestSeverityForCode_allRegistryCodes(t *testing.T) {
	for code := range errorCodeRegistry {
		sev := SeverityForCode(code)
		switch sev {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		default:
			t.Fatalf("code %s: invalid severity %q", code, sev)
		}
	}
}

func TestSeverityForCode_unknownDefaultsMedium(t *testing.T) {
	if SeverityForCode("ISSUE-99999") != SeverityMedium {
		t.Fatal("expected medium for unknown code")
	}
}
