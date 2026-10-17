package runners

import "testing"

// TestRetiredAsOfIsTheDatedList pins the exact six labels GitHub itself
// retired as of RetiredAsOf: a job pinned to any one of them can never be
// scheduled.
func TestRetiredAsOfIsTheDatedList(t *testing.T) {
	if RetiredAsOf != "2026-10-15" {
		t.Fatalf("RetiredAsOf = %q, want 2026-10-15", RetiredAsOf)
	}
	for _, label := range []string{"ubuntu-18.04", "ubuntu-20.04", "macos-11", "macos-12", "macos-13", "windows-2019"} {
		if !Retired(label) {
			t.Errorf("Retired(%q) = false, want true", label)
		}
	}
}

// TestRetiredMatchesCaseInsensitivelyAndTrimsSpaces pins that a label
// written with different casing, or with leading/trailing whitespace
// (both legal YAML authoring accidents), is still recognized.
func TestRetiredMatchesCaseInsensitivelyAndTrimsSpaces(t *testing.T) {
	for _, label := range []string{"Ubuntu-20.04", "UBUNTU-20.04", "  ubuntu-20.04  ", "\tmacos-11\n"} {
		if !Retired(label) {
			t.Errorf("Retired(%q) = false, want true", label)
		}
	}
}

// TestRetiredFalseOnALiveLabel pins that a currently supported label (or
// an unrelated self-hosted tag) never reads as retired.
func TestRetiredFalseOnALiveLabel(t *testing.T) {
	for _, label := range []string{"ubuntu-22.04", "ubuntu-latest", "macos-14", "windows-latest", "self-hosted", ""} {
		if Retired(label) {
			t.Errorf("Retired(%q) = true, want false", label)
		}
	}
}
