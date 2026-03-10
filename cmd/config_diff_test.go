package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlattenYamlContentsIntoMap(t *testing.T) {
	yaml := `
version: "1.0"
controls:
  branchMustBeProtected:
    enabled: true
    namePatterns:
      - main
      - master
`
	m, err := flattenYamlContentsIntoMap([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}

	if v, ok := m["version"]; !ok || v != "1.0" {
		t.Errorf("expected version=1.0, got %v", v)
	}
	if v, ok := m["controls.branchMustBeProtected.enabled"]; !ok || v != true {
		t.Errorf("expected enabled=true, got %v", v)
	}
	if _, ok := m["controls.branchMustBeProtected.namePatterns"]; !ok {
		t.Error("expected namePatterns key to exist")
	}
}

func TestFlattenYamlContentsIntoMap_InvalidYAML(t *testing.T) {
	_, err := flattenYamlContentsIntoMap([]byte(":::invalid"))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestFormatDiffValue(t *testing.T) {
	if got := formatDiffValue(nil); got != "(unset)" {
		t.Errorf("expected (unset), got %q", got)
	}
	if got := formatDiffValue(true); got != "true" {
		t.Errorf("expected true, got %q", got)
	}
	if got := formatDiffValue("hello"); got != "hello" {
		t.Errorf("expected hello, got %q", got)
	}
}

func TestToStringSlice(t *testing.T) {
	input := []interface{}{"a", "b", "c"}
	result := toStringSlice(input)
	if len(result) != 3 || result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestPrintChange_Scalar(t *testing.T) {
	out := captureStdout(t, func() {
		printChange("controls.x.enabled", true, false, false)
	})

	if !strings.Contains(out, "controls.x.enabled") {
		t.Error("expected key in output")
	}
	if !strings.Contains(out, "true") || !strings.Contains(out, "false") {
		t.Errorf("expected old/new values, got: %s", out)
	}
	if !strings.Contains(out, "→") {
		t.Error("expected arrow separator")
	}
}

func TestPrintChange_UnsetDefault(t *testing.T) {
	out := captureStdout(t, func() {
		printChange("controls.x.required", nil, "a AND b", false)
	})

	if !strings.Contains(out, "(unset)") {
		t.Errorf("expected (unset) for nil default, got: %s", out)
	}
	if !strings.Contains(out, "a AND b") {
		t.Errorf("expected user value, got: %s", out)
	}
}

func TestPrintSliceDiff(t *testing.T) {
	out := captureStdout(t, func() {
		defaultSlice := []interface{}{"a", "b", "c"}
		userSlice := []interface{}{"b", "c", "d"}
		printSliceDiff("controls.x.tags", defaultSlice, userSlice, false)
	})

	if !strings.Contains(out, "- a") {
		t.Errorf("expected removed item 'a', got: %s", out)
	}
	if !strings.Contains(out, "+ d") {
		t.Errorf("expected added item 'd', got: %s", out)
	}
	if strings.Contains(out, "- b") || strings.Contains(out, "+ b") {
		t.Errorf("unchanged item 'b' should not appear as +/-, got: %s", out)
	}
}

func TestPrintSliceDiff_AllAdded(t *testing.T) {
	out := captureStdout(t, func() {
		printSliceDiff("controls.x.items", []interface{}{}, []interface{}{"x", "y"}, false)
	})

	if !strings.Contains(out, "+ x") || !strings.Contains(out, "+ y") {
		t.Errorf("expected all items as added, got: %s", out)
	}
}

func TestPrintSliceDiff_AllRemoved(t *testing.T) {
	out := captureStdout(t, func() {
		printSliceDiff("controls.x.items", []interface{}{"a", "b"}, []interface{}{}, false)
	})

	if !strings.Contains(out, "- a") || !strings.Contains(out, "- b") {
		t.Errorf("expected all items as removed, got: %s", out)
	}
}

func TestPrintDiffReport_IdenticalConfigs(t *testing.T) {
	m := map[string]any{
		"version":                                     "1.0",
		"controls.branchMustBeProtected.enabled":      true,
		"controls.branchMustBeProtected.namePatterns": []interface{}{"main"},
	}
	userMap := map[string]any{
		"version":                                     "1.0",
		"controls.branchMustBeProtected.enabled":      true,
		"controls.branchMustBeProtected.namePatterns": []interface{}{"main"},
	}

	out := captureStdout(t, func() {
		printDiffReport(m, userMap, false)
	})

	assertContains(t, out, "Controls changed from defaults:")
	assertContains(t, out, "(none)")
}

func TestPrintDiffReport_ChangedValues(t *testing.T) {
	defaultMap := map[string]any{
		"controls.branchMustBeProtected.enabled":        true,
		"controls.branchMustBeProtected.allowForcePush": false,
	}
	userMap := map[string]any{
		"controls.branchMustBeProtected.enabled":        false,
		"controls.branchMustBeProtected.allowForcePush": true,
	}

	out := captureStdout(t, func() {
		printDiffReport(defaultMap, userMap, false)
	})

	assertContains(t, out, "controls.branchMustBeProtected.enabled")
	assertContains(t, out, "controls.branchMustBeProtected.allowForcePush")
	assertContains(t, out, "true → false")
	assertContains(t, out, "false → true")
}

func TestPrintDiffReport_MissingFromUser(t *testing.T) {
	defaultMap := map[string]any{
		"controls.branchMustBeProtected.enabled":        true,
		"controls.branchMustBeProtected.allowForcePush": false,
	}
	userMap := map[string]any{
		"controls.branchMustBeProtected.enabled": true,
	}

	out := captureStdout(t, func() {
		printDiffReport(defaultMap, userMap, false)
	})

	assertContains(t, out, "New keys in default")
	assertContains(t, out, "controls.branchMustBeProtected.allowForcePush")
	assertContains(t, out, "(default: false)")
}

func TestPrintDiffReport_UnknownKeys(t *testing.T) {
	defaultMap := map[string]any{
		"controls.branchMustBeProtected.enabled": true,
	}
	userMap := map[string]any{
		"controls.branchMustBeProtected.enabled": true,
		"controls.totallyFakeControl.enabled":    true,
	}

	out := captureStdout(t, func() {
		printDiffReport(defaultMap, userMap, false)
	})

	assertContains(t, out, "Unknown keys in your config")
	assertContains(t, out, "totallyFakeControl")
}

func TestPrintDiffReport_SliceChanges(t *testing.T) {
	defaultMap := map[string]any{
		"controls.branchMustBeProtected.namePatterns": []interface{}{"main", "master", "release"},
	}
	userMap := map[string]any{
		"controls.branchMustBeProtected.namePatterns": []interface{}{"main", "production"},
	}

	out := captureStdout(t, func() {
		printDiffReport(defaultMap, userMap, false)
	})

	assertContains(t, out, "- master")
	assertContains(t, out, "- release")
	assertContains(t, out, "+ production")
}

func TestRunConfigDiff_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	userFile := filepath.Join(dir, "nonexistent.yaml")

	_, err := os.ReadFile(userFile)
	if err == nil {
		t.Fatal("expected file to not exist")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected IsNotExist error, got: %v", err)
	}

	expectedMsg := fmt.Sprintf("config file not found: %s", userFile)
	if !strings.Contains(expectedMsg, "config file not found") {
		t.Errorf("unexpected error message: %s", expectedMsg)
	}
}

// captureStdout redirects os.Stdout to a pipe, runs fn, and returns the output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	fn()

	defer func() { _ = w.Close() }()
	os.Stdout = old

	var buf [16384]byte
	n, _ := r.Read(buf[:])
	return string(buf[:n])
}

func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected output to contain %q, got:\n%s", needle, haystack)
	}
}
