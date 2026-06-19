package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

// TestOutputsSurfaceWarnings is the ISSUE-228 degraded-mode regression: a
// "could not verify" warning on the result must appear in the SARIF (as a
// tool-execution notification) and the GLSAST report (as a scan.message),
// so a skipped check is visible to dashboards instead of silently passing.
// A clean result must emit neither.
func TestOutputsSurfaceWarnings(t *testing.T) {
	const warn = "aquasecurity/trivy-action@deadbeef: tag list unavailable, could not resolve the pinned commit to a version, so the known-CVE check was skipped for this action"
	dir := t.TempDir()

	// Degraded result: warning shows in both formats.
	result := &control.AnalysisResult{Warnings: []string{warn}}

	sarifPath := filepath.Join(dir, "out.sarif")
	if err := writeSARIFToFile(result, sarifPath, "github"); err != nil {
		t.Fatalf("writeSARIFToFile: %v", err)
	}
	sb := mustRead(t, sarifPath)
	if !strings.Contains(sb, "toolExecutionNotifications") || !strings.Contains(sb, "tag list unavailable") {
		t.Errorf("SARIF missing warning notification:\n%s", sb)
	}

	glPath := filepath.Join(dir, "gl-sast.json")
	if err := writeGLSASTToFile(result, glPath, "github"); err != nil {
		t.Fatalf("writeGLSASTToFile: %v", err)
	}
	gb := mustRead(t, glPath)
	if !strings.Contains(gb, `"messages"`) || !strings.Contains(gb, "tag list unavailable") {
		t.Errorf("GLSAST missing scan.messages warning:\n%s", gb)
	}

	// Clean result: no warning machinery emitted.
	clean := &control.AnalysisResult{}
	cleanSarif := filepath.Join(dir, "clean.sarif")
	if err := writeSARIFToFile(clean, cleanSarif, "github"); err != nil {
		t.Fatalf("writeSARIFToFile clean: %v", err)
	}
	if cb := mustRead(t, cleanSarif); strings.Contains(cb, "toolExecutionNotifications") {
		t.Errorf("clean SARIF should carry no notifications:\n%s", cb)
	}
}

// TestDegradedArtifactsStampedFailed is the #220 counterpart: a
// data-collection-degraded result must stamp the SARIF as a failed run
// (executionSuccessful:false) and the GLSAST scan status as "failure", so a
// dashboard does not treat the partial report as authoritative. A clean run
// must keep executionSuccessful:true / status:"success".
func TestDegradedArtifactsStampedFailed(t *testing.T) {
	dir := t.TempDir()
	degraded := &control.AnalysisResult{
		DataCollectionDegraded: true,
		DegradedReasons:        []string{"3 workflow file(s) could not be fetched and were skipped"},
	}

	sarifPath := filepath.Join(dir, "degraded.sarif")
	if err := writeSARIFToFile(degraded, sarifPath, "github"); err != nil {
		t.Fatalf("writeSARIFToFile: %v", err)
	}
	sb := mustRead(t, sarifPath)
	if !strings.Contains(sb, `"executionSuccessful": false`) {
		t.Errorf("degraded SARIF should mark executionSuccessful:false:\n%s", sb)
	}
	if !strings.Contains(sb, "data collection incomplete") {
		t.Errorf("degraded SARIF should carry the reason notification:\n%s", sb)
	}

	glPath := filepath.Join(dir, "degraded-gl.json")
	if err := writeGLSASTToFile(degraded, glPath, "github"); err != nil {
		t.Fatalf("writeGLSASTToFile: %v", err)
	}
	gb := mustRead(t, glPath)
	if !strings.Contains(gb, `"status": "failure"`) {
		t.Errorf("degraded GLSAST should mark scan.status failure:\n%s", gb)
	}

	// Clean run keeps the success markers.
	clean := &control.AnalysisResult{}
	cleanGl := filepath.Join(dir, "clean-gl.json")
	if err := writeGLSASTToFile(clean, cleanGl, "github"); err != nil {
		t.Fatalf("writeGLSASTToFile clean: %v", err)
	}
	if cb := mustRead(t, cleanGl); !strings.Contains(cb, `"status": "success"`) {
		t.Errorf("clean GLSAST should keep status success:\n%s", cb)
	}
	cleanSarif := filepath.Join(dir, "clean2.sarif")
	if err := writeSARIFToFile(clean, cleanSarif, "github"); err != nil {
		t.Fatalf("writeSARIFToFile clean: %v", err)
	}
	if cb := mustRead(t, cleanSarif); strings.Contains(cb, `"executionSuccessful": false`) {
		t.Errorf("clean SARIF must not mark the run failed:\n%s", cb)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
