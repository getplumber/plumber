package provider

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/getplumber/plumber/capability"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
)

// The one recognize call both bills share (the --pbom artifact and the push's
// bom section): the CLI's built-in list, nothing at all without a pipeline. The
// served declarations are wired in by the next change of this series.
func TestCapabilitiesOf_BuiltinListStandaloneAndNilPipeline(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "leaks", Scripts: []string{"gitleaks detect"}},
		{Name: "corp", Scripts: []string{"scan-secrets --all"}},
		{Name: "test", Scripts: []string{"make test"}},
	}}
	result := &control.AnalysisResult{Pipeline: pipe}

	standalone := CapabilitiesOf(result, &configuration.Configuration{})
	want := []capability.Match{{Kind: "secret_detection", Job: "leaks", Tool: "gitleaks", Evidence: "commands"}}
	if !reflect.DeepEqual(standalone, want) {
		t.Fatalf("standalone = %+v, want the built-in list only %+v", standalone, want)
	}

	// A platform run whose /context fetch failed degrades to the defaults.
	degraded := CapabilitiesOf(result, &configuration.Configuration{PlatformRun: &platform.RunContext{}})
	if len(degraded) != 1 || degraded[0].Tool != "gitleaks" {
		t.Fatalf("a failed /context fetch = %+v, want the defaults only", degraded)
	}

	if got := CapabilitiesOf(&control.AnalysisResult{}, nil); got != nil {
		t.Fatalf("no pipeline = %+v, want nil", got)
	}
	if got := CapabilitiesOf(nil, nil); got != nil {
		t.Fatalf("nil result = %+v, want nil", got)
	}
}

// Wrapper scripts are read off disk only when the checkout IS the analyzed
// project at the analyzed ref, the same two gates the CI-file read and the
// config digest use (control/task.go, cmd/platform_mode.go). Otherwise a
// script of whatever repository the CLI stands in would become wrapper_script
// evidence for another project. Image and command evidence need no checkout
// and keep working either way. The ref gate reads the CI environment, so the
// test sets it with t.Setenv rather than building a repository.
func TestCapabilitiesOf_WrapperScriptsOnlyFromTheAnalyzedCheckoutAtItsRef(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ci"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ci", "scan.sh"), []byte("#!/bin/sh\ntrufflehog filesystem .\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := &control.AnalysisResult{Pipeline: &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "image", Image: &ir.Image{Registry: "docker.io", Name: "zricethezav/gitleaks"}},
		{Name: "command", Scripts: []string{"gitleaks detect"}},
		{Name: "wrapper", Scripts: []string{"./ci/scan.sh"}},
	}}}
	withWrapper := []capability.Match{
		{Kind: "secret_detection", Job: "command", Tool: "gitleaks", Evidence: "commands"},
		{Kind: "secret_detection", Job: "image", Tool: "gitleaks", Evidence: "images"},
		{Kind: "secret_detection", Job: "wrapper", Tool: "trufflehog", Evidence: "wrapper_script"},
	}
	withoutWrapper := withWrapper[:2]

	t.Setenv("CI", "true")
	t.Setenv("CI_COMMIT_REF_NAME", "main")

	t.Run("the analyzed project at its ref", func(t *testing.T) {
		got := CapabilitiesOf(result, &configuration.Configuration{GitRepoRoot: root, CheckoutIsAnalyzedProject: true, Branch: "main"})
		if !reflect.DeepEqual(got, withWrapper) {
			t.Fatalf("got %+v, want %+v", got, withWrapper)
		}
	})
	t.Run("the checkout is another project", func(t *testing.T) {
		got := CapabilitiesOf(result, &configuration.Configuration{GitRepoRoot: root, CheckoutIsAnalyzedProject: false, Branch: "main"})
		if !reflect.DeepEqual(got, withoutWrapper) {
			t.Fatalf("got %+v, want no wrapper evidence %+v", got, withoutWrapper)
		}
	})
	t.Run("the checkout is at another ref", func(t *testing.T) {
		got := CapabilitiesOf(result, &configuration.Configuration{GitRepoRoot: root, CheckoutIsAnalyzedProject: true, Branch: "release"})
		if !reflect.DeepEqual(got, withoutWrapper) {
			t.Fatalf("got %+v, want no wrapper evidence %+v", got, withoutWrapper)
		}
	})
}
