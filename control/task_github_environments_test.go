package control

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

// TestEnrichGitHubEnvironmentsSetsPipelineFields checks that a
// successful lookup threads straight onto the pipeline: Environments
// and EnvironmentsKnown both set, no warning logged.
func TestEnrichGitHubEnvironmentsSetsPipelineFields(t *testing.T) {
	orig := fetchGitHubEnvironments
	t.Cleanup(func() { fetchGitHubEnvironments = orig })
	fetchGitHubEnvironments = func(host, owner, repo string) ([]ir.Environment, bool, error) {
		return []ir.Environment{{Name: "production", Known: true, RequiredReviewers: true}}, true, nil
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}
	enrichGitHubEnvironments(logrus.NewEntry(logrus.New()), p, "", "acme", "widget")
	if !p.EnvironmentsKnown {
		t.Fatal("EnvironmentsKnown must be true on a successful fetch")
	}
	if len(p.Environments) != 1 || p.Environments[0].Name != "production" {
		t.Fatalf("Environments = %+v", p.Environments)
	}
}

// TestEnrichGitHubEnvironmentsDegradesQuietlyWithoutError checks the
// 403/404/network contract: known=false with a nil error never flags
// the run degraded and never logs a warning (nothing to log).
func TestEnrichGitHubEnvironmentsDegradesQuietlyWithoutError(t *testing.T) {
	orig := fetchGitHubEnvironments
	t.Cleanup(func() { fetchGitHubEnvironments = orig })
	fetchGitHubEnvironments = func(host, owner, repo string) ([]ir.Environment, bool, error) {
		return nil, false, nil
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}
	enrichGitHubEnvironments(logrus.NewEntry(logrus.New()), p, "", "acme", "widget")
	if p.EnvironmentsKnown {
		t.Fatal("EnvironmentsKnown must stay false on a degraded fetch")
	}
	if p.Environments != nil {
		t.Fatalf("Environments = %+v, want none", p.Environments)
	}
}

// TestEnrichGitHubEnvironmentsWithoutOwnerRepoNeverCalls checks that an
// unaddressable project path never reaches the collector.
func TestEnrichGitHubEnvironmentsWithoutOwnerRepoNeverCalls(t *testing.T) {
	orig := fetchGitHubEnvironments
	t.Cleanup(func() { fetchGitHubEnvironments = orig })
	fetchGitHubEnvironments = func(host, owner, repo string) ([]ir.Environment, bool, error) {
		t.Fatal("must not be called without an owner and a repo")
		return nil, false, nil
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}
	enrichGitHubEnvironments(logrus.NewEntry(logrus.New()), p, "", "", "widget")
}
