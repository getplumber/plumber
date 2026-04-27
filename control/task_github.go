package control

import (
	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
)

// RunGitHubAnalysis is the GitHub counterpart of RunAnalysis. It scans
// .github/workflows/*.{yml,yaml} under conf.GitRepoRoot, evaluates the
// embedded Rego policies against the resulting IR, and returns an
// AnalysisResult whose only populated fields are the project metadata
// and Findings. No legacy Go control fields are set — GitHub support is
// Rego-only by design (see docs/REFACTOR_MULTI_PROVIDER.md §4).
func RunGitHubAnalysis(conf *configuration.Configuration) (*AnalysisResult, error) {
	l := logrus.WithFields(logrus.Fields{
		"action":      "RunGitHubAnalysis",
		"projectPath": conf.ProjectPath,
		"gitRepoRoot": conf.GitRepoRoot,
	})
	l.Info("Starting GitHub Actions analysis")

	// Forward conf.ProgressFunc to the collector so the analyze-
	// command spinner animates during the slow GitHub API enrichment
	// phase. The collector's progress contract is ProgressFunc(step,
	// total, message); we map directly onto the same-shape callback
	// conf exposes.
	var progressFn collector.ProgressFunc
	if conf.ProgressFunc != nil {
		progressFn = collector.ProgressFunc(conf.ProgressFunc)
	}
	pipeline, partial, err := collector.ScanGitHubWorkflowsWithProgress(
		conf.ProjectPath,
		conf.Branch,
		conf.GitRepoRoot,
		progressFn,
	)
	if err != nil {
		l.WithError(err).Error("Failed to scan GitHub workflows")
		return nil, err
	}
	for _, perr := range partial {
		l.WithError(perr).Warn("GitHub workflow parse: partial failure (file skipped)")
	}

	if conf.ProgressFunc != nil {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total-1, total, "Evaluating policies")
	}
	result := &AnalysisResult{
		ProjectPath:    conf.ProjectPath,
		DefaultBranch:  conf.Branch,
		CIConfigSource: "local",
		CiValid:        len(pipeline.Jobs) > 0,
		CiMissing:      len(pipeline.Jobs) == 0,
		Findings:       evaluatePolicies(l, conf.PlumberConfig, pipeline),
	}
	if conf.ProgressFunc != nil {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total, total, "Analysis complete")
	}

	l.WithFields(logrus.Fields{
		"jobCount":     len(pipeline.Jobs),
		"findingCount": len(result.Findings),
	}).Info("GitHub Actions analysis completed")

	return result, nil
}
