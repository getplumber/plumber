package provider

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/pbom"
	"github.com/spf13/cobra"
)

func init() {
	Register(&GitHubProvider{})
}

// GitHubProvider implements Provider for GitHub Actions.
type GitHubProvider struct{}

func (p *GitHubProvider) Name() string { return "github" }

func (p *GitHubProvider) Controls(pc *configuration.PlumberConfig) []control.ControlEntry {
	return control.GitHubControls(pc)
}

func (p *GitHubProvider) ComputeCompliance(result *control.AnalysisResult, conf *configuration.Configuration) (float64, int) {
	findingsByControl := control.FindingsByControl(result.Findings)
	entries := control.GitHubControls(conf.PlumberConfig)
	control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
	totalPct := 0.0
	considered := 0
	for _, e := range entries {
		if e.Skipped {
			continue
		}
		totalPct += control.GitHubControlCompliance(e.ControlName, result.GitHubStats, len(findingsByControl[e.ControlName]))
		considered++
	}
	if considered == 0 {
		return 100.0, 0
	}
	return totalPct / float64(considered), considered
}

func (p *GitHubProvider) Run(conf *configuration.Configuration) (*control.AnalysisResult, error) {
	result, err := control.RunGitHubAnalysis(conf)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}
	return result, nil
}

// splitOwnerRepo splits "owner/repo" into [owner, repo].
// Returns ["", ""] when the path is not in that form.
func splitOwnerRepo(projectPath string) [2]string {
	for i, c := range projectPath {
		if c == '/' {
			return [2]string{projectPath[:i], projectPath[i+1:]}
		}
	}
	return [2]string{"", projectPath}
}

func (p *GitHubProvider) RunRemote(conf *configuration.Configuration) (*control.AnalysisResult, error) {
	parts := splitOwnerRepo(conf.ProjectPath)
	owner, repo := parts[0], parts[1]
	result, err := control.RunGitHubAnalysisRemote(conf, owner, repo, conf.Branch)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *GitHubProvider) WritePBOM(result *control.AnalysisResult, conf *configuration.Configuration, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	host := conf.GithubAPIHost
	if host == "" {
		host = "github.com"
	}
	gen := pbom.NewGitHubGenerator(result.ProjectPath, host, conf.Branch).
		WithGitHubComplianceData(pbom.BuildGitHubPBOMCompliance(result))
	bom := gen.GenerateFromGitHubIR(result.GitHubPipeline)
	bom.PlumberScore = pbom.BuildPlumberScoreSummary(score, scoreMode)

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create PBOM file: %w", err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

func (p *GitHubProvider) WritePBOMCycloneDX(result *control.AnalysisResult, conf *configuration.Configuration, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	host := conf.GithubAPIHost
	if host == "" {
		host = "github.com"
	}
	gen := pbom.NewGitHubGenerator(result.ProjectPath, host, conf.Branch).
		WithGitHubComplianceData(pbom.BuildGitHubPBOMCompliance(result))
	bom := gen.GenerateFromGitHubIR(result.GitHubPipeline)
	bom.PlumberScore = pbom.BuildPlumberScoreSummary(score, scoreMode)
	cdx := bom.ToCycloneDX("")

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CycloneDX PBOM file: %w", err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(cdx)
}

func (p *GitHubProvider) PostAnalysisActions(_ *cobra.Command, _ *control.AnalysisResult, _ *configuration.Configuration, _ PostActionSummary) error {
	return nil
}

func (p *GitHubProvider) BlobURLInfix() string { return "/blob/" }

func (p *GitHubProvider) CIEnvVars() CIEnvMapping {
	return CIEnvMapping{
		ServerURL: "GITHUB_SERVER_URL",
		RepoPath:  "GITHUB_REPOSITORY",
		CommitSHA: "GITHUB_SHA",
	}
}
