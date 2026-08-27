package provider

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	glabCI "github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/pbom"
	"github.com/spf13/cobra"
)

func init() {
	Register(&GitLabProvider{})
}

// GitLabProvider implements Provider for GitLab CI/CD.
type GitLabProvider struct{}

func (p *GitLabProvider) Name() string { return "gitlab" }

func (p *GitLabProvider) Controls(pc *configuration.PlumberConfig) []control.ControlEntry {
	return control.GitLabControls(pc)
}

func (p *GitLabProvider) ComputeCompliance(result *control.AnalysisResult, conf *configuration.Configuration) (float64, int) {
	// --no-controls wins over the config: the controls enabled in
	// .plumber.yaml are ignored, so nothing is evaluated and nothing is
	// counted. The zero is what makes the gate a no-op.
	if conf.NoControls {
		return 0.0, 0
	}
	if result.CiMissing || !result.CiValid {
		return 0.0, 0
	}
	findingCountsByControl := map[string]int{}
	for _, f := range result.Findings {
		if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil {
			findingCountsByControl[info.ControlName]++
		}
	}
	passed := 0
	controlCount := 0
	entries := control.GitLabControls(conf.PlumberConfig)
	control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
	for _, e := range entries {
		if e.Skipped {
			continue
		}
		controlCount++
		if findingCountsByControl[e.ControlName] == 0 {
			passed++
		}
	}
	if controlCount == 0 {
		return 0.0, 0
	}
	return float64(passed) * 100.0 / float64(controlCount), controlCount
}

func (p *GitLabProvider) Run(conf *configuration.Configuration) (*control.AnalysisResult, error) {
	result, err := control.RunAnalysis(conf)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}
	return result, nil
}

func (p *GitLabProvider) RunRemote(_ *configuration.Configuration) (*control.AnalysisResult, error) {
	return nil, ErrNoRemote
}

// noControlsAwareImageCompliance returns the per-image compliance flags, or
// nil when the run evaluated nothing. The flags are derived from findings,
// not from the score, so an empty findings slice would otherwise mark every
// image forbiddenTag:false / authorized:true and assert the very image
// checks --no-controls skipped, inside the artifact the flag exists to
// produce. With nil the PBOM records the inventory and claims nothing.
// conf is required, as everywhere else on this path (the writers read
// conf.GitlabURL unconditionally).
func noControlsAwareImageCompliance(result *control.AnalysisResult, conf *configuration.Configuration) *pbom.ImageComplianceData {
	if conf.NoControls {
		return nil
	}
	return pbom.BuildImageComplianceData(result)
}

func (p *GitLabProvider) WritePBOM(result *control.AnalysisResult, conf *configuration.Configuration, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	complianceData := noControlsAwareImageCompliance(result, conf)
	overrideData := pbom.BuildIncludeOverrideData(result)
	gen := pbom.NewGenerator(result.ProjectPath, result.ProjectID, conf.GitlabURL, conf.Branch).
		WithComplianceData(complianceData).
		WithIncludeOverrideData(overrideData)
	if conf.NoControls {
		gen = gen.WithoutComplianceVerdicts()
	}
	bom := gen.Generate(result.PipelineImageData, result.PipelineOriginData)
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

func (p *GitLabProvider) WritePBOMCycloneDX(result *control.AnalysisResult, conf *configuration.Configuration, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	complianceData := noControlsAwareImageCompliance(result, conf)
	overrideData := pbom.BuildIncludeOverrideData(result)
	gen := pbom.NewGenerator(result.ProjectPath, result.ProjectID, conf.GitlabURL, conf.Branch).
		WithComplianceData(complianceData).
		WithIncludeOverrideData(overrideData)
	if conf.NoControls {
		gen = gen.WithoutComplianceVerdicts()
	}
	bom := gen.Generate(result.PipelineImageData, result.PipelineOriginData)
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

func (p *GitLabProvider) PostAnalysisActions(cmd *cobra.Command, result *control.AnalysisResult, conf *configuration.Configuration, s PostActionSummary) error {
	if mrComment, _ := cmd.Flags().GetBool("mr-comment"); mrComment {
		if result.DataCollectionDegraded {
			// A transient collection failure must not overwrite the MR comment
			// with a partial result whose score reads as a clean A on an empty
			// pipeline (#220).
			fmt.Fprintf(os.Stderr, "Skipping merge request comment: data collection was incomplete; not overwriting with a partial result.\n")
		} else if mrIID := glabCI.DetectMergeRequestIID(); mrIID != 0 {
			fmt.Fprintf(os.Stderr, "Merge request pipeline detected (MR !%d), posting Plumber comment...\n", mrIID)
			if err := control.ManageMergeRequestComment(result.ProjectID, mrIID, result, conf.PlumberConfig, s.Passed, s.GateLine, conf, s.Score, s.ScoreMode, s.ScorePoint); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to post merge request comment: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Merge request comment posted successfully\n")
			}
		}
	}
	if badge, _ := cmd.Flags().GetBool("badge"); badge {
		shouldUpdate, skipReason := gitLabBadgeShouldUpdate(cmd, result, conf)
		if !shouldUpdate {
			fmt.Fprintf(os.Stderr, "Skipping badge update (%s)\n", skipReason)
		} else {
			fmt.Fprintf(os.Stderr, "Updating project badge...\n")
			if err := control.ManageProjectBadge(result.ProjectID, conf, s.Score); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to update project badge: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Project badge updated successfully\n")
			}
		}
	}
	return nil
}

func (p *GitLabProvider) BlobURLInfix() string { return "/-/blob/" }

func (p *GitLabProvider) CIEnvVars() CIEnvMapping {
	return CIEnvMapping{
		ServerURL: "CI_SERVER_URL",
		RepoPath:  "CI_PROJECT_PATH",
		CommitSHA: "CI_COMMIT_SHA",
	}
}

func gitLabBadgeShouldUpdate(cmd *cobra.Command, result *control.AnalysisResult, conf *configuration.Configuration) (bool, string) {
	// A network/rate-limit blip should leave the last good badge untouched, not
	// replace it with a misleading score from an empty pipeline (#220).
	if result.DataCollectionDegraded {
		return false, "data collection was incomplete; badge left unchanged to avoid overwriting the last good score"
	}
	if glabCI.IsRunningInCI() {
		if glabCI.IsOnDefaultBranchCI() {
			return true, ""
		}
		return false, "not on default branch in CI"
	}
	if result.CIConfigSource == "local" {
		return false, "using local CI files (testing mode)"
	}
	if !cmd.Flags().Changed("branch") {
		return true, ""
	}
	if conf.Branch == result.DefaultBranch {
		return true, ""
	}
	return false, fmt.Sprintf("analyzing branch '%s', not default branch '%s'", conf.Branch, result.DefaultBranch)
}
