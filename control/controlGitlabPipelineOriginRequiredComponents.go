package control

import (
	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabPipelineOriginRequiredComponentsVersion = "0.2.0"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineRequiredComponentsConf holds the configuration for required components check
type GitlabPipelineRequiredComponentsConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`
	// DNF (Disjunctive Normal Form) format:
	// Outer array = OR (at least one group must be satisfied)
	// Inner array = AND (all components in group must be present)
	// Example: [["comp-a", "comp-b"], ["comp-c"]] means:
	//   "must have (comp-a AND comp-b) OR (comp-c)"
	RequiredGroups [][]string `json:"requiredGroups"`
}

// GetConf loads configuration from PlumberConfig
func (p *GitlabPipelineRequiredComponentsConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	config := plumberConfig.GetPipelineMustIncludeComponentConfig()
	if config == nil {
		p.Enabled = false
		return nil
	}

	p.Enabled = config.IsEnabled()

	// Resolve required groups from either 'required' expression or legacy 'requiredGroups'
	groups, err := config.GetResolvedRequiredGroups()
	if err != nil {
		return err
	}
	p.RequiredGroups = groups

	l.WithFields(logrus.Fields{
		"enabled":        p.Enabled,
		"requiredGroups": p.RequiredGroups,
		"hasExpression":  config.Required != "",
	}).Debug("pipelineMustIncludeComponent control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// ComponentGroupStatus tracks the status of a single requirement group (AND clause)
type ComponentGroupStatus struct {
	GroupIndex        int      `json:"groupIndex"`        // Which requirement group (0-based)
	RequiredOrigins   []string `json:"requiredOrigins"`   // Components required in this group
	FoundOrigins      []string `json:"foundOrigins"`      // Components found and not overridden
	MissingOrigins    []string `json:"missingOrigins"`    // Components missing from this group
	OverriddenOrigins []string `json:"overriddenOrigins"` // Components found but overridden with forbidden keywords
	IsFullySatisfied  bool     `json:"isFullySatisfied"`  // All components in group present (not missing)
}

// GitlabPipelineRequiredComponentsMetrics holds metrics about required components
type GitlabPipelineRequiredComponentsMetrics struct {
	TotalGroups       uint `json:"totalGroups"`       // Total number of requirement groups
	SatisfiedGroups   uint `json:"satisfiedGroups"`   // Number of fully satisfied groups
	AnySatisfiedGroup bool `json:"anySatisfiedGroup"` // True if at least one group satisfied
	CiInvalid         uint `json:"ciInvalid"`
	CiMissing         uint `json:"ciMissing"`
}

// GitlabPipelineRequiredComponentsResult holds the result of the required components control
type GitlabPipelineRequiredComponentsResult struct {
	RequirementGroups []ComponentGroupStatus                  `json:"requirementGroups"`
	Issues            []RequiredComponentIssue                `json:"issues"`
	OverriddenIssues  []RequiredComponentOverriddenIssue      `json:"overriddenIssues"`
	Metrics           GitlabPipelineRequiredComponentsMetrics `json:"metrics"`
	Compliance        float64                                 `json:"compliance"`
	Version           string                                  `json:"version"`
	CiValid           bool                                    `json:"ciValid"`
	CiMissing         bool                                    `json:"ciMissing"`
	Skipped           bool                                    `json:"skipped"`
	Error             string                                  `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// RequiredComponentIssue represents an issue with a missing required component
type RequiredComponentIssue struct {
	ComponentPath string `json:"componentPath"`
	GroupIndex    int    `json:"groupIndex"`
}

// RequiredComponentOverriddenIssue represents an issue where a required component
// is imported but its jobs are overridden with forbidden keywords
type RequiredComponentOverriddenIssue struct {
	ComponentPath  string                `json:"componentPath"`
	GroupIndex     int                   `json:"groupIndex"`
	OverriddenJobs []utils.OverriddenJobDetail `json:"overriddenJobs"`
}

///////////////////////
// Control functions //
///////////////////////

// Run executes the required components control
func (p *GitlabPipelineRequiredComponentsConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData, gitlabURL string) *GitlabPipelineRequiredComponentsResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineRequiredComponents",
		"controlVersion": ControlTypeGitlabPipelineOriginRequiredComponentsVersion,
	})
	l.Info("Start required components control")

	result := &GitlabPipelineRequiredComponentsResult{
		RequirementGroups: []ComponentGroupStatus{},
		Issues:            []RequiredComponentIssue{},
		OverriddenIssues:  []RequiredComponentOverriddenIssue{},
		Metrics:           GitlabPipelineRequiredComponentsMetrics{},
		Compliance:        0.0,
		Version:           ControlTypeGitlabPipelineOriginRequiredComponentsVersion,
		CiValid:           pipelineOriginData.CiValid,
		CiMissing:         pipelineOriginData.CiMissing,
		Skipped:           false,
	}

	if !p.Enabled {
		l.Info("Required components control is disabled, skipping")
		result.Skipped = true
		result.Compliance = 100.0
		return result
	}

	// Initialize metrics
	metrics := GitlabPipelineRequiredComponentsMetrics{}

	if !pipelineOriginData.CiValid {
		metrics.CiInvalid = 1
	}
	if pipelineOriginData.CiMissing {
		metrics.CiMissing = 1
	}

	// Initialize requirement groups
	result.RequirementGroups = make([]ComponentGroupStatus, len(p.RequiredGroups))
	for i, group := range p.RequiredGroups {
		result.RequirementGroups[i] = ComponentGroupStatus{
			GroupIndex:        i,
			RequiredOrigins:   group,
			FoundOrigins:      []string{},
			MissingOrigins:    make([]string, len(group)),
			OverriddenOrigins: []string{},
			IsFullySatisfied:  false,
		}
		// Initialize all as missing
		copy(result.RequirementGroups[i].MissingOrigins, group)
	}

	// Check all origins against all requirement groups
	for idx := range pipelineOriginData.Origins {
		origin := &pipelineOriginData.Origins[idx]

		if origin.OriginType != "component" {
			continue
		}

		cleanComponentPath := utils.CleanOriginPath(origin.GitlabIncludeOrigin.Location)

		for groupIdx := range result.RequirementGroups {
			group := &result.RequirementGroups[groupIdx]

			for _, requiredOrigin := range group.RequiredOrigins {
				cleanRequired := utils.CleanOriginPath(requiredOrigin)

				if cleanComponentPath == cleanRequired {
					overriddenJobs := getOriginOverriddenJobs(origin, pipelineOriginData)

					if len(overriddenJobs) > 0 {
						group.OverriddenOrigins = append(group.OverriddenOrigins, requiredOrigin)
						result.OverriddenIssues = append(result.OverriddenIssues, RequiredComponentOverriddenIssue{
							ComponentPath:  requiredOrigin,
							GroupIndex:     groupIdx,
							OverriddenJobs: overriddenJobs,
						})
					} else {
						group.FoundOrigins = append(group.FoundOrigins, requiredOrigin)
					}

					// Remove from missing list regardless of override status
					removeMissingComponent(group, requiredOrigin)

					l.WithFields(logrus.Fields{
						"component":      requiredOrigin,
						"groupIndex":     groupIdx,
						"overriddenJobs": overriddenJobs,
					}).Debug("Required component matched")

					break
				}
			}
		}
	}

	// Evaluate groups, populate issues
	anySatisfied := false
	for i := range result.RequirementGroups {
		group := &result.RequirementGroups[i]

		// Group is fully satisfied if no components are missing.
		// Overridden components are still "present" (imported) — they produce separate issues.
		group.IsFullySatisfied = len(group.MissingOrigins) == 0

		if group.IsFullySatisfied {
			anySatisfied = true
			metrics.SatisfiedGroups++
		}

		// Create issues for missing components
		for _, missing := range group.MissingOrigins {
			result.Issues = append(result.Issues, RequiredComponentIssue{
				ComponentPath: missing,
				GroupIndex:    i,
			})
		}
		// Note: overridden issues are created inline during origin matching
		// so we can capture the specific forbidden keys per component
	}

	// Calculate metrics
	metrics.TotalGroups = uint(len(p.RequiredGroups))
	metrics.AnySatisfiedGroup = anySatisfied

	// Calculate compliance using DNF logic
	// Found = 100%, Overridden = 50%, Missing = 0%
	if len(p.RequiredGroups) == 0 {
		result.Compliance = 100.0
	} else {
		maxScore := 0.0
		for _, group := range result.RequirementGroups {
			totalRequired := len(group.RequiredOrigins)
			if totalRequired == 0 {
				continue
			}

			found := len(group.FoundOrigins)
			overridden := len(group.OverriddenOrigins)

			score := (float64(found) + float64(overridden)*0.5) / float64(totalRequired)
			if score > maxScore {
				maxScore = score
			}
		}
		result.Compliance = maxScore * 100.0
	}

	result.Metrics = metrics

	l.WithFields(logrus.Fields{
		"totalGroups":      metrics.TotalGroups,
		"satisfiedGroups":  metrics.SatisfiedGroups,
		"compliance":       result.Compliance,
		"missingIssues":    len(result.Issues),
		"overriddenIssues": len(result.OverriddenIssues),
	}).Info("Required components control completed")

	return result
}

// removeMissingComponent removes a component from the missing list by path
func removeMissingComponent(group *ComponentGroupStatus, componentPath string) {
	cleanTarget := utils.CleanOriginPath(componentPath)
	for i := 0; i < len(group.MissingOrigins); i++ {
		cleanMissing := utils.CleanOriginPath(group.MissingOrigins[i])
		if cleanMissing == cleanTarget {
			group.MissingOrigins = append(group.MissingOrigins[:i], group.MissingOrigins[i+1:]...)
			return
		}
	}
}
