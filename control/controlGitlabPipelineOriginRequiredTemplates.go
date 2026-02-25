package control

import (
	"path"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabPipelineOriginRequiredTemplatesVersion = "0.2.0"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineRequiredTemplatesConf holds the configuration for required templates check
type GitlabPipelineRequiredTemplatesConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`
	// DNF (Disjunctive Normal Form) format:
	// Outer array = OR (at least one group must be satisfied)
	// Inner array = AND (all templates in group must be present)
	// Example: [["go", "helm"], ["go_helm_unified"]] means:
	//   "must have (go AND helm) OR (go_helm_unified)"
	RequiredGroups [][]string `json:"requiredGroups"`
}

// GetConf loads configuration from PlumberConfig
func (p *GitlabPipelineRequiredTemplatesConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	config := plumberConfig.GetPipelineMustIncludeTemplateConfig()
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
	}).Debug("pipelineMustIncludeTemplate control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// TemplateGroupStatus tracks the status of a single requirement group (AND clause)
type TemplateGroupStatus struct {
	GroupIndex        int      `json:"groupIndex"`        // Which requirement group (0-based)
	RequiredOrigins   []string `json:"requiredOrigins"`   // Templates required in this group
	FoundOrigins      []string `json:"foundOrigins"`      // Templates found and not overridden
	MissingOrigins    []string `json:"missingOrigins"`    // Templates missing from this group
	OverriddenOrigins []string `json:"overriddenOrigins"` // Templates found but overridden with forbidden keywords
	IsFullySatisfied  bool     `json:"isFullySatisfied"`  // All templates in group present (not missing)
}

// GitlabPipelineRequiredTemplatesMetrics holds metrics about required templates
type GitlabPipelineRequiredTemplatesMetrics struct {
	TotalGroups       uint `json:"totalGroups"`       // Total number of requirement groups
	SatisfiedGroups   uint `json:"satisfiedGroups"`   // Number of fully satisfied groups
	AnySatisfiedGroup bool `json:"anySatisfiedGroup"` // True if at least one group satisfied
	CiInvalid         uint `json:"ciInvalid"`
	CiMissing         uint `json:"ciMissing"`
}

// GitlabPipelineRequiredTemplatesResult holds the result of the required templates control
type GitlabPipelineRequiredTemplatesResult struct {
	RequirementGroups []TemplateGroupStatus                  `json:"requirementGroups"`
	Issues            []RequiredTemplateIssue                `json:"issues"`
	OverriddenIssues  []RequiredTemplateOverriddenIssue      `json:"overriddenIssues"`
	Metrics           GitlabPipelineRequiredTemplatesMetrics `json:"metrics"`
	Compliance        float64                                `json:"compliance"`
	Version           string                                 `json:"version"`
	CiValid           bool                                   `json:"ciValid"`
	CiMissing         bool                                   `json:"ciMissing"`
	Skipped           bool                                   `json:"skipped"`
	Error             string                                 `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// RequiredTemplateIssue represents an issue with a missing required template
type RequiredTemplateIssue struct {
	TemplatePath string `json:"templatePath"`
	GroupIndex   int    `json:"groupIndex"`
}

// RequiredTemplateOverriddenIssue represents an issue where a required template
// is imported but its jobs are overridden with forbidden keywords
type RequiredTemplateOverriddenIssue struct {
	TemplatePath   string                `json:"templatePath"`
	GroupIndex     int                   `json:"groupIndex"`
	OverriddenJobs []utils.OverriddenJobDetail `json:"overriddenJobs"`
}

///////////////////////
// Control functions //
///////////////////////

// pathsMatch checks if two paths match (direct or normalized)
func pathsMatch(path1, path2 string) bool {
	if path1 == path2 {
		return true
	}
	return path.Clean(path1) == path.Clean(path2)
}


// templateMatchesRequired checks if a found template path matches a required template path
func templateMatchesRequired(foundPath, requiredPath string) bool {
	if pathsMatch(foundPath, requiredPath) {
		return true
	}
	if strings.HasSuffix(foundPath, "/"+requiredPath) || strings.HasSuffix(foundPath, requiredPath) {
		return true
	}
	return false
}

// Run executes the required templates control
func (p *GitlabPipelineRequiredTemplatesConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabPipelineRequiredTemplatesResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineRequiredTemplates",
		"controlVersion": ControlTypeGitlabPipelineOriginRequiredTemplatesVersion,
	})
	l.Info("Start required templates control")

	result := &GitlabPipelineRequiredTemplatesResult{
		RequirementGroups: []TemplateGroupStatus{},
		Issues:            []RequiredTemplateIssue{},
		OverriddenIssues:  []RequiredTemplateOverriddenIssue{},
		Metrics:           GitlabPipelineRequiredTemplatesMetrics{},
		Compliance:        0.0,
		Version:           ControlTypeGitlabPipelineOriginRequiredTemplatesVersion,
		CiValid:           pipelineOriginData.CiValid,
		CiMissing:         pipelineOriginData.CiMissing,
		Skipped:           false,
	}

	if !p.Enabled {
		l.Info("Required templates control is disabled, skipping")
		result.Skipped = true
		result.Compliance = 100.0
		return result
	}

	// Initialize metrics
	metrics := GitlabPipelineRequiredTemplatesMetrics{}

	if !pipelineOriginData.CiValid {
		metrics.CiInvalid = 1
	}
	if pipelineOriginData.CiMissing {
		metrics.CiMissing = 1
	}

	// Initialize requirement groups
	result.RequirementGroups = make([]TemplateGroupStatus, len(p.RequiredGroups))
	for i, group := range p.RequiredGroups {
		result.RequirementGroups[i] = TemplateGroupStatus{
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

		// Skip hardcoded origins
		if origin.OriginType == originHardcoded {
			continue
		}

		// Determine the template path from the origin
		var templatePaths []string
		if origin.FromPlumber && origin.PlumberOrigin.Path != "" {
			templatePaths = append(templatePaths, origin.PlumberOrigin.Path)
		}
		if origin.OriginType == "project" && origin.GitlabIncludeOrigin.Location != "" {
			templatePath := origin.GitlabIncludeOrigin.Location
			templatePath = strings.TrimSuffix(templatePath, ".yml")
			templatePath = strings.TrimSuffix(templatePath, ".yaml")
			templatePaths = append(templatePaths, templatePath)
		}

		if len(templatePaths) == 0 {
			continue
		}

		for groupIdx := range result.RequirementGroups {
			group := &result.RequirementGroups[groupIdx]

			for _, requiredOrigin := range group.RequiredOrigins {
				matched := false
				for _, foundPath := range templatePaths {
					if templateMatchesRequired(foundPath, requiredOrigin) {
						matched = true
						break
					}
				}

				if matched {
					overriddenJobs := getOriginOverriddenJobs(origin, pipelineOriginData)

					if len(overriddenJobs) > 0 {
						group.OverriddenOrigins = append(group.OverriddenOrigins, requiredOrigin)
						result.OverriddenIssues = append(result.OverriddenIssues, RequiredTemplateOverriddenIssue{
							TemplatePath:   requiredOrigin,
							GroupIndex:     groupIdx,
							OverriddenJobs: overriddenJobs,
						})
					} else {
						group.FoundOrigins = append(group.FoundOrigins, requiredOrigin)
					}

					// Remove from missing list regardless of override status
					removeMissingTemplate(group, requiredOrigin)

					l.WithFields(logrus.Fields{
						"template":       requiredOrigin,
						"groupIndex":     groupIdx,
						"overriddenJobs": overriddenJobs,
					}).Debug("Required template matched")

					break
				}
			}
		}
	}

	// Evaluate groups, populate issues
	anySatisfied := false
	for i := range result.RequirementGroups {
		group := &result.RequirementGroups[i]

		// Group is fully satisfied if no templates are missing.
		// Overridden templates are still "present" (imported) — they produce separate issues.
		group.IsFullySatisfied = len(group.MissingOrigins) == 0

		if group.IsFullySatisfied {
			anySatisfied = true
			metrics.SatisfiedGroups++
		}

		// Create issues for missing templates
		for _, missing := range group.MissingOrigins {
			result.Issues = append(result.Issues, RequiredTemplateIssue{
				TemplatePath: missing,
				GroupIndex:   i,
			})
		}
		// Note: overridden issues are created inline during origin matching
		// so we can capture the specific forbidden keys per template
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
	}).Info("Required templates control completed")

	return result
}

// removeMissingTemplate removes a template from the missing list by path
func removeMissingTemplate(group *TemplateGroupStatus, templatePath string) {
	for i := 0; i < len(group.MissingOrigins); i++ {
		if pathsMatch(group.MissingOrigins[i], templatePath) {
			group.MissingOrigins = append(group.MissingOrigins[:i], group.MissingOrigins[i+1:]...)
			return
		}
	}
}
