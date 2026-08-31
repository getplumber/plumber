package pbom

import (
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
)

// BuildImageComplianceData extracts per-image compliance flags from an
// AnalysisResult into the lookup map consumed by the PBOM generator.
func BuildImageComplianceData(result *control.AnalysisResult) *ImageComplianceData {
	data := &ImageComplianceData{
		ForbiddenTagImages: make(map[string]bool),
		UnauthorizedImages: make(map[string]bool),
	}
	if result.PipelineImageData == nil {
		return data
	}
	imagesByJob := make(map[string]string, len(result.PipelineImageData.Images))
	for _, img := range result.PipelineImageData.Images {
		imagesByJob[img.Job] = img.Link
		// Seeding false is what makes "no finding for this image" mean
		// "compliant". That is right for an image the rules judged and wrong
		// for one they abstained on: a reference that never rendered to a
		// literal was never checked against any registry or tag, so
		// publishing it as authorized states a fact the run does not have.
		//
		// Leaving it unseeded uses the tri-state the generator already has -
		// an absent key leaves the pointer nil and the field out of the
		// document - so a consumer sees "not assessed" rather than "fine".
		if img.Unresolved {
			continue
		}
		data.ForbiddenTagImages[img.Link] = false
		data.UnauthorizedImages[img.Link] = false
	}
	for _, f := range result.Findings {
		link, ok := imagesByJob[f.Job]
		if !ok {
			continue
		}
		switch control.ErrorCode(f.Code) {
		case control.CodeImageForbiddenTag, control.CodeImageNotPinnedByDigest:
			data.ForbiddenTagImages[link] = true
		case control.CodeImageUnauthorizedSource:
			data.UnauthorizedImages[link] = true
		}
	}
	return data
}

// BuildIncludeOverrideData extracts include-override detection results from
// an AnalysisResult into the lookup map consumed by the PBOM generator.
func BuildIncludeOverrideData(result *control.AnalysisResult) *IncludeOverrideData {
	data := &IncludeOverrideData{
		Overrides: make(map[string][]utils.OverriddenJobDetail),
	}
	if result.PipelineOriginData == nil {
		return data
	}
	for idx := range result.PipelineOriginData.Origins {
		o := &result.PipelineOriginData.Origins[idx]
		location := o.GitlabIncludeOrigin.Location
		if location == "" {
			location = o.GitlabComponent.ComponentIncludePath
		}
		if location == "" {
			continue
		}
		key := utils.CleanOriginPath(location)
		irJobs := gitlab.CollectOverriddenJobs(o, result.PipelineOriginData)
		if len(irJobs) == 0 {
			continue
		}
		details := make([]utils.OverriddenJobDetail, 0, len(irJobs))
		for _, j := range irJobs {
			details = append(details, utils.OverriddenJobDetail{JobName: j.Name, OverriddenKeys: j.Keys})
		}
		data.Overrides[key] = details
	}
	return data
}

// BuildPlumberScoreSummary converts a PlumberScoreResult into the PBOM
// PlumberScoreSummary shape. Returns nil when scoreMode is false or score
// is nil (no score in output).
func BuildPlumberScoreSummary(score *control.PlumberScoreResult, scoreMode bool) *PlumberScoreSummary {
	if score == nil || !scoreMode {
		return nil
	}
	return &PlumberScoreSummary{
		ProfileID:            score.ProfileID,
		RawPoints:            score.RawPoints,
		FinalPoints:          score.FinalPoints,
		Score:                score.Score,
		CriticalMalusApplied: score.CriticalMalusApplied,
		CriticalMalusMax:     score.CriticalMalusMax,
		Counts: PlumberScoreCounts{
			Critical: score.Counts.Critical,
			High:     score.Counts.High,
			Medium:   score.Counts.Medium,
			Low:      score.Counts.Low,
		},
	}
}

// normalizeIRImageRef builds the canonical image reference string from an
// ir.Image, matching the format pbom uses as map keys.
func normalizeIRImageRef(img ir.Image) string {
	if img.Name == "" {
		return ""
	}
	ref := img.Name
	if img.Registry != "" && len(ref) < len(img.Registry)+1 {
		ref = img.Registry + "/" + ref
	}
	if img.Digest != "" {
		return ref + "@" + img.Digest
	}
	if img.Tag != "" {
		return ref + ":" + img.Tag
	}
	return ref
}

// collectGitHubPinnedImages walks the normalized pipeline IR and records every
// image that is pinned by digest into out.
func collectGitHubPinnedImages(result *control.AnalysisResult, out *GitHubComplianceData) {
	if result.GitHubPipeline == nil {
		return
	}
	for _, j := range result.GitHubPipeline.Jobs {
		if j.Image != nil && j.Image.Digest != "" {
			out.ImagesPinnedByDigest[normalizeIRImageRef(*j.Image)] = true
		}
		for _, s := range j.Services {
			if s.Digest != "" {
				out.ImagesPinnedByDigest[normalizeIRImageRef(s)] = true
			}
		}
	}
}

func parseAdvisoryIDs(advRaw []any) []string {
	ids := make([]string, 0, len(advRaw))
	for _, a := range advRaw {
		if s, ok := a.(string); ok && s != "" {
			ids = append(ids, s)
		}
	}
	return ids
}

func applyVulnerableActionCompliance(uses string, data map[string]any, out *GitHubComplianceData) {
	out.VulnerableActions[uses] = true
	if advRaw, ok := data["advisories"].([]any); ok {
		if ids := parseAdvisoryIDs(advRaw); len(ids) > 0 {
			out.ActionAdvisories[uses] = ids
		}
	}
}

func applyGitHubFindingToCompliance(code string, data map[string]any, out *GitHubComplianceData) {
	switch code {
	case string(control.CodeImageForbiddenTag):
		if v, ok := data["link"].(string); ok && v != "" {
			out.ForbiddenTagImages[v] = true
		}
	case string(control.CodeActionUnpinned):
		if v, ok := data["uses"].(string); ok && v != "" {
			out.UnpinnedActions[v] = true
		}
	case string(control.CodeActionArchivedRepo):
		if v, ok := data["uses"].(string); ok && v != "" {
			out.ArchivedActions[v] = true
		}
	case string(control.CodeKnownVulnerableAction):
		if v, ok := data["uses"].(string); ok && v != "" {
			applyVulnerableActionCompliance(v, data, out)
		}
	}
}

// BuildGitHubPBOMCompliance walks Findings and the IR to assemble the
// per-image / per-action compliance lookup the PBOM generator uses to enrich
// entries.
func BuildGitHubPBOMCompliance(result *control.AnalysisResult) *GitHubComplianceData {
	if result == nil {
		return nil
	}
	out := &GitHubComplianceData{
		ForbiddenTagImages:   map[string]bool{},
		ImagesPinnedByDigest: map[string]bool{},
		UnpinnedActions:      map[string]bool{},
		ArchivedActions:      map[string]bool{},
		VulnerableActions:    map[string]bool{},
		ActionAdvisories:     map[string][]string{},
	}
	for _, f := range result.Findings {
		applyGitHubFindingToCompliance(f.Code, f.Data, out)
	}
	collectGitHubPinnedImages(result, out)
	return out
}
