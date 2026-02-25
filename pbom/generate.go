package pbom

import (
	"time"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/utils"
)

// ImageComplianceData holds compliance results for images to enrich PBOM output
type ImageComplianceData struct {
	// ForbiddenTagImages maps image links to true if they use a forbidden tag
	ForbiddenTagImages map[string]bool
	// UnauthorizedImages maps image links to true if they are from unauthorized sources
	UnauthorizedImages map[string]bool
}

// IncludeOverrideData holds override detection results for includes.
// Key is the clean include location path (without version/instance prefix).
type IncludeOverrideData struct {
	// Overrides maps a clean include path to its overridden job details
	Overrides map[string][]utils.OverriddenJobDetail
}

// Generator creates PBOMs from pipeline analysis data
type Generator struct {
	projectPath       string
	projectID         int
	gitlabURL         string
	branch            string
	complianceData    *ImageComplianceData
	includeOverrides  *IncludeOverrideData
}

// NewGenerator creates a new PBOM generator
func NewGenerator(projectPath string, projectID int, gitlabURL, branch string) *Generator {
	return &Generator{
		projectPath: projectPath,
		projectID:   projectID,
		gitlabURL:   gitlabURL,
		branch:      branch,
	}
}

// WithComplianceData attaches compliance results so the PBOM includes authorized/forbiddenTag fields
func (g *Generator) WithComplianceData(data *ImageComplianceData) *Generator {
	g.complianceData = data
	return g
}

// WithIncludeOverrideData attaches override detection results so the PBOM marks overridden includes
func (g *Generator) WithIncludeOverrideData(data *IncludeOverrideData) *Generator {
	g.includeOverrides = data
	return g
}

// Generate creates a PBOM from pipeline data collections
func (g *Generator) Generate(
	imageData *collector.GitlabPipelineImageData,
	originData *collector.GitlabPipelineOriginData,
) *PBOM {
	pbom := &PBOM{
		PBOMVersion: Version,
		GeneratedAt: time.Now().UTC(),
		Project: ProjectInfo{
			Path:      g.projectPath,
			ID:        g.projectID,
			GitLabURL: g.gitlabURL,
			Branch:    g.branch,
		},
		ContainerImages: make([]ContainerImage, 0),
		Includes:        make([]Include, 0),
	}

	// Process container images
	if imageData != nil {
		pbom.ContainerImages = g.processImages(imageData)
	}

	// Process includes/origins
	if originData != nil {
		pbom.Includes = g.processIncludes(originData)
	}

	// Calculate summary
	pbom.Summary = g.calculateSummary(pbom)

	return pbom
}

// processImages extracts container image information from the image data collection
func (g *Generator) processImages(imageData *collector.GitlabPipelineImageData) []ContainerImage {
	// Group images by their full link to aggregate jobs
	imageJobMap := make(map[string][]string)
	imageInfoMap := make(map[string]collector.GitlabPipelineImageInfo)

	for _, img := range imageData.Images {
		imageJobMap[img.Link] = append(imageJobMap[img.Link], img.Job)
		// Store the first occurrence's parsed info
		if _, exists := imageInfoMap[img.Link]; !exists {
			imageInfoMap[img.Link] = img
		}
	}

	// Convert to PBOM format
	images := make([]ContainerImage, 0, len(imageJobMap))
	for link, jobs := range imageJobMap {
		info := imageInfoMap[link]
		img := ContainerImage{
			Image:    link,
			Registry: info.Registry,
			Name:     info.Name,
			Tag:      info.Tag,
			Jobs:     uniqueStrings(jobs),
		}

		// Enrich with compliance data if available
		if g.complianceData != nil {
			forbidden, hasForbidden := g.complianceData.ForbiddenTagImages[link]
			if hasForbidden {
				img.ForbiddenTag = &forbidden
			}
			unauthorized, hasUnauthorized := g.complianceData.UnauthorizedImages[link]
			if hasUnauthorized {
				// Authorized is the inverse of unauthorized
				authorized := !unauthorized
				img.Authorized = &authorized
			}
		}

		images = append(images, img)
	}

	return images
}

// processIncludes extracts include information from the origin data collection
func (g *Generator) processIncludes(originData *collector.GitlabPipelineOriginData) []Include {
	includes := make([]Include, 0, len(originData.Origins))

	for _, origin := range originData.Origins {
		// Skip hardcoded origins (they're not includes)
		if origin.OriginType == "hardcoded" {
			continue
		}

		inc := Include{
			Type:     origin.OriginType,
			Location: origin.GitlabIncludeOrigin.Location,
			Project:  origin.GitlabIncludeOrigin.Project,
			Version:  origin.Version,
			Nested:   origin.Nested,
		}

		// Add version info if available
		if origin.FromPlumber {
			inc.LatestVersion = origin.PlumberOrigin.LatestVersion
			upToDate := origin.UpToDate
			inc.UpToDate = &upToDate
		}

		// Add component-specific info
		if origin.OriginType == "component" {
			inc.ComponentName = origin.GitlabComponent.ComponentName
			inc.FromCatalog = origin.FromGitlabCatalog

			if origin.FromGitlabCatalog {
				inc.LatestVersion = origin.GitlabComponent.ComponentLatestVersion
				upToDate := origin.UpToDate
				inc.UpToDate = &upToDate
			}
		}

		// Enrich with override data if available
		if g.includeOverrides != nil {
			cleanPath := utils.CleanOriginPath(inc.Location)
			if jobs, found := g.includeOverrides.Overrides[cleanPath]; found {
				inc.Overridden = true
				inc.OverriddenJobs = jobs
			}
		}

		includes = append(includes, inc)
	}

	return includes
}

// calculateSummary computes aggregate statistics for the PBOM
func (g *Generator) calculateSummary(pbom *PBOM) Summary {
	summary := Summary{
		TotalImages:   len(pbom.ContainerImages),
		TotalIncludes: len(pbom.Includes),
	}

	// Count unique registries
	registries := make(map[string]struct{})
	for _, img := range pbom.ContainerImages {
		if img.Registry != "" {
			registries[img.Registry] = struct{}{}
		}
	}
	summary.UniqueRegistries = len(registries)

	// Count include types
	for _, inc := range pbom.Includes {
		switch inc.Type {
		case "component":
			summary.Components++
		case "project":
			summary.ProjectIncludes++
		case "local":
			summary.LocalIncludes++
		case "remote":
			summary.RemoteIncludes++
		case "template":
			summary.Templates++
		}
	}

	return summary
}

// uniqueStrings returns a slice with duplicate strings removed
func uniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(input))

	for _, s := range input {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}

	return result
}
