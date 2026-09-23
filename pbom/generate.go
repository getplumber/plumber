package pbom

import (
	"sort"
	"strings"
	"time"

	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
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
	projectPath    string
	projectID      int
	gitlabURL      string
	branch         string
	complianceData *ImageComplianceData
	// suppressVerdicts drops the collected-but-verdict-bearing include
	// fields; see WithoutComplianceVerdicts.
	suppressVerdicts bool
	includeOverrides *IncludeOverrideData
	githubData       *GitHubComplianceData
	commitSHA        string
	ref              string
	// jobs is the analyzed pipeline's job list, attached by WithJobResources.
	// nil when the caller never attached one, which is what keeps the jobs
	// key out of the document entirely.
	jobs []ir.Job
}

// WithJobResources attaches the analyzed pipeline's jobs so the document can
// name each job's service images and runner tags.
//
// The jobs come from the normalized pipeline model, already parsed: the CLI
// is the one parser of CI configuration (invariant I1), and nothing here
// reads YAML or splits an image reference a second time.
func (g *Generator) WithJobResources(jobs []ir.Job) *Generator {
	g.jobs = jobs
	return g
}

// WithCommit attaches the resolved analyzed commit and its branch/tag so the
// PBOM names the exact code it describes (#443).
func (g *Generator) WithCommit(sha, ref string) *Generator {
	g.commitSHA = sha
	g.ref = ref
	return g
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
// WithoutComplianceVerdicts suppresses the include fields that state a
// CONTROL'S CONCLUSION rather than what was collected. It backs
// --no-controls.
//
// `UpToDate` is the one that matters: unlike the image flags it is computed
// during data collection (the origin collector probes the upstream ref), so
// it survives even when no policy is evaluated, and it is exactly what
// includesMustBeUpToDate reports. `LatestVersion` is kept: the upstream
// version is a collected fact and asserts nothing on its own.
func (g *Generator) WithoutComplianceVerdicts() *Generator {
	g.suppressVerdicts = true
	return g
}

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
	imageData *gitlab.GitlabPipelineImageData,
	originData *gitlab.GitlabPipelineOriginData,
) *PBOM {
	pbom := &PBOM{
		PBOMVersion: Version,
		GeneratedAt: time.Now().UTC(),
		Project: ProjectInfo{
			Path:      g.projectPath,
			ID:        g.projectID,
			Provider:  "gitlab",
			URL:       g.gitlabURL,
			GitLabURL: g.gitlabURL,
			Branch:    g.branch,
			CommitSHA: g.commitSHA,
			Ref:       g.ref,
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

	// Per-job resources (services, runner tags). Read off the pipeline model
	// rather than the collections above, because neither collection carries
	// them: images are pipeline-level and includes are not jobs.
	pbom.Jobs = g.processJobResources()

	// Calculate summary
	pbom.Summary = g.calculateSummary(pbom)

	return pbom
}

// processJobResources projects the attached pipeline jobs onto the document's
// per-job entries, keeping only the jobs that actually carry a service or a
// runner tag: a job that asks for neither is not a dependency of anything and
// would only pad the bill of materials.
//
// Sorted by name so two runs over the same pipeline produce the same
// document, which is what lets a consumer replace a project's entries as one
// set without seeing a spurious change.
func (g *Generator) processJobResources() []JobResources {
	if len(g.jobs) == 0 {
		return nil
	}
	out := make([]JobResources, 0, len(g.jobs))
	for _, j := range g.jobs {
		if len(j.Services) == 0 && len(j.Tags) == 0 {
			continue
		}
		entry := JobResources{Name: j.Name}
		for _, svc := range j.Services {
			ref := containerImageRefFrom(svc)
			// A blank services: entry (an empty string, or a {name: ""} map)
			// reaches here as a zero-valued image. It names no dependency,
			// and a consumer that keys a resource on the reference would key
			// one on nothing at all. The GitHub path already skips such a
			// reference; so does this one.
			if ref.Image == "" {
				continue
			}
			entry.Services = append(entry.Services, ref)
		}
		if len(j.Tags) > 0 {
			entry.RunnerTags = append([]string(nil), j.Tags...)
		}
		// The job may have had nothing but blank services, in which case it
		// is back to carrying nothing and is not listed.
		if len(entry.Services) == 0 && len(entry.RunnerTags) == 0 {
			continue
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// containerImageRefFrom projects one pipeline-model image onto the document's
// reference shape. Registry, name, tag and digest are copied as the collector
// parsed them; Image joins them back so a consumer has the whole reference
// without having to join them itself.
//
// The registry is prefixed only when the name does not already carry it,
// which is what keeps a reference the collector already normalised from
// growing a duplicated host.
func containerImageRefFrom(img ir.Image) ContainerImageRef {
	out := ContainerImageRef{
		Registry:   img.Registry,
		Name:       img.Name,
		Tag:        img.Tag,
		Digest:     img.Digest,
		Unresolved: img.Unresolved,
	}
	if img.Name == "" {
		return out
	}
	ref := img.Name
	if img.Registry != "" && !strings.HasPrefix(ref, img.Registry+"/") {
		ref = img.Registry + "/" + ref
	}
	switch {
	case img.Digest != "":
		ref += "@" + img.Digest
	case img.Tag != "":
		ref += ":" + img.Tag
	}
	out.Image = ref
	return out
}

// processImages extracts container image information from the image data collection
func (g *Generator) processImages(imageData *gitlab.GitlabPipelineImageData) []ContainerImage {
	// Group images by their full link to aggregate jobs
	imageJobMap := make(map[string][]string)
	imageInfoMap := make(map[string]gitlab.GitlabPipelineImageInfo)

	for _, img := range imageData.Images {
		imageJobMap[img.Link] = append(imageJobMap[img.Link], img.Job)
		// Store the first occurrence's parsed info
		if _, exists := imageInfoMap[img.Link]; !exists {
			imageInfoMap[img.Link] = img
		}
	}

	// Convert to PBOM format in stable order (sorted image link — map iteration is not deterministic).
	links := make([]string, 0, len(imageJobMap))
	for link := range imageJobMap {
		links = append(links, link)
	}
	sort.Strings(links)

	images := make([]ContainerImage, 0, len(links))
	for _, link := range links {
		jobs := imageJobMap[link]
		info := imageInfoMap[link]
		img := ContainerImage{
			Image:      link,
			Registry:   info.Registry,
			Name:       info.Name,
			Tag:        info.Tag,
			Jobs:       uniqueSortedStrings(jobs),
			Unresolved: info.Unresolved,
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
func (g *Generator) processIncludes(originData *gitlab.GitlabPipelineOriginData) []Include {
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

		// Add version info if available. FromPlumber only says the include's
		// template identity is known from its ref; a version comparison
		// needs the upstream listing too, which can fail (a private source
		// project) independently of the identity. Gate on LatestVersion so
		// a failed listing reports "unknown", not a fabricated verdict.
		if origin.FromPlumber && origin.PlumberOrigin.LatestVersion != "" {
			inc.LatestVersion = origin.PlumberOrigin.LatestVersion
			if !g.suppressVerdicts {
				upToDate := origin.UpToDate
				inc.UpToDate = &upToDate
			}
		}

		// Add component-specific info
		if origin.OriginType == "component" {
			inc.ComponentName = origin.GitlabComponent.ComponentName
			inc.FromCatalog = origin.FromGitlabCatalog

			if origin.FromGitlabCatalog {
				inc.LatestVersion = origin.GitlabComponent.ComponentLatestVersion
				if !g.suppressVerdicts {
					upToDate := origin.UpToDate
					inc.UpToDate = &upToDate
				}
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
		case "action":
			summary.Actions++
		case "reusableWorkflow":
			summary.ReusableWorkflows++
		}
	}

	return summary
}

// uniqueSortedStrings removes duplicates and sorts for stable PBOM JSON.
func uniqueSortedStrings(input []string) []string {
	seen := make(map[string]struct{})
	for _, s := range input {
		seen[s] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
