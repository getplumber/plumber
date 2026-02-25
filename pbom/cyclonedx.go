package pbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CycloneDX spec version we're generating
const CycloneDXSpecVersion = "1.5"

// CycloneDX represents a CycloneDX SBOM
// Spec: https://cyclonedx.org/docs/1.5/json/
type CycloneDX struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Metadata     CycloneDXMetadata    `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
}

// CycloneDXMetadata contains metadata about the BOM
type CycloneDXMetadata struct {
	Timestamp  string              `json:"timestamp"`
	Tools      []CycloneDXTool     `json:"tools,omitempty"`
	Component  *CycloneDXComponent `json:"component,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

// CycloneDXTool describes a tool used to create the BOM
type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CycloneDXComponent represents a component in the BOM
type CycloneDXComponent struct {
	Type        string              `json:"type"`
	BOMRef      string              `json:"bom-ref,omitempty"`
	Name        string              `json:"name"`
	Version     string              `json:"version,omitempty"`
	Description string              `json:"description,omitempty"`
	Purl        string              `json:"purl,omitempty"`
	Properties  []CycloneDXProperty `json:"properties,omitempty"`
}

// CycloneDXProperty represents a name-value property
type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ToCycloneDX converts a PBOM to CycloneDX format
func (p *PBOM) ToCycloneDX(plumberVersion string) *CycloneDX {
	cdx := &CycloneDX{
		BOMFormat:    "CycloneDX",
		SpecVersion:  CycloneDXSpecVersion,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: p.GeneratedAt.Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{
					Vendor:  "Plumber",
					Name:    "plumber",
					Version: plumberVersion,
				},
			},
			// Add the project as the main component
			Component: &CycloneDXComponent{
				Type:    "application",
				BOMRef:  fmt.Sprintf("project:%s", p.Project.Path),
				Name:    p.Project.Path,
				Version: p.Project.Branch,
				Properties: []CycloneDXProperty{
					{Name: "plumber:gitlab-url", Value: p.Project.GitLabURL},
					{Name: "plumber:project-id", Value: fmt.Sprintf("%d", p.Project.ID)},
				},
			},
		},
		Components: make([]CycloneDXComponent, 0, len(p.ContainerImages)+len(p.Includes)),
	}

	// Add container images as components
	for i, img := range p.ContainerImages {
		component := CycloneDXComponent{
			Type:    "container",
			BOMRef:  fmt.Sprintf("container:%d", i),
			Name:    img.Name,
			Version: img.Tag,
			Purl:    buildDockerPurl(img),
			Properties: []CycloneDXProperty{
				{Name: "plumber:registry", Value: img.Registry},
				{Name: "plumber:full-image", Value: img.Image},
				{Name: "plumber:jobs", Value: strings.Join(img.Jobs, ",")},
			},
		}

		// Add compliance properties if available
		if img.Authorized != nil {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:authorized", Value: fmt.Sprintf("%t", *img.Authorized)})
		}
		if img.ForbiddenTag != nil {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:forbidden-tag", Value: fmt.Sprintf("%t", *img.ForbiddenTag)})
		}

		cdx.Components = append(cdx.Components, component)
	}

	// Add includes as components
	for i, inc := range p.Includes {
		component := CycloneDXComponent{
			Type:    mapIncludeTypeToCycloneDX(inc.Type),
			BOMRef:  fmt.Sprintf("include:%d", i),
			Name:    inc.Location,
			Version: inc.Version,
			Purl:    buildIncludePurl(inc),
			Properties: []CycloneDXProperty{
				{Name: "plumber:include-type", Value: inc.Type},
			},
		}

		// Add optional properties
		if inc.Project != "" {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:project", Value: inc.Project})
		}
		if inc.LatestVersion != "" {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:latest-version", Value: inc.LatestVersion})
		}
		if inc.UpToDate != nil {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:up-to-date", Value: fmt.Sprintf("%t", *inc.UpToDate)})
		}
		if inc.ComponentName != "" {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:component-name", Value: inc.ComponentName})
		}
		if inc.FromCatalog {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:from-catalog", Value: "true"})
		}
		if inc.Nested {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:nested", Value: "true"})
		}
		if inc.Overridden {
			component.Properties = append(component.Properties,
				CycloneDXProperty{Name: "plumber:overridden", Value: "true"})
			for _, job := range inc.OverriddenJobs {
				component.Properties = append(component.Properties,
					CycloneDXProperty{
						Name:  "plumber:overridden-job",
						Value: fmt.Sprintf("%s:%s", job.JobName, strings.Join(job.OverriddenKeys, ",")),
					})
			}
		}

		cdx.Components = append(cdx.Components, component)
	}

	return cdx
}

// buildDockerPurl creates a Package URL for a container image
// Format: pkg:docker/namespace/name@version?repository_url=registry
// See: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#docker
func buildDockerPurl(img ContainerImage) string {
	name := img.Name

	// For Docker Hub official images, the namespace is "library"
	if img.Registry == "docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}

	// Build the base purl
	purl := fmt.Sprintf("pkg:docker/%s", name)
	if img.Tag != "" {
		purl += "@" + img.Tag
	}

	// For non-Docker Hub registries, add repository_url qualifier
	if img.Registry != "" && img.Registry != "docker.io" && img.Registry != "unknown" {
		purl += "?repository_url=" + img.Registry
	}

	return purl
}

// buildIncludePurl creates a Package URL for a GitLab include
// Using pkg:generic since GitLab includes aren't a standard purl type
func buildIncludePurl(inc Include) string {
	// Components use a specific format
	if inc.Type == "component" {
		purl := fmt.Sprintf("pkg:gitlab/%s", strings.TrimPrefix(inc.Location, "gitlab.com/"))
		if inc.Version != "" {
			purl += "@" + inc.Version
		}
		return purl
	}

	// For project includes
	if inc.Type == "project" && inc.Project != "" {
		purl := fmt.Sprintf("pkg:gitlab/%s/%s", inc.Project, inc.Location)
		if inc.Version != "" {
			purl += "@" + inc.Version
		}
		return purl
	}

	// For other types, use generic
	purl := fmt.Sprintf("pkg:generic/%s", sanitizeForPurl(inc.Location))
	if inc.Version != "" {
		purl += "@" + inc.Version
	}
	return purl
}

// mapIncludeTypeToCycloneDX maps our include types to CycloneDX component types
func mapIncludeTypeToCycloneDX(includeType string) string {
	switch includeType {
	case "component":
		return "library" // GitLab CI/CD components are reusable libraries
	case "template":
		return "library" // GitLab CI templates are reusable pipeline libraries
	case "local":
		return "file"
	case "remote":
		return "file"
	case "project":
		return "file"
	default:
		return "data"
	}
}

// sanitizeForPurl cleans a string for use in a Package URL
func sanitizeForPurl(s string) string {
	// Replace characters that aren't allowed in purl
	s = strings.ReplaceAll(s, "://", "/")
	s = strings.ReplaceAll(s, " ", "-")
	return s
}
