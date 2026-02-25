// Package pbom provides Pipeline Bill of Materials (PBOM) generation.
//
// A PBOM is an inventory of all dependencies used in a CI/CD pipeline,
// including container images and includes (components, templates, remote files).
// Unlike an SBOM (Software Bill of Materials) which tracks application dependencies,
// a PBOM tracks pipeline infrastructure dependencies.
package pbom

import (
	"time"

	"github.com/getplumber/plumber/utils"
)

// Version is the current PBOM specification version
const Version = "1.0.0"

// PBOM represents a Pipeline Bill of Materials - an inventory of all
// dependencies used in a CI/CD pipeline.
type PBOM struct {
	// Metadata
	PBOMVersion string    `json:"pbomVersion"`
	GeneratedAt time.Time `json:"generatedAt"`

	// Project information
	Project ProjectInfo `json:"project"`

	// Pipeline dependencies
	ContainerImages []ContainerImage `json:"containerImages"`
	Includes        []Include        `json:"includes"`

	// Summary statistics
	Summary Summary `json:"summary"`
}

// ProjectInfo contains information about the analyzed project
type ProjectInfo struct {
	Path      string `json:"path"`
	ID        int    `json:"id,omitempty"`
	GitLabURL string `json:"gitlabUrl"`
	Branch    string `json:"branch,omitempty"`
}

// ContainerImage represents a container image used in the pipeline
type ContainerImage struct {
	// Full image reference (e.g., "docker.io/library/golang:1.22-alpine")
	Image string `json:"image"`

	// Parsed components
	Registry string `json:"registry"`
	Name     string `json:"name"`
	Tag      string `json:"tag,omitempty"`

	// Usage context
	Jobs []string `json:"jobs"`

	// Compliance status (from analysis, if available)
	Authorized    *bool `json:"authorized,omitempty"`
	ForbiddenTag  *bool `json:"forbiddenTag,omitempty"`
}

// Include represents an include/component/template used in the pipeline
type Include struct {
	// Type of include: "component", "project", "local", "remote", "template"
	Type string `json:"type"`

	// Location/path of the include
	Location string `json:"location"`

	// For project includes
	Project string `json:"project,omitempty"`

	// Version information
	Version       string `json:"version,omitempty"`
	LatestVersion string `json:"latestVersion,omitempty"`
	UpToDate      *bool  `json:"upToDate,omitempty"`

	// For components from GitLab CI/CD Catalog
	ComponentName string `json:"componentName,omitempty"`
	FromCatalog   bool   `json:"fromCatalog,omitempty"`

	// Whether this is a nested include (included by another include)
	Nested bool `json:"nested,omitempty"`

	// Override information (populated from control results)
	Overridden     bool                       `json:"overridden,omitempty"`
	OverriddenJobs []utils.OverriddenJobDetail `json:"overriddenJobs,omitempty"`
}

// Summary provides aggregate statistics about the pipeline dependencies
type Summary struct {
	// Image counts
	TotalImages      int `json:"totalImages"`
	UniqueRegistries int `json:"uniqueRegistries"`

	// Include counts
	TotalIncludes   int `json:"totalIncludes"`
	Components      int `json:"components"`
	ProjectIncludes int `json:"projectIncludes"`
	LocalIncludes   int `json:"localIncludes"`
	RemoteIncludes  int `json:"remoteIncludes"`
	Templates       int `json:"templates"`
}
