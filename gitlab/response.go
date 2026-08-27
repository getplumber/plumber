package gitlab

import "time"

// GraphQL page info
type PageInfo struct {
	EndCursor   string
	HasNextPage bool
}

// Gitlab GraphQL response of query to get all projects of a group with metadata
type GroupProjectsResponse struct {
	Group struct {
		Projects struct {
			Nodes    []ProjectMetadataNode
			PageInfo PageInfo
		}
	}
}
type ProjectMetadataNode struct {
	ID                    string
	CreatedAt             time.Time
	NameWithNamespace     string
	FullPath              string
	Visibility            string
	CiConfigPathOrDefault string
	Repository            struct {
		RootRef string
		Tree    struct {
			LastCommit struct {
				Sha string
			}
		}
	}
	Group struct {
		ID string
	}
	LastActivityAt    time.Time
	Archived          bool
	IsCatalogResource bool
	Languages         []struct {
		Name  string  `json:"name"`
		Share float64 `json:"share"`
	}
}

type GroupMetadataNode struct {
	ID         string
	FullName   string
	FullPath   string
	Visibility string
	CreatedAt  time.Time
	Parent     struct {
		ID string
	}
}

// Gitlab GraphQL response of query to get all projects of an instance with metadata
type InstanceProjectsResponse struct {
	Projects struct {
		Nodes    []ProjectMetadataNode
		PageInfo PageInfo
	}
}

// Gitlab GraphQL response of query to get all groups of an instance with metadata
type InstanceGroupsResponse struct {
	Groups struct {
		Nodes    []GroupMetadataNode
		PageInfo PageInfo
	}
}

// Gitlab GrapQL response of query to get all branches of a project
type ProjectBranchesResponse struct {
	Project struct {
		Repository struct {
			BranchNames []string
		}
	}
}

// Gitlab GraphQL response of merged CI conf
type MergedCIConfResponse struct {
	CiConfig struct {
		MergedYaml string                        `json:"mergedYaml"`
		Errors     []string                      `json:"errors"`
		Warnings   []interface{}                 `json:"warnings"`
		Status     string                        `json:"status"`
		Includes   []MergedCIConfResponseInclude `json:"includes"`
		Stages     struct {
			Nodes []struct {
				Name   string `json:"name"`
				Groups struct {
					Nodes []struct {
						Name string `json:"name"`
						Size int    `json:"size"`
						Jobs struct {
							Nodes []struct {
								Name   string   `json:"name"`
								Script []string `json:"script"`
							} `json:"nodes"`
						} `json:"jobs"`
					} `json:"nodes"`
				} `json:"groups"`
			} `json:"nodes"`
		} `json:"stages"`
	} `json:"ciConfig"`
}

type MergedCIConfResponseInclude struct {
	Location       string `json:"location,omitempty"`
	Raw            string `json:"raw,omitempty"`
	Blob           string `json:"blob,omitempty"` // Contains version-specific reference (e.g., blob SHA) - critical for cache key differentiation
	ContextProject string `json:"contextProject,omitempty"`
	Type           string `json:"type,omitempty"`
	Extra          struct {
		Project string `json:"project,omitempty"`
		Ref     string `json:"ref,omitempty"`
	} `json:"extra,omitempty"`

	// The fields below are upstream OBSERVATIONS about this include's SOURCE
	// project, supplied by an embedding host that collected them on the
	// CLI's behalf (the Plumber platform). GitLab does not return them on the
	// merged-config response; they are additive, and a run that receives none
	// behaves exactly as it did before they existed.
	//
	// They exist because these questions can only be answered by talking to
	// the SOURCE project - the catalogue that publishes a component, or the
	// project an include points at - and a tokenless CI job has no
	// credentials for it. The host that does holds them here.
	//
	// The host supplies observations only. Whether a ref is ambiguous, and
	// whether a pin is behind, are judgements this package makes from them.
	// A host that ships conclusions instead ends up with a second copy of
	// the control logic, which is how it drifts.

	// RefExistsAsTag and RefExistsAsBranch report whether this include's ref
	// names an existing tag, and an existing branch, in the source project.
	//
	// Tri-state deliberately. A nil pointer means the host did not determine
	// the answer - a skipped probe, a rate limit, a cancelled request - which
	// is NOT a determined false and must not be read as one. A ref that could
	// not be checked is not an unambiguous ref, and collapsing the two is the
	// silent pass ISSUE-402 exists to catch.
	RefExistsAsTag    *bool `json:"ref_exists_as_tag,omitempty"`
	RefExistsAsBranch *bool `json:"ref_exists_as_branch,omitempty"`

	// Jobs is the list of job names this include contributed, and JobsKnown
	// whether that was established.
	//
	// The CLI derives this itself with one config-merge request per include
	// (DeriveIncludeJobs). A host that has already done so serves it here and
	// the request is skipped.
	//
	// JobsKnown is the discriminator, not the emptiness of Jobs: an empty
	// list is a REAL answer (a nested include, or one contributing only
	// variables), so it cannot double as "we did not find out". Jobs is read
	// only when JobsKnown is true; anything else falls through to the CLI's
	// own resolution, and if that cannot run the include controls degrade
	// rather than treating an unresolved include as one that contributed
	// nothing.
	Jobs      []string `json:"jobs,omitempty"`
	JobsKnown bool     `json:"jobs_known,omitempty"`

	// SourceCatalog is the CI catalogue listing for the include's source
	// project, exactly as GetGitlabCIComponentResource returns it: every
	// published version and the components each one carries.
	//
	// It is served verbatim rather than reduced to a "latest version" on
	// purpose. Which versions count is a rule - only those still carrying
	// the named component - and latestCatalogVersion applies it here. A host
	// that reduces first has to reimplement that rule to do so, and a
	// component dropped in a later version is then reported as upgradeable
	// to a version that does not contain it.
	//
	// Nil means the lookup did not complete, which leaves the component with
	// no known latest version and the up-to-date control without a verdict.
	SourceCatalog *CICatalogResource `json:"source_catalog,omitempty"`
}
