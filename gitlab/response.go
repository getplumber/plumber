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
}
