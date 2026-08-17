package gitlab

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/machinebox/graphql"
	"github.com/sirupsen/logrus"
)

// ErrProjectVariablesUnreadable signals that GetGitlabProjectVariables got a
// well-formed HTTP 200 whose GraphQL `project`/`ciVariables` resolved to null —
// the token authenticated but lacks the role to read CI/CD variables
// (Maintainer+ / admin_cicd_variables). Callers that must never turn
// "unreadable" into a silent empty pass (the settings-variable controls, #418)
// treat any error as not-evaluable. Callers that only want the values
// opportunistically (image-ref resolution) check errors.Is for this sentinel
// and proceed with no project variables instead of failing the whole run.
var ErrProjectVariablesUnreadable = errors.New("project CI/CD variables not readable (insufficient token permissions)")

// GetGitlabProjectInheritedVariables returns all project inherited variables
func GetGitlabProjectInheritedVariables(fullPath string, token string, instanceUrl string, conf *configuration.Configuration) ([]CICDVariable, error) {
	l := logrus.WithFields(logrus.Fields{
		"platform":        "gitlab",
		"action":          "GetGitlabProjectInheritedVariables",
		"projectFullPath": fullPath,
		"instanceUrl":     instanceUrl,
	})

	variables := []CICDVariable{}

	request := `
		query getProjectGroupsVariables($fullPath: ID!) {
			project(fullPath: $fullPath) {
				group {
					ciVariables {
						nodes {
							key
							value
							variableType
							masked
							protected
							hidden
							environmentScope
						}
					}
					parent {
						ciVariables {
							nodes {
								key
								value
								variableType
								masked
								protected
								hidden
								environmentScope
							}
						}
						parent {
							ciVariables {
								nodes {
									key
									value
									variableType
									masked
									protected
									hidden
									environmentScope
								}
							}
						}
					}
				}
			}
		}
	`

	type variable struct {
		Key              string `json:"key"`
		Value            string `json:"value"`
		VariableType     string `json:"variableType"`
		Masked           bool   `json:"masked"`
		Protected        bool   `json:"protected"`
		Hidden           bool   `json:"hidden"`
		EnvironmentScope string `json:"environmentScope"`
	}

	type group2 struct {
		CiVariables struct {
			Nodes []variable `json:"nodes"`
		} `json:"ciVariables"`
	}
	type group1 struct {
		CiVariables struct {
			Nodes []variable `json:"nodes"`
		} `json:"ciVariables"`
		ParentGroup *group2 `json:"parent"`
	}
	type group0 struct {
		CiVariables struct {
			Nodes []variable `json:"nodes"`
		} `json:"ciVariables"`
		ParentGroup *group1 `json:"parent"`
	}

	type response struct {
		Project struct {
			Group *group0 `json:"group"`
		} `json:"project"`
	}

	client := GetGraphQLClient(instanceUrl, conf)
	req := graphql.NewRequest(request)
	req.Var("fullPath", fullPath)
	req.Header.Add("Authorization", "Bearer "+token)

	var respData response
	if err := client.Run(context.Background(), req, &respData); err != nil {
		l.WithError(err).Error("Failed to get project variables through GitLab GraphQL API")
		return variables, err
	}

	// Build results while respecting precedence
	varAlreadyDefined := map[string]bool{}
	if respData.Project.Group != nil {
		for _, v := range respData.Project.Group.CiVariables.Nodes {
			newVar := CICDVariable{
				Name:        v.Key,
				Value:       v.Value,
				Type:        string(v.VariableType),
				Protected:   v.Protected,
				Masked:      v.Masked,
				Hidden:      v.Hidden,
				Environment: v.EnvironmentScope,
			}
			variables = append(variables, newVar)
			varAlreadyDefined[newVar.Name] = true
		}

		if respData.Project.Group.ParentGroup != nil {
			for _, v := range respData.Project.Group.ParentGroup.CiVariables.Nodes {
				if _, ok := varAlreadyDefined[v.Key]; ok {
					continue
				}
				newVar := CICDVariable{
					Name:        v.Key,
					Value:       v.Value,
					Type:        string(v.VariableType),
					Protected:   v.Protected,
					Masked:      v.Masked,
					Hidden:      v.Hidden,
					Environment: v.EnvironmentScope,
				}
				variables = append(variables, newVar)
				varAlreadyDefined[newVar.Name] = true
			}

			if respData.Project.Group.ParentGroup.ParentGroup != nil {
				for _, v := range respData.Project.Group.ParentGroup.ParentGroup.CiVariables.Nodes {
					if _, ok := varAlreadyDefined[v.Key]; ok {
						continue
					}
					newVar := CICDVariable{
						Name:        v.Key,
						Value:       v.Value,
						Type:        string(v.VariableType),
						Protected:   v.Protected,
						Masked:      v.Masked,
						Hidden:      v.Hidden,
						Environment: v.EnvironmentScope,
					}
					variables = append(variables, newVar)
					varAlreadyDefined[newVar.Name] = true
				}
			}
		}
	}

	return variables, nil
}

// FetchGitlabMergedCIConf gets merged version of a GitLab CI configuration
func FetchGitlabMergedCIConf(projectPath string, confContent string, sha string, userToken string, instanceUrl string, conf *configuration.Configuration) (MergedCIConfResponse, error) {
	l := logrus.WithFields(logrus.Fields{
		"action":      "FetchGitlabMergedCIConf",
		"instanceUrl": instanceUrl,
		"projectPath": projectPath,
		"sha":         sha,
	})

	request := `
	query getCiConfig($projectPath: ID!, $content: String!, $sha: String!, $dryRun: Boolean!) {
		ciConfig(projectPath: $projectPath, content: $content, sha: $sha, dryRun: $dryRun) {
			mergedYaml
			errors
			warnings
			status
			includes {
				location
				type
				extra
				raw
				contextProject
				blob
			}
			stages {
				nodes {
					name
					groups {
						nodes {
							name
							size
							jobs {
								nodes {
									name
									script
								}
							}
						}
					}
				}
			}
		}
	}
	`

	client := GetGraphQLClient(instanceUrl, conf)
	req := graphql.NewRequest(request)
	req.Var("projectPath", projectPath)
	req.Var("content", confContent)
	req.Var("sha", sha)
	req.Var("dryRun", false)
	req.Header.Add("Authorization", "Bearer "+userToken)

	var response MergedCIConfResponse
	if err := client.Run(context.Background(), req, &response); err != nil {
		l.WithError(err).Error("Failed to get ci merged configuration using GitLab GraphQL API")
		return response, err
	}

	return response, nil
}

// GetGitlabProjectVariables returns all project variables
func GetGitlabProjectVariables(fullPath string, token string, instanceUrl string, conf *configuration.Configuration) ([]CICDVariable, error) {
	l := logrus.WithFields(logrus.Fields{
		"platform":        "gitlab",
		"action":          "GetGitlabProjectVariables",
		"projectFullPath": fullPath,
		"instanceUrl":     instanceUrl,
	})

	variables := []CICDVariable{}

	request := `
		query getProjectVariables($fullPath: ID!, $after: String) {
			project(fullPath: $fullPath) {
				ciVariables(after: $after) {
					pageInfo {
						hasNextPage
						endCursor
					}
					nodes {
						key
						value
						variableType
						masked
						protected
						hidden
						environmentScope
					}
				}
			}
		}
	`

	type variable struct {
		Key              string `json:"key"`
		Value            string `json:"value"`
		VariableType     string `json:"variableType"`
		Masked           bool   `json:"masked"`
		Protected        bool   `json:"protected"`
		Hidden           bool   `json:"hidden"`
		EnvironmentScope string `json:"environmentScope"`
	}
	type ciVariables struct {
		Nodes    []variable `json:"nodes"`
		PageInfo struct {
			HasNextPage bool   `json:"hasNextPage"`
			EndCursor   string `json:"endCursor"`
		} `json:"pageInfo"`
	}
	// Project and CiVariables are pointers so a GraphQL `project: null` or
	// `ciVariables: null` is distinguishable from an empty list. GitLab returns
	// null there (HTTP 200, no transport error) when the token authenticates but
	// lacks the role to read CI/CD variables (Maintainer+ / admin_cicd_variables),
	// or when the project is not visible. A value struct would silently
	// deserialize that to zero variables — a false "no variables" pass. Detecting
	// null and erroring keeps the not-evaluable guarantee honest (#418).
	type response struct {
		Project *struct {
			CiVariables *ciVariables `json:"ciVariables"`
		} `json:"project"`
	}

	client := GetGraphQLClient(instanceUrl, conf)

	var allNodes []variable
	var cursor string
	hasNextPage := true

	for hasNextPage {
		req := graphql.NewRequest(request)
		req.Var("after", cursor)
		req.Var("fullPath", fullPath)
		req.Header.Add("Authorization", "Bearer "+token)

		var respData response
		if err := client.Run(context.Background(), req, &respData); err != nil {
			l.WithError(err).Error("Failed to get project variables through GitLab GraphQL API")
			return variables, err
		}

		if respData.Project == nil || respData.Project.CiVariables == nil {
			// Null project/ciVariables with no transport error means the token
			// cannot read the variables. Return the sentinel so the settings
			// controls report not-evaluable (#418) while opportunistic callers
			// (image-ref resolution) can tolerate it via errors.Is.
			err := fmt.Errorf("GitLab returned a null project/ciVariables for %q (needs Maintainer+ / admin_cicd_variables): %w", fullPath, ErrProjectVariablesUnreadable)
			l.WithError(err).Warn("project CI/CD variables not readable")
			return variables, err
		}

		allNodes = append(allNodes, respData.Project.CiVariables.Nodes...)
		hasNextPage = respData.Project.CiVariables.PageInfo.HasNextPage
		cursor = respData.Project.CiVariables.PageInfo.EndCursor
	}

	for _, v := range allNodes {
		newVar := CICDVariable{
			Name: v.Key,
			Value: v.Value,
			// Normalise the GraphQL enum (ENV_VAR / FILE) to the lower-case form
			// the rest of the pipeline and the REST API use ("env_var" / "file"),
			// so the masked rule's file-type exclusion and the identity value stay
			// consistent between real runs and fixtures.
			Type:        strings.ToLower(string(v.VariableType)),
			Protected:   v.Protected,
			Masked:      v.Masked,
			Hidden:      v.Hidden,
			Environment: v.EnvironmentScope,
		}
		variables = append(variables, newVar)
	}

	return variables, nil
}

// GetGitlabInstanceVariables returns all instance variables
func GetGitlabInstanceVariables(token string, instanceUrl string, conf *configuration.Configuration) ([]CICDVariable, error) {
	l := logrus.WithFields(logrus.Fields{
		"platform":    "gitlab",
		"action":      "GetGitlabInstanceVariables",
		"instanceUrl": instanceUrl,
	})

	variables := []CICDVariable{}

	request := `
		query getInstanceVariables($after: String) {
			ciVariables(after: $after) {
				pageInfo {
					hasNextPage
					endCursor
				}
				nodes {
					key
					value
					variableType
					masked
					protected
				}
			}
		}
	`

	type variable struct {
		Key          string `json:"key"`
		Value        string `json:"value"`
		VariableType string `json:"variableType"`
		Masked       bool   `json:"masked"`
		Protected    bool   `json:"protected"`
	}
	type ciVariables struct {
		Nodes    []variable `json:"nodes"`
		PageInfo struct {
			HasNextPage bool   `json:"hasNextPage"`
			EndCursor   string `json:"endCursor"`
		} `json:"pageInfo"`
	}
	type response struct {
		CiVariables ciVariables `json:"ciVariables"`
	}

	client := GetGraphQLClient(instanceUrl, conf)

	var allNodes []variable
	var cursor string
	hasNextPage := true

	for hasNextPage {
		req := graphql.NewRequest(request)
		req.Var("after", cursor)
		req.Header.Add("Authorization", "Bearer "+token)

		var respData response
		if err := client.Run(context.Background(), req, &respData); err != nil {
			l.WithError(err).Error("Failed to get instance variables using GitLab GraphQL API")
			return variables, err
		}

		allNodes = append(allNodes, respData.CiVariables.Nodes...)
		hasNextPage = respData.CiVariables.PageInfo.HasNextPage
		cursor = respData.CiVariables.PageInfo.EndCursor
	}

	for _, v := range allNodes {
		newVar := CICDVariable{
			Name:      v.Key,
			Value:     v.Value,
			Type:      string(v.VariableType),
			Protected: v.Protected,
			Masked:    v.Masked,
		}
		variables = append(variables, newVar)
	}

	return variables, nil
}

// GetGitlabCIComponentResource fetches a SINGLE CI/CD catalog resource by its
// project full path, with its released versions and their components. It is the
// targeted replacement for the removed instance-wide catalog enumeration: on
// a large catalog (gitlab.com has ~800 resources) that broad
// query returns a multi-megabyte payload that exceeds the HTTP timeout, gets
// cancelled, and silently disables outdated-include detection (#156). This
// per-component lookup returns in well under a second and is complete (no
// pagination roulette). Returns (nil, nil) when no catalog resource exists at
// fullPath — e.g. a component published only as git tags, or a plain project
// include — so the caller can fall back to the tags API.
func GetGitlabCIComponentResource(fullPath string, token string, instanceUrl string, conf *configuration.Configuration) (*CICatalogResource, error) {
	l := logrus.WithFields(logrus.Fields{
		"action":      "GetGitlabCIComponentResource",
		"instanceUrl": instanceUrl,
		"fullPath":    fullPath,
	})

	const query = `query getCIComponentResource($fullPath: ID!) {
		ciCatalogResource(fullPath: $fullPath) {
			id
			name
			fullPath
			webPath
			versions(first: 50) {
				nodes {
					name
					components {
						nodes { id name includePath }
					}
				}
			}
		}
	}`

	client := GetGraphQLClient(instanceUrl, conf)
	req := graphql.NewRequest(query)
	req.Var("fullPath", fullPath)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	var resp struct {
		CICatalogResource *struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			FullPath string `json:"fullPath"`
			WebPath  string `json:"webPath"`
			Versions struct {
				Nodes []struct {
					Name       string `json:"name"`
					Components struct {
						Nodes []struct {
							ID          string `json:"id"`
							Name        string `json:"name"`
							IncludePath string `json:"includePath"`
						} `json:"nodes"`
					} `json:"components"`
				} `json:"nodes"`
			} `json:"versions"`
		} `json:"ciCatalogResource"`
	}

	if err := client.Run(context.Background(), req, &resp); err != nil {
		l.WithError(err).Debug("ciCatalogResource query failed")
		return nil, err
	}
	if resp.CICatalogResource == nil {
		return nil, nil
	}

	n := resp.CICatalogResource
	res := &CICatalogResource{
		ID:       n.ID,
		Name:     n.Name,
		FullPath: n.FullPath,
		WebPath:  n.WebPath,
		Versions: make([]CICatalogResourceVersion, 0, len(n.Versions.Nodes)),
	}
	for _, vNode := range n.Versions.Nodes {
		version := CICatalogResourceVersion{
			Name:       vNode.Name,
			Components: make([]CIComponent, 0, len(vNode.Components.Nodes)),
		}
		for _, cNode := range vNode.Components.Nodes {
			version.Components = append(version.Components, CIComponent{ID: cNode.ID, Name: cNode.Name, IncludePath: cNode.IncludePath})
		}
		res.Versions = append(res.Versions, version)
	}
	return res, nil
}
