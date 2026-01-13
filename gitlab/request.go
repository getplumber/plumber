package gitlab

import (
	"context"
	"fmt"

	"github.com/getplumber/plumber/configuration"
	"github.com/machinebox/graphql"
	"github.com/sirupsen/logrus"
)

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
	type response struct {
		Project struct {
			CiVariables ciVariables `json:"ciVariables"`
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

		allNodes = append(allNodes, respData.Project.CiVariables.Nodes...)
		hasNextPage = respData.Project.CiVariables.PageInfo.HasNextPage
		cursor = respData.Project.CiVariables.PageInfo.EndCursor
	}

	for _, v := range allNodes {
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

// GetGitlabCIComponentResources fetches all CI component resources from GitLab
func GetGitlabCIComponentResources(isGroup bool, token string, instanceUrl string, conf *configuration.Configuration) ([]CICatalogResource, error) {
	l := logrus.WithFields(logrus.Fields{
		"action":      "GetGitlabCIComponentResources",
		"instanceUrl": instanceUrl,
	})

	scope := "ALL"
	if isGroup {
		scope = "NAMESPACES"
	}

	query := fmt.Sprintf(`
	query getCIComponentResources {
		ciCatalogResources(scope: %s){
			nodes {
				id
				name
				fullPath
				webPath
				versions{
					nodes{
						name
						components {
							nodes {
								id
								name
								includePath
							}
						}
					}
				}
			}
		}
	}`, scope)

	graphqlClient := GetGraphQLClient(instanceUrl, conf)
	req := graphql.NewRequest(query)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	type componentNode struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		IncludePath string `json:"includePath"`
	}

	type componentsNodes struct {
		Nodes []componentNode `json:"nodes"`
	}

	type versionNode struct {
		Name       string          `json:"name"`
		Path       string          `json:"path"`
		Components componentsNodes `json:"components"`
	}

	type versionsNodes struct {
		Nodes []versionNode `json:"nodes"`
	}

	type resourceNode struct {
		ID       string        `json:"id"`
		Name     string        `json:"name"`
		FullPath string        `json:"fullPath"`
		WebPath  string        `json:"webPath"`
		Versions versionsNodes `json:"versions"`
	}

	type ciResourcesResponse struct {
		CICatalogResources struct {
			Nodes []resourceNode `json:"nodes"`
		} `json:"ciCatalogResources"`
	}

	var graphqlResp ciResourcesResponse
	if err := graphqlClient.Run(context.Background(), req, &graphqlResp); err != nil {
		l.WithError(err).Error("Failed to execute GraphQL query")
		return nil, err
	}

	resources := make([]CICatalogResource, 0, len(graphqlResp.CICatalogResources.Nodes))
	for _, node := range graphqlResp.CICatalogResources.Nodes {
		resource := CICatalogResource{
			ID:       node.ID,
			Name:     node.Name,
			FullPath: node.FullPath,
			WebPath:  node.WebPath,
			Versions: make([]CICatalogResourceVersion, 0, len(node.Versions.Nodes)),
		}

		for _, vNode := range node.Versions.Nodes {
			version := CICatalogResourceVersion{
				Name:       vNode.Name,
				Path:       vNode.Path,
				Components: make([]CIComponent, 0, len(vNode.Components.Nodes)),
			}

			for _, cNode := range vNode.Components.Nodes {
				version.Components = append(version.Components, CIComponent(cNode))
			}

			resource.Versions = append(resource.Versions, version)
		}

		resources = append(resources, resource)
	}

	return resources, nil
}
