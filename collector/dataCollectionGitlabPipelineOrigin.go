package collector

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/utils"
	gover "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const DataCollectionTypeGitlabPipelineOriginVersion = "0.2.0"

const (
	// Gitlab types
	glOriginComponent = "component"
	glOriginLocal     = "local"
	glOriginProject   = "file"
	glOriginRemote    = "remote"
	glOriginTemplate  = "template"

	// Our types
	originHardcoded = "hardcoded"
	originComponent = "component"
	originLocal     = "local"
	originProject   = "project"
	originRemote    = "remote"
	originTemplate  = "template"

	glComponentVersionSeparator = "@"
	pbLatestTag                 = "latest"
	glTildeLatestTag            = "~latest"
	gitHeadRef                  = "HEAD"

	mainBranch   = "main"
	masterBranch = "master"
)

////////////////////////////
// DataCollection results //
////////////////////////////

type GitlabPipelineOriginDataCollection struct{}

type GitlabPipelineOriginMetrics struct {

	// Data metrics: jobs
	JobTotal     uint `json:"jobTotal"`
	JobHardcoded uint `json:"jobHardcoded"`

	// Data metrics: origin
	OriginTotal         uint `json:"originTotal"`
	OriginComponent     uint `json:"originComponent"`
	OriginLocal         uint `json:"originLocal"`
	OriginProject       uint `json:"originProject"`
	OriginRemote        uint `json:"originRemote"`
	OriginTemplate      uint `json:"originTemplate"`
	OriginGitLabCatalog uint `json:"originGitLabCatalog"`
	OriginOutdated      uint `json:"originOutdated"`
}

type GitlabPipelineOriginData struct {

	// Gitlab CI catalog data
	GitlabCatalogResources    []gitlab.CICatalogResource
	GitlabCatalogComponentMap map[string]int      // path -> index in catalogResources
	VersionMap                map[string][]string // path -> []versions (newest first)

	// Gitlab CI configuration
	Conf            *gitlab.GitlabCIConf
	ConfString      string
	MergedConf      *gitlab.GitlabCIConf
	MergedResponse  *gitlab.MergedCIConfResponse
	CiValid         bool
	CiMissing       bool
	LimitedAnalysis bool

	// Origins and jobs data
	Origins []GitlabPipelineOriginDataFull

	// CI conf content
	JobMap              map[string]*GitlabPipelineJobData
	JobExtendsMap       map[string][]string
	JobHardcodedMap     map[string]bool
	JobHardcodedContent map[string]interface{}
}

type GitlabPipelineOriginDataFull struct {
	// Origin data generic and specific
	GitlabPipelineOriginDataGeneric
	GitlabPipelineOriginDataProjectSpecific
}

type GitlabPipelineOriginDataGeneric struct {
	OriginType          string                           `json:"originType"`
	FromGitlabCatalog   bool                             `json:"fromGitlabCatalog"`
	GitlabIncludeOrigin gitlab.IncludeOriginWithoutRef   `json:"gitlabIncludeOrigin"`
	GitlabComponent     GitlabPipelineJobGitlabComponent `json:"gitlabComponent"`
	OriginHash          uint64                           `json:"originHash"`
}

type GitlabPipelineOriginDataProjectSpecific struct {
	// Data specific to this project
	Version  string `json:"version"`
	UpToDate bool   `json:"upToDate"`
	Nested   bool   `json:"nested"`

	// Job related data
	Jobs []GitlabPipelineJobData `json:"jobs"`
}

type GitlabPipelineJobData struct {
	Name         string   `json:"name"`
	Extends      []string `json:"extends"`
	Lines        int      `json:"lines"`
	IsHardocded  bool     `json:"isHardcoded"`
	IsOverridden bool     `json:"isOverridden"`
}

// GitlabPipelineJobGitlabComponent represents a GitLab component
type GitlabPipelineJobGitlabComponent struct {
	RepoFullPath           string `json:"repoFullPath"`
	RepoWebPath            string `json:"repoWebPath"`
	RepoName               string `json:"repoName"`
	ComponentName          string `json:"componentName"`
	ComponentLatestVersion string `json:"componentLatestVersion"`
	ComponentIncludePath   string `json:"componentIncludePath"`
}

//////////////////////////////
// DataCollection functions //
//////////////////////////////

// ParseGitlabComponentPath parses a GitLab component path to extract:
// 1. The instance (if any)
// 2. The clean path without instance prefix
// 3. The version (if any)
func ParseGitlabComponentPath(path string, instanceURL string) (string, string, string) {
	// Get GitLab server name from instanceURL
	gitlabServerName := strings.TrimPrefix(instanceURL, "https://")
	gitlabServerName = strings.TrimPrefix(gitlabServerName, "http://")

	// Initialize the results
	instance := ""
	cleanPath := path
	version := ""

	// Check if the path starts with one of the known prefixes
	if strings.HasPrefix(path, gitlabServerName+"/") {
		instance = gitlabServerName
		cleanPath = strings.TrimPrefix(path, gitlabServerName+"/")
	} else if strings.HasPrefix(path, "$CI_SERVER_FQDN/") {
		instance = "$CI_SERVER_FQDN"
		cleanPath = strings.TrimPrefix(path, "$CI_SERVER_FQDN/")
	} else if strings.HasPrefix(path, "$CI_SERVER_HOST/") {
		instance = "$CI_SERVER_HOST"
		cleanPath = strings.TrimPrefix(path, "$CI_SERVER_HOST/")
	} else if strings.HasPrefix(path, "$CI_SERVER_URL/") {
		instance = "$CI_SERVER_URL"
		cleanPath = strings.TrimPrefix(path, "$CI_SERVER_URL/")
	}

	// Extract version if present
	componentSplit := strings.Split(cleanPath, glComponentVersionSeparator)
	if len(componentSplit) > 1 {
		cleanPath = componentSplit[0]
		version = componentSplit[1]
	}

	return instance, cleanPath, version
}

// extractInputsFromInclude extracts inputs from a single include entry and generates its hash
// includeEntry can be a string (simple include) or a map (include with properties)
// Returns: hash (uint64), inputs (map), error
func extractInputsFromInclude(includeEntry interface{}, instanceURL string) (uint64, map[string]interface{}, error) {
	// If it's a string, create a simple include origin
	if includeStr, ok := includeEntry.(string); ok {
		// Simple string includes are typically templates or remote URLs
		includeOrigin := gitlab.IncludeOriginWithoutRef{
			Location: includeStr,
			Type:     "", // Will be empty for simple strings
			Project:  "",
		}
		hash, err := generateIncludeHash(includeOrigin)
		return hash, nil, err
	}

	// If it's a map, extract location, type, project and inputs
	if includeMap, ok := includeEntry.(map[interface{}]interface{}); ok {
		var includeOrigin gitlab.IncludeOriginWithoutRef
		var inputs map[string]interface{}

		// Check each possible include type and populate IncludeOriginWithoutRef
		if component, ok := includeMap["component"].(string); ok {
			includeOrigin.Location = component
			includeOrigin.Type = glOriginComponent
		} else if local, ok := includeMap["local"].(string); ok {
			includeOrigin.Location = local
			includeOrigin.Type = glOriginLocal
		} else if file, ok := includeMap["file"].(string); ok {
			includeOrigin.Location = file
			includeOrigin.Type = glOriginProject
			if project, ok := includeMap["project"].(string); ok {
				includeOrigin.Project = project
			}
		} else if remote, ok := includeMap["remote"].(string); ok {
			includeOrigin.Location = remote
			includeOrigin.Type = glOriginRemote
		} else if template, ok := includeMap["template"].(string); ok {
			includeOrigin.Location = template
			includeOrigin.Type = glOriginTemplate
		}

		// Extract inputs if present
		if inputsRaw, ok := includeMap["inputs"]; ok {
			inputs = make(map[string]interface{})
			// Convert map[interface{}]interface{} to map[string]interface{}
			if inputsMap, ok := inputsRaw.(map[interface{}]interface{}); ok {
				for k, v := range inputsMap {
					if keyStr, ok := k.(string); ok {
						inputs[keyStr] = v
					}
				}
			}
		}

		// For components, normalize the location (remove version) to match the main loop logic
		// This ensures the hash will match between the original config and the merged response
		if includeOrigin.Type == glOriginComponent {
			instance, cleanPath, _ := ParseGitlabComponentPath(includeOrigin.Location, instanceURL)

			// Resolve GitLab CI variables to actual instance name
			// In the main loop, GitLab has already resolved these, so we need to match
			if instance == "$CI_SERVER_HOST" || instance == "$CI_SERVER_FQDN" || instance == "$CI_SERVER_URL" {
				// Extract the actual instance name from the instance URL
				actualInstance := strings.TrimPrefix(instanceURL, "https://")
				actualInstance = strings.TrimPrefix(actualInstance, "http://")
				instance = actualInstance
			}

			includeOrigin.Location = instance + "/" + cleanPath
		}

		// Generate hash using the same method as the main loop
		hash, err := generateIncludeHash(includeOrigin)
		return hash, inputs, err
	}

	return 0, nil, nil
}

// generateIncludeHash generates a hash from an IncludeOriginWithoutRef
// This uses the same logic as the main loop for consistency
func generateIncludeHash(includeOrigin gitlab.IncludeOriginWithoutRef) (uint64, error) {
	gitlabIncludeOriginByte, err := json.Marshal(includeOrigin)
	if err != nil {
		return 0, err
	}
	return utils.GenerateFNVHash(gitlabIncludeOriginByte), nil
}

// buildIncludeInputsMap builds a map of include hash to inputs from the GitLab CI configuration
// The map is used to pass the correct inputs when fetching includes
// Uses the same hash mechanism as the main origin detection loop for consistency
func buildIncludeInputsMap(gitlabConf *gitlab.GitlabCIConf, instanceURL string) map[uint64]map[string]interface{} {
	includeInputsMap := make(map[uint64]map[string]interface{})

	if gitlabConf == nil || gitlabConf.Include == nil {
		return includeInputsMap
	}

	// Process each include entry
	for _, includeEntry := range gitlabConf.Include {
		hash, inputs, err := extractInputsFromInclude(includeEntry, instanceURL)
		if err != nil || hash == 0 {
			continue
		}

		// Store inputs for this hash
		if len(inputs) > 0 {
			includeInputsMap[hash] = inputs
		}
	}

	return includeInputsMap
}

////////////////////////
// DataCollection run //
////////////////////////

func (dc *GitlabPipelineOriginDataCollection) Run(project *gitlab.ProjectInfo, token string, conf *configuration.Configuration) (*GitlabPipelineOriginData, *GitlabPipelineOriginMetrics, error) {
	l := l.WithFields(logrus.Fields{
		"dataCollection":        "GitlabPipelineOrigin",
		"dataCollectionVersion": DataCollectionTypeGitlabPipelineOriginVersion,
		"project":               project.Path,
	})
	l.Info("Start data collection")

	////////////////////////
	// Initialize results //
	////////////////////////

	data := &GitlabPipelineOriginData{}
	data.CiValid = true
	data.CiMissing = false
	data.LimitedAnalysis = false
	data.JobMap = make(map[string]*GitlabPipelineJobData)
	data.JobExtendsMap = make(map[string][]string)
	data.JobHardcodedMap = make(map[string]bool)
	data.JobHardcodedContent = make(map[string]interface{})
	data.GitlabCatalogResources = []gitlab.CICatalogResource{}
	data.GitlabCatalogComponentMap = make(map[string]int)
	data.VersionMap = make(map[string][]string)
	data.Origins = []GitlabPipelineOriginDataFull{}
	data.ConfString = ""
	data.MergedConf = nil
	data.MergedResponse = nil

	metrics := &GitlabPipelineOriginMetrics{}

	//////////////////////////////
	// Fetch info from the repo //
	//////////////////////////////

	var err error

	// Get all infos about the CI configuration
	// Use project.DefaultBranch as ref (can be overridden via --branch CLI flag)
	data.Conf, data.MergedConf, data.MergedResponse, data.ConfString, _, err = gitlab.GetFullGitlabCI(project, project.DefaultBranch, token, conf.GitlabURL, conf)
	if err != nil {
		data.LimitedAnalysis = true
		data.CiValid = false
		data.CiMissing = false

		// Check if this is a 404 error when project.NotFound is false
		if strings.Contains(err.Error(), "404") && !project.NotFound {
			// In this case, it's CI missing rather than an analysis error
			data.CiMissing = true
			data.CiValid = true // It's not really valid (missing) but we keep it to avoid false positive on "invalid"
			l.WithError(err).Warning("Unable to retrieve project's CI configuration (404). CI is missing but project exists. Data collection will continue with limited data.")
		} else {
			data.CiValid = false
			l.WithError(err).Warning("Unable to retrieve project's CI merged configuration. Data collection will continue with limited data.")
		}

	} else if data.MergedResponse != nil && (len(data.MergedResponse.CiConfig.Errors) > 0 || data.MergedResponse.CiConfig.Status == "INVALID") {

		if data.ConfString == "" {
			data.CiMissing = true
			data.CiValid = true // It's not really valid (missing) but we keep it to avoid false positive on "invalid"
		} else {
			data.CiMissing = false // CI exists but has errors
			data.CiValid = false
		}
		data.LimitedAnalysis = true
		l.WithField("errors", data.MergedResponse.CiConfig.Errors).Warning("Pipeline has configuration errors. Data collection will continue with limited data.")

	} else if data.MergedResponse == nil || data.MergedConf == nil {

		data.LimitedAnalysis = true
		data.CiValid = true   // It's not really valid (missing) but we keep it to avoid false positive on "invalid"
		data.CiMissing = true // CI is empty/missing
		l.Warning("Pipeline is empty. Data collection will continue with limited data.")

	}

	// If we weren't able to retrieve the pipelines (invalid configuration, archived project, unauthorized, ...), we stop here
	if data.LimitedAnalysis {
		// Return empty result for limited analysis
		return data, metrics, nil
	}

	// Fetch all GitLab components
	data.GitlabCatalogResources, err = gitlab.GetGitlabCIComponentResources(project.IsGroup, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Warning("Unable to retrieve GitLab CI components")
		// Continue even if we can't get components (will just not detect them)
	}

	// Create maps to quickly lookup components and versions
	for i, resource := range data.GitlabCatalogResources {
		// Process each version and component
		for _, version := range resource.Versions {
			for _, component := range version.Components {

				// Extract instance, clean path, and version from the includePath
				_, cleanPath, _ := ParseGitlabComponentPath(component.IncludePath, conf.GitlabURL)

				// Store component resource index in the map - key is the clean path
				data.GitlabCatalogComponentMap[cleanPath] = i

				// Add component to versionMap
				if _, ok := data.VersionMap[cleanPath]; !ok {
					data.VersionMap[cleanPath] = make([]string, 0, len(resource.Versions))
				}
				data.VersionMap[cleanPath] = append(data.VersionMap[cleanPath], version.Name)
			}
		}
	}

	// Sort versions (newest first) - using semantic versioning comparison
	for path, versions := range data.VersionMap {
		sort.Slice(versions, func(i, j int) bool {
			// Try to parse as semantic versions
			v1, err1 := gover.NewVersion(versions[i])
			v2, err2 := gover.NewVersion(versions[j])

			// If both are valid semantic versions, compare them properly
			if err1 == nil && err2 == nil {
				return v1.GreaterThan(v2) // For descending order (newest first)
			}

			// Fall back to string comparison if not valid semantic versions
			return versions[i] > versions[j] // Simple lexicographic sort for descending order
		})
		data.VersionMap[path] = versions
	}

	////////////////////////////////////////////////////////
	// Build map of include identifiers to their inputs  //
	////////////////////////////////////////////////////////

	// This map will help us pass the correct inputs when fetching includes
	// Key: include hash (same hash used for origin tracking)
	// Value: map of input name to input value
	includeInputsMap := buildIncludeInputsMap(data.Conf, conf.GitlabURL)
	l.WithField("includeInputsMap", includeInputsMap).Debug("Built include inputs map from original configuration")

	//////////////////
	// Extract data //
	//////////////////

	// Check all job in unmerged conf to identify hardcoded jobs (it can be
	// overrides, this will be detected later)
	for name, content := range data.Conf.GitlabJobs {
		data.JobHardcodedMap[name] = true
		data.JobHardcodedContent[name] = content
	}

	// Build the list of all job (not checking origin yet)
	if data.MergedConf != nil {
		for name, content := range data.MergedConf.GitlabJobs {

			// Add logging info
			lJob := l.WithField("jobName", name)
			lJob.Debug("Start to analyze a job from merged conf")

			// Parse the job
			var job *gitlab.GitlabJob
			job, err = gitlab.ParseGitlabCIJob(content)
			if err != nil {
				l.WithError(err).Error("Unable to parse the job retrieved from CI conf")
				return data, metrics, err
			}

			// Get the extends value
			extends := []string{}
			if job.Extends != nil {
				extendsResult, err := gitlab.GetExtends(job.Extends)
				if err != nil {
					lJob.WithError(err).WithField("extends", job.Extends).Error("Unable to parse job extends")
					continue
				}
				if extendsResult != nil {
					extends = extendsResult
				}
			}

			// Count job lines
			yamlData, err := yaml.Marshal(job)
			if err != nil {
				lJob.WithError(err).Error("Could not marshal the job")
			}
			jobLines := strings.Count(string(yamlData), "\n")

			// Create result data for the job
			jobData := GitlabPipelineJobData{}
			jobData.Name = name
			jobData.Extends = extends
			jobData.Lines = jobLines
			jobData.IsHardocded = false
			jobData.IsOverridden = false

			// Check if hardcoded
			if _, ok := data.JobHardcodedMap[name]; ok {
				jobData.IsHardocded = true
			}

			lJob.Debug("Job added to result list")

			data.JobMap[name] = &jobData

			// If the job extends another job(s), add a reference to extends map
			for _, jobExtendSource := range extends {
				data.JobExtendsMap[jobExtendSource] = append(data.JobExtendsMap[jobExtendSource], name)
			}
		}
	}

	/////////////////////////////////////////////////////////////////////////
	////// Loop over all "includes" to find what job they contains and add //
	////// origin info to jobs previously listed                           //
	/////////////////////////////////////////////////////////////////////////

	if data.MergedResponse != nil {
		for _, include := range data.MergedResponse.CiConfig.Includes {

			// Add logging info
			lInclude := l.WithField("include", include)
			lInclude.Debug("Include analysis in progress")

			////////////////////////////////////////////////////////
			////////// Check if include is a first-level include //
			////////////////////////////////////////////////////////

			// Context: the merged response contains all includes, even those
			// nested in another includes.
			// To detect if the origin is not first level (so, nested), we just check if
			// contextProject is different that the current project
			isNested := false
			if include.ContextProject != project.Path {
				lInclude.Debug("Nested include found")
				isNested = true
				// NOTE: there is a case of nested include we don't detect yet:
				// .gitlab-ci.yml => include a local file local.yml
				//  local.yml => include anything                    => we don't detect this is a nested include
			}

			///////////////////////////////////////////////////////////////////////
			////////// Initialize the job origin data with current include data  //
			///////////////////////////////////////////////////////////////////////

			originData := GitlabPipelineOriginDataFull{}
			originData.FromGitlabCatalog = false
			originData.Version = ""
			originData.UpToDate = false
			originData.Nested = isNested
			originData.GitlabComponent = GitlabPipelineJobGitlabComponent{}
			originData.GitlabIncludeOrigin = gitlab.IncludeOriginWithoutRef{
				Location: include.Location,
				Type:     include.Type,
				Project:  include.Extra.Project,
			}

			// Prepare latest ref slice to check version
			latestRefs := []string{gitHeadRef, project.DefaultBranch, pbLatestTag, glTildeLatestTag, mainBranch, masterBranch}

			// Create a hash to be able to distinguish each origin
			gitlabIncludeOriginByte, err := json.Marshal(originData.GitlabIncludeOrigin)
			if err != nil {
				lInclude.WithError(err).Error("Unable to marshal the include origin to generate its hash")
				return data, metrics, err
			}
			originData.OriginHash = utils.GenerateFNVHash(gitlabIncludeOriginByte)

			///////////////////////////////////////////////////////////
			////////// Extract specific data for each type of include //
			///////////////////////////////////////////////////////////

			switch include.Type {

			// GitLab component
			case glOriginComponent:

				// Set type
				originData.OriginType = originComponent

				// Extract instance, clean path, and version
				instance, cleanPath, version := ParseGitlabComponentPath(originData.GitlabIncludeOrigin.Location, conf.GitlabURL)

				// Remove version to avoid it to be split in SQL "group by" on GitlabIncludeOrigin
				originData.GitlabIncludeOrigin.Location = instance + "/" + cleanPath

				// Regenerate the hash with the updated location
				gitlabIncludeOriginByteWithoutVersion, err := json.Marshal(originData.GitlabIncludeOrigin)
				if err != nil {
					lInclude.WithError(err).Error("Unable to marshal the include origin to re-generate its hash with the updated location without version")
					return data, metrics, err
				}
				originData.OriginHash = utils.GenerateFNVHash(gitlabIncludeOriginByteWithoutVersion)

				// Set the version
				originData.Version = version

				// Check if we can find this component in the catalog
				foundComponent := false

				// Try to find matching component directly in our componentMap
				if resourceIndex, exists := data.GitlabCatalogComponentMap[cleanPath]; exists {

					// We found a matching component
					lInclude.WithFields(logrus.Fields{
						"componentLocation": originData.GitlabIncludeOrigin.Location,
						"cleanPath":         cleanPath,
						"fullPath":          data.GitlabCatalogResources[resourceIndex].FullPath,
					}).Debug("Found a matching GitLab component")

					foundComponent = true

					// Mark as found in GitLab catalog
					originData.FromGitlabCatalog = true

					// Get latest version from our pre-sorted version map
					latestVersion := ""
					if versions, ok := data.VersionMap[cleanPath]; ok && len(versions) > 0 {
						latestVersion = versions[0] // First version is the newest
					}

					// Extract component name from the path (last segment)
					// The component include is: <instance>/<repo_full_path>/<component_name>@version
					repoFullPath := data.GitlabCatalogResources[resourceIndex].FullPath
					componentName := ""
					pathParts := strings.Split(cleanPath, "/")
					if len(pathParts) > 0 {
						componentName = pathParts[len(pathParts)-1]
					}

					// If component name is empty, skip
					if componentName == "" {
						lInclude.Warning("Component name is empty. It should not happen.")
						continue
					}

					// Set GitLab component data
					originData.GitlabComponent = GitlabPipelineJobGitlabComponent{
						RepoFullPath:           data.GitlabCatalogResources[resourceIndex].FullPath + "/" + componentName,
						RepoWebPath:            data.GitlabCatalogResources[resourceIndex].WebPath,
						RepoName:               data.GitlabCatalogResources[resourceIndex].Name,
						ComponentName:          componentName,
						ComponentIncludePath:   instance + "/" + cleanPath,
						ComponentLatestVersion: latestVersion,
					}

					// Check if version is up to date
					originData.UpToDate = gitlab.IsUpToDate(originData.Version, latestVersion, latestRefs)

					lInclude.WithFields(logrus.Fields{
						"repoFullPath":  repoFullPath,
						"componentName": componentName,
						"cleanPath":     cleanPath,
					}).Debug("Extracted component information")
				}

				// If component was not found, log a debug message
				if !foundComponent {
					lInclude.WithFields(logrus.Fields{
						"componentIncludeLocation": originData.GitlabIncludeOrigin.Location,
						"cleanComponentPath":       cleanPath,
						"componentMap":             data.GitlabCatalogComponentMap,
						"versionMap":               data.VersionMap,
					}).Debug("Could not find a matching GitLab component")
				}

			// External file (project)
			case glOriginProject:

				// Set type
				originData.OriginType = originProject
				// Set version
				originData.Version = include.Extra.Ref

			// Local file
			case glOriginLocal:
				originData.OriginType = originLocal

			// External file (remote)
			case glOriginRemote:
				originData.OriginType = originRemote

			// GitLab template
			case glOriginTemplate:
				originData.OriginType = originTemplate

			default:
				lInclude.WithField("include.Type", include.Type).Error("Unknown include type")
			}

			////////////////////////////////////////////////////////////////////////////////////
			////////// Get all job from the current include excepted if it's a nested include //
			////////////////////////////////////////////////////////////////////////////////////

			// Skip fetching if it's a nested include
			if isNested {
				lInclude.Debug("Skipping nested include from another project context")
				// Initialize empty jobs list for this origin
				originData.Jobs = make([]GitlabPipelineJobData, 0)
				// Add current include (origin) data to the result
				data.Origins = append(data.Origins, originData)
				continue
			}

			// Get inputs for this include from the map using the origin hash
			// The hash was already calculated
			includeInputs := includeInputsMap[originData.OriginHash]
			lInclude.WithFields(logrus.Fields{
				"originHash": originData.OriginHash,
				"inputs":     includeInputs,
			}).Debug("Fetching include with inputs")

			// Fetch the include with inputs and stages from the merged configuration
			// Stages are needed because components may reference custom stages defined at the root level
			var jobsFromInclude []string
			jobsFromInclude, err = gitlab.FetchGitlabInclude(include, project.Path, token, conf.GitlabURL, project.LatestHeadCommitSha, conf, includeInputs, data.MergedConf.Stages)
			if err != nil {
				lInclude.WithError(err).Error("Unable to fetch include from GitLab")
				// If we cannot retrieve the include, next
				continue
			}
			lInclude.WithField("jobs", jobsFromInclude).Debug("Job list to analyze")

			// Initialize originData.Jobs to avoid it to be nil
			originData.Jobs = make([]GitlabPipelineJobData, 0, len(jobsFromInclude))

			////////////////////////////////////////////////////////////////////
			////////// Add origin data to all jobs that extends jobs from the //
			////////// current include                                        //
			////////////////////////////////////////////////////////////////////

			for _, jobExtendSource := range jobsFromInclude {

				// If job is not extended by any other job, next
				if _, ok := data.JobExtendsMap[jobExtendSource]; !ok {
					continue
				}

				for _, job := range data.JobExtendsMap[jobExtendSource] {

					// If job does not exist in final result, next
					if _, ok := data.JobMap[job]; !ok {
						lInclude.WithFields(logrus.Fields{
							"allJobsFromMergedResult": data.JobMap,
							"jobExtendSource":         jobExtendSource,
							"jobExtendMap":            data.JobExtendsMap[jobExtendSource],
						}).Error("Job extended by a job from an include does not exist in merged final result")
						continue
					}

					// If job was in hardocoded list, it means it has overrides
					if _, ok := data.JobHardcodedMap[job]; ok {

						// Job is not hardcoded
						data.JobHardcodedMap[job] = false
						data.JobMap[job].IsHardocded = false

						// Job is overriden
						data.JobMap[job].IsOverridden = true
					}

					// Add the job to this origin
					originData.Jobs = append(originData.Jobs, *data.JobMap[job])
				}
			}

			//////////////////////////////////////////////////////////////////
			////////// Add origin data to all jobs directly coming from the //
			////////// current include                                      //
			//////////////////////////////////////////////////////////////////

			for _, job := range jobsFromInclude {

				// If job does not exist in final result, next
				if _, ok := data.JobMap[job]; !ok {
					lInclude.WithFields(logrus.Fields{
						"currentJobFromInclude":   job,
						"allJobsFromMergedResult": data.JobMap,
					}).Error("Job retrieved in include does not exist in merged final result")
					continue
				}

				// If job was in hardocoded list, it means it has overrides
				if _, ok := data.JobHardcodedMap[job]; ok {

					// Job is not hardcoded
					data.JobHardcodedMap[job] = false
					data.JobMap[job].IsHardocded = false

					// Job is overriden
					data.JobMap[job].IsOverridden = true
				}

				// Add the job to this origin
				originData.Jobs = append(originData.Jobs, *data.JobMap[job])
			}

			// Add current include (origin) data to the result
			data.Origins = append(data.Origins, originData)
		}

		/////////////////////////////////////////////////
		////////// Create an origin for hardcoded jobs //
		/////////////////////////////////////////////////

		originData := GitlabPipelineOriginDataFull{}
		originData.GitlabComponent = GitlabPipelineJobGitlabComponent{}
		originData.GitlabIncludeOrigin = gitlab.IncludeOriginWithoutRef{}
		originData.OriginType = originHardcoded
		originData.Jobs = make([]GitlabPipelineJobData, 0, len(data.JobHardcodedMap))

		// Add all hardcoded jobs (excluding overridden jobs)
		for name, isHardcoded := range data.JobHardcodedMap {

			// Skip if not actually hardcoded (i.e., it's overridden)
			if !isHardcoded {
				continue
			}

			// Search in jobMap (all job from merged version)
			if _, jobFound := data.JobMap[name]; !jobFound {
				l.WithField("jobHardcoded", name).Warning("Job hardcoded in conf is not found in job list from merged conf")
				continue
			}
			originData.Jobs = append(originData.Jobs, *data.JobMap[name])
		}
		// Add hardcoded origin data to the result
		data.Origins = append(data.Origins, originData)
	}

	// Compute metrics

	// Job metrics
	metrics.JobTotal = uint(len(data.JobMap))

	// Count only truly hardcoded jobs (excluding overridden ones)
	hardcodedCount := 0
	for _, isHardcoded := range data.JobHardcodedMap {
		if isHardcoded {
			hardcodedCount++
		}
	}
	metrics.JobHardcoded = uint(hardcodedCount)

	// Origin metrics
	metrics.OriginTotal = uint(len(data.Origins))

	// Count origins by type
	for _, origin := range data.Origins {
		switch origin.OriginType {
		case originComponent:
			metrics.OriginComponent++
		case originLocal:
			metrics.OriginLocal++
		case originProject:
			metrics.OriginProject++
		case originRemote:
			metrics.OriginRemote++
		case originTemplate:
			metrics.OriginTemplate++
		}

		// Count GitLab catalog origins
		if origin.FromGitlabCatalog {
			metrics.OriginGitLabCatalog++
		}

		// Count outdated origins (those that are not up to date)
		if origin.FromGitlabCatalog && !origin.UpToDate {
			metrics.OriginOutdated++
		}
	}

	// Return the populated analysis data
	return data, metrics, nil
}
