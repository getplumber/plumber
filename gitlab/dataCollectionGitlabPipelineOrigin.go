package gitlab

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/getplumber/plumber/configuration"
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
	plumberLatestTag            = "latest"
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

	// Gitlab CI configuration
	Conf            *GitlabCIConf
	ConfString      string
	MergedConf      *GitlabCIConf
	MergedResponse  *MergedCIConfResponse
	CiValid         bool
	CiMissing       bool
	CiErrors        []string // Specific CI config errors for output
	IncludesFailed  []string // include locations whose fetch failed (jobs dropped from analysis, #220)
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
	FromPlumber         bool                             `json:"fromPlumber"`
	FromGitlabCatalog   bool                             `json:"fromGitlabCatalog"`
	PlumberOrigin       GitlabPipelineJobPlumberOrigin   `json:"plumberOrigin"`
	GitlabIncludeOrigin IncludeOriginWithoutRef          `json:"gitlabIncludeOrigin"`
	GitlabComponent     GitlabPipelineJobGitlabComponent `json:"gitlabComponent"`
	OriginHash          uint64                           `json:"originHash"`
}

// GitlabPipelineJobPlumberOrigin represents a Plumber template origin
type GitlabPipelineJobPlumberOrigin struct {
	ID                uint   `json:"id"`
	Path              string `json:"path"`
	LatestVersion     string `json:"latestVersion"`
	RepoDefaultBranch string `json:"repoDefaultBranch"`
}

type GitlabPipelineOriginDataProjectSpecific struct {
	// Data specific to this project
	Version  string `json:"version"`
	UpToDate bool   `json:"upToDate"`
	Nested   bool   `json:"nested"`
	// RefIsAmbiguous: the pinned Version resolves upstream as both a
	// tag and a branch (ref-confusion, ISSUE-402). Set by the origin
	// collector's tag+branch probe; false unless both are confirmed.
	RefIsAmbiguous bool `json:"refIsAmbiguous"`

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

// Predefined GitLab project-path variables we can resolve from the scanned
// project's full path. Each pattern ends on a word boundary (\b) so a longer
// variable that merely shares a prefix is left untouched instead of being
// corrupted: without the boundary, replacing $CI_PROJECT_PATH inside
// $CI_PROJECT_PATH_SLUG would yield "<path>_SLUG", and $CI_PROJECT_NAMESPACE
// inside $CI_PROJECT_NAMESPACE_ID would yield "<namespace>_ID". Because each
// pattern is anchored on the full variable name plus a boundary, ordering no
// longer matters for correctness.
var (
	reCIProjectRootNamespace = regexp.MustCompile(`\$CI_PROJECT_ROOT_NAMESPACE\b`)
	reCIProjectNamespace     = regexp.MustCompile(`\$CI_PROJECT_NAMESPACE\b`)
	reCIProjectPath          = regexp.MustCompile(`\$CI_PROJECT_PATH\b`)
	reCIProjectName          = regexp.MustCompile(`\$CI_PROJECT_NAME\b`)
)

// resolvePredefinedProjectVars substitutes the predefined GitLab CI project
// variables that can appear in a component/include path with their values for
// the scanned project. GitLab resolves these server-side before fetching the
// component, so the main-loop origin hash is built from the resolved path; we
// must resolve them the same way here or the include's inputs-map hash will not
// match, the inputs are dropped, and an overridden component job is misreported
// as hardcoded (ISSUE-401, #286).
func resolvePredefinedProjectVars(path, projectPath string) string {
	if projectPath == "" || !strings.Contains(path, "$CI_PROJECT_") {
		return path
	}

	namespace, name := projectPath, projectPath
	if i := strings.LastIndex(projectPath, "/"); i >= 0 {
		namespace = projectPath[:i] // group path, e.g. "swepy/cicd-templates"
		name = projectPath[i+1:]    // project slug, e.g. "ci-trigger"
	}
	rootNamespace, _, _ := strings.Cut(projectPath, "/") // top-level group, e.g. "swepy"

	// ReplaceAllLiteralString avoids interpreting "$" in the replacement value
	// as a capture-group reference (GitLab paths never contain "$", but this is
	// defensive and free).
	path = reCIProjectRootNamespace.ReplaceAllLiteralString(path, rootNamespace)
	path = reCIProjectNamespace.ReplaceAllLiteralString(path, namespace)
	path = reCIProjectPath.ReplaceAllLiteralString(path, projectPath)
	path = reCIProjectName.ReplaceAllLiteralString(path, name)
	return path
}

// splitComponentPath splits a GitLab component cleanPath
// ("group/.../project/component") into the project full path and the component
// name (the last segment). GitLab component includes are always
// <project-full-path>/<component-name>, so the project is everything before the
// final "/". Used to resolve the project's catalog resource / git tags (#156).
func splitComponentPath(cleanPath string) (project string, component string) {
	i := strings.LastIndex(cleanPath, "/")
	if i < 0 {
		return "", cleanPath
	}
	return cleanPath[:i], cleanPath[i+1:]
}

// isFullCommitSHA reports whether s is a 40-character lowercase hex commit
// SHA. SHA-pinned includes are unambiguous, so ref-confusion (ISSUE-402)
// skips them.
func isFullCommitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// shouldProbeRefAmbiguity reports whether a pinned include version is a
// literal symbolic ref worth probing for a tag/branch collision
// (ref-confusion, ISSUE-402). Exempt: empty (local include, no ref),
// ~latest / latest (catalog-resolved, not a literal ref), HEAD, and full
// commit SHAs (unambiguous by construction).
func shouldProbeRefAmbiguity(version string) bool {
	switch strings.TrimSpace(version) {
	case "", "~latest", "latest", "HEAD":
		return false
	}
	return !isFullCommitSHA(strings.TrimSpace(version))
}

// latestSemver returns the newest version from versions using semantic-version
// ordering, falling back to lexicographic order for non-semver strings. Returns
// "" for an empty slice.
func latestSemver(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	out := append([]string(nil), versions...)
	sort.Slice(out, func(i, j int) bool {
		v1, e1 := gover.NewVersion(out[i])
		v2, e2 := gover.NewVersion(out[j])
		if e1 == nil && e2 == nil {
			return v1.GreaterThan(v2)
		}
		return out[i] > out[j]
	})
	return out[0]
}

// latestCatalogVersion returns the newest released version of the resource that
// still carries the named component. Components are versioned with their
// project, but a component can be added or removed across releases, so we only
// consider versions that actually contain it.
func latestCatalogVersion(resource *CICatalogResource, component string) string {
	if resource == nil {
		return ""
	}
	candidates := make([]string, 0, len(resource.Versions))
	for _, v := range resource.Versions {
		for _, c := range v.Components {
			if c.Name == component {
				candidates = append(candidates, v.Name)
				break
			}
		}
	}
	return latestSemver(candidates)
}

// extractInputsFromInclude extracts inputs from a single include entry and generates its hash
// includeEntry can be a string (simple include) or a map (include with properties)
// Returns: hash (uint64), inputs (map), error
func extractInputsFromInclude(includeEntry interface{}, instanceURL, projectPath string) (uint64, map[string]interface{}, error) {
	// If it's a string, create a simple include origin
	if includeStr, ok := includeEntry.(string); ok {
		// Simple string includes are typically templates or remote URLs
		includeOrigin := IncludeOriginWithoutRef{
			Location: includeStr,
			Type:     "", // Will be empty for simple strings
			Project:  "",
		}
		hash, err := generateIncludeHash(includeOrigin)
		return hash, nil, err
	}

	// If it's a map, extract location, type, project and inputs
	if includeMap, ok := includeEntry.(map[interface{}]interface{}); ok {
		var includeOrigin IncludeOriginWithoutRef
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

			// GitLab also resolves predefined project variables ($CI_PROJECT_NAMESPACE,
			// ...) in the component path before fetching it, so the main-loop hash is
			// built from the resolved path. Substitute them here too, otherwise the
			// hash mismatches, the include's inputs are dropped, and an overridden
			// component job is misreported as hardcoded (ISSUE-401, #286).
			cleanPath = resolvePredefinedProjectVars(cleanPath, projectPath)

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
func generateIncludeHash(includeOrigin IncludeOriginWithoutRef) (uint64, error) {
	gitlabIncludeOriginByte, err := json.Marshal(includeOrigin)
	if err != nil {
		return 0, err
	}
	return utils.GenerateFNVHash(gitlabIncludeOriginByte), nil
}

// buildIncludeInputsMap builds a map of include hash to inputs from the GitLab CI configuration
// The map is used to pass the correct inputs when fetching includes
// Uses the same hash mechanism as the main origin detection loop for consistency
func buildIncludeInputsMap(gitlabConf *GitlabCIConf, instanceURL, projectPath string) map[uint64]map[string]interface{} {
	includeInputsMap := make(map[uint64]map[string]interface{})

	if gitlabConf == nil || gitlabConf.Include == nil {
		return includeInputsMap
	}

	// Process each include entry
	for _, includeEntry := range gitlabConf.Include {
		hash, inputs, err := extractInputsFromInclude(includeEntry, instanceURL, projectPath)
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

func (dc *GitlabPipelineOriginDataCollection) Run(project *ProjectInfo, token string, conf *configuration.Configuration) (*GitlabPipelineOriginData, *GitlabPipelineOriginMetrics, error) {
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
	// Use project.AnalyzeBranch as ref (set via --branch CLI flag, defaults to DefaultBranch)
	data.Conf, data.MergedConf, data.MergedResponse, data.ConfString, _, err = GetFullGitlabCI(project, project.AnalyzeBranch, token, conf.GitlabURL, conf)
	if err != nil {
		data.LimitedAnalysis = true
		data.CiValid = false
		data.CiMissing = false

		// Check if this is a 404 error when project.NotFound is false
		if strings.Contains(err.Error(), "404") && !project.NotFound {
			// A 404 on the CI config is ambiguous: the requested branch may
			// not exist, or it exists but simply has no .gitlab-ci.yml. Tell
			// them apart so a non-existent --branch fails loudly instead of
			// rendering a confusing limited report at 0%/FAILED with a
			// 100/100 score (#222). A branch probe that itself fails (auth,
			// network) falls through to the limited-data path rather than
			// masking the original error.
			if exists, berr := BranchExists(project.ID, project.AnalyzeBranch, token, conf.GitlabURL, conf); berr == nil && !exists {
				return nil, nil, fmt.Errorf("branch or ref %q not found in %s", project.AnalyzeBranch, project.Path)
			}
			// In this case, it's CI missing rather than an analysis error
			data.CiMissing = true
			data.CiValid = true // It's not really valid (missing) but we keep it to avoid false positive on "invalid"
			l.WithError(err).Warn("Unable to retrieve project's CI configuration (404). CI is missing but project exists. Data collection will continue with limited data.")
		} else {
			data.CiValid = false
			// Store the error as a CI error so it can be shown in the output
			data.CiErrors = []string{err.Error()}
			l.WithError(err).Warn("Unable to retrieve project's CI merged configuration. Data collection will continue with limited data.")
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
		l.WithField("errors", data.MergedResponse.CiConfig.Errors).Warn("Pipeline has configuration errors. Data collection will continue with limited data.")

	} else if data.MergedResponse == nil || data.MergedConf == nil {

		data.LimitedAnalysis = true
		data.CiValid = true   // It's not really valid (missing) but we keep it to avoid false positive on "invalid"
		data.CiMissing = true // CI is empty/missing
		l.Warn("Pipeline is empty. Data collection will continue with limited data.")

	}

	// If we weren't able to retrieve the pipelines (invalid configuration, archived project, unauthorized, ...), we stop here
	if data.LimitedAnalysis {
		// Return empty result for limited analysis
		return data, metrics, nil
	}

	// Component latest-version resolution (#156).
	//
	// We no longer enumerate the whole instance catalog up front
	// (ciCatalogResources(scope: ALL)): on gitlab.com that query returns a
	// ~2 MB / 30 s+ payload that exceeds the HTTP timeout, gets cancelled, and
	// silently leaves every component "up to date". Instead each component
	// include resolves its project on demand via a targeted
	// ciCatalogResource(fullPath:) lookup (cheap and complete). Results are
	// cached per project so repeated includes from the same project share one
	// query.
	catalogCache := map[string]*CICatalogResource{}
	catalogTried := map[string]bool{}
	resolveComponentLatest := func(project, component string) (latest, webPath, repoName string) {
		webPath = "/" + project
		repoName = component
		if !catalogTried[project] {
			r, qerr := GetGitlabCIComponentResource(project, token, conf.GitlabURL, conf)
			if qerr != nil {
				l.WithError(qerr).WithField("project", project).Debug("catalog resource lookup failed")
			}
			catalogCache[project] = r
			catalogTried[project] = true
		}
		if r := catalogCache[project]; r != nil {
			latest = latestCatalogVersion(r, component)
			if r.WebPath != "" {
				webPath = r.WebPath
			}
			if r.Name != "" {
				repoName = r.Name
			}
		}
		return latest, webPath, repoName
	}

	////////////////////////////////////////////////////////
	// Build map of include identifiers to their inputs  //
	////////////////////////////////////////////////////////

	// This map will help us pass the correct inputs when fetching includes
	// Key: include hash (same hash used for origin tracking)
	// Value: map of input name to input value
	includeInputsMap := buildIncludeInputsMap(data.Conf, conf.GitlabURL, project.Path)
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
			var job *GitlabJob
			job, err = ParseGitlabCIJob(content)
			if err != nil {
				l.WithError(err).Error("Unable to parse the job retrieved from CI conf")
				return data, metrics, err
			}

			// Get the extends value
			extends := []string{}
			if job.Extends != nil {
				extendsResult, err := GetExtends(job.Extends)
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
			originData.FromPlumber = false
			originData.FromGitlabCatalog = false
			originData.Version = ""
			originData.UpToDate = false
			originData.Nested = isNested
			originData.PlumberOrigin = GitlabPipelineJobPlumberOrigin{}
			originData.GitlabComponent = GitlabPipelineJobGitlabComponent{}
			originData.GitlabIncludeOrigin = IncludeOriginWithoutRef{
				Location: include.Location,
				Type:     include.Type,
				Project:  include.Extra.Project,
			}

			// Prepare latest ref slice to check version
			latestRefs := []string{gitHeadRef, project.DefaultBranch, plumberLatestTag, glTildeLatestTag, mainBranch, masterBranch}

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

				// Resolve the component's latest published version via a targeted
				// catalog lookup (cached), falling back to the project's git tags (#156).
				project, componentName := splitComponentPath(cleanPath)
				if componentName == "" {
					lInclude.Warning("Component name is empty. It should not happen.")
					continue
				}
				latestVersion, webPath, repoName := resolveComponentLatest(project, componentName)
				if latestVersion != "" {
					originData.FromGitlabCatalog = true
					originData.GitlabComponent = GitlabPipelineJobGitlabComponent{
						RepoFullPath:           project + "/" + componentName,
						RepoWebPath:            webPath,
						RepoName:               repoName,
						ComponentName:          componentName,
						ComponentIncludePath:   instance + "/" + cleanPath,
						ComponentLatestVersion: latestVersion,
					}
					originData.UpToDate = IsUpToDate(version, latestVersion, latestRefs)
					lInclude.WithFields(logrus.Fields{
						"cleanPath":     cleanPath,
						"componentName": componentName,
						"latestVersion": latestVersion,
						"upToDate":      originData.UpToDate,
					}).Debug("Resolved GitLab component latest version")
				} else {
					lInclude.WithField("cleanPath", cleanPath).Debug("Could not resolve latest version for component (not in catalog and no semver tags)")
				}

				// ref-confusion (ISSUE-402): a component pinned to a name that
				// resolves upstream as BOTH a tag and a branch is ambiguous.
				// Fail-safe — only a confirmed tag+branch double-hit sets the
				// flag; a SHA / ~latest / failed probe leaves it false.
				if shouldProbeRefAmbiguity(version) {
					if tagExists, branchExists, errAmb := RefResolvesAsTagAndBranch(project, version, token, conf.GitlabURL, conf); errAmb == nil && tagExists && branchExists {
						originData.RefIsAmbiguous = true
						lInclude.WithFields(logrus.Fields{"project": project, "ref": version}).Debug("Component ref resolves as both a tag and a branch (ref-confusion)")
					}
				}

			// External file (project)
			case glOriginProject:

				// Set type
				originData.OriginType = originProject
				// Set version from ref
				originData.Version = include.Extra.Ref

				// ref-confusion (ISSUE-402): a project include whose ref
				// resolves as BOTH a tag and a branch in the source project is
				// ambiguous. Fail-safe — confirmed tag+branch double-hit only.
				if include.Extra.Project != "" && shouldProbeRefAmbiguity(include.Extra.Ref) {
					if tagExists, branchExists, errAmb := RefResolvesAsTagAndBranch(include.Extra.Project, include.Extra.Ref, token, conf.GitlabURL, conf); errAmb == nil && tagExists && branchExists {
						originData.RefIsAmbiguous = true
						lInclude.WithFields(logrus.Fields{"project": include.Extra.Project, "ref": include.Extra.Ref}).Debug("Project include ref resolves as both a tag and a branch (ref-confusion)")
					}
				}

				// Try to detect if this project include is outdated by checking tags
				// The ref format can be: templates/go/go@0.1.0
				// We need to extract the prefix (templates/go/go@) and find the latest version
				if include.Extra.Project != "" && include.Extra.Ref != "" {
					// Check if ref contains @ (version separator)
					if strings.Contains(include.Extra.Ref, "@") {
						parts := strings.Split(include.Extra.Ref, "@")
						if len(parts) == 2 {
							prefix := parts[0] + "@"
							currentVersion := parts[1]
							originData.Version = currentVersion

							// Fetch tags from the source project
							lInclude.WithFields(logrus.Fields{
								"sourceProject":  include.Extra.Project,
								"prefix":         prefix,
								"currentVersion": currentVersion,
							}).Debug("Fetching tags to check for outdated version")

							// Fetch source project info to get default branch (for forbidden version check)
							sourceProject, errProject := FetchProjectDetails(include.Extra.Project, token, conf.GitlabURL, conf)
							if errProject == nil && sourceProject != nil {
								originData.PlumberOrigin.RepoDefaultBranch = sourceProject.DefaultBranch
							}

							tags, errPlatform, err := SearchTags(include.Extra.Project, token, conf.GitlabURL, conf)
							if err != nil || errPlatform != nil {
								lInclude.WithFields(logrus.Fields{
									"err":         err,
									"errPlatform": errPlatform,
								}).Debug("Could not fetch tags from source project")
							} else {
								// Find all tags matching the prefix and extract versions
								var matchingVersions []string
								for _, tag := range tags {
									if strings.HasPrefix(tag, prefix) {
										tagVersion := strings.TrimPrefix(tag, prefix)
										if tagVersion != "" {
											matchingVersions = append(matchingVersions, tagVersion)
										}
									}
								}

								if len(matchingVersions) > 0 {
									// Sort versions (newest first) using semantic versioning
									sort.Slice(matchingVersions, func(i, j int) bool {
										v1, err1 := gover.NewVersion(matchingVersions[i])
										v2, err2 := gover.NewVersion(matchingVersions[j])
										if err1 == nil && err2 == nil {
											return v1.GreaterThan(v2)
										}
										return matchingVersions[i] > matchingVersions[j]
									})

									latestVersion := matchingVersions[0]
									originData.PlumberOrigin.LatestVersion = latestVersion
									originData.PlumberOrigin.Path = prefix[:len(prefix)-1] // Remove trailing @

									// Mark as "Plumber" origin so the control picks it up for outdated checking
									// This includes any versioned project include where we can determine latest version
									originData.FromPlumber = true

									// Check if up to date
									originData.UpToDate = IsUpToDate(currentVersion, latestVersion, latestRefs)

									lInclude.WithFields(logrus.Fields{
										"currentVersion":   currentVersion,
										"latestVersion":    latestVersion,
										"matchingVersions": matchingVersions,
										"upToDate":         originData.UpToDate,
										"fromPlumber":      originData.FromPlumber,
									}).Debug("Version check completed for project include")
								}
							}
						}
					}
				}

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

			// include:local is just the project's own CI config split into
			// multiple files — those jobs are treated as hardcoded since they
			// don't come from reusable external sources (components, templates,
			// project files from other repos, remote URLs).
			isLocalInclude := include.Type == glOriginLocal

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
			jobsFromInclude, err = FetchGitlabInclude(include, project.Path, token, conf.GitlabURL, project.LatestHeadCommitSha, conf, includeInputs, data.MergedConf.Stages)
			if err != nil {
				lInclude.WithError(err).Error("Unable to fetch include from GitLab")
				// Record the dropped include so the caller can flag the run
				// degraded: its jobs are missing from the analysis (#220).
				loc := include.Location
				if loc == "" {
					loc = include.Extra.Project
				}
				data.IncludesFailed = append(data.IncludesFailed, loc)
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
						if isLocalInclude {
							// Local include: keep as hardcoded
							data.JobHardcodedMap[job] = true
							data.JobMap[job].IsHardocded = true
						} else {
							// External include: not hardcoded
							data.JobHardcodedMap[job] = false
							data.JobMap[job].IsHardocded = false

							// Job is overriden
							data.JobMap[job].IsOverridden = true
						}
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

				if isLocalInclude {
					// Local include: mark job as hardcoded
					data.JobHardcodedMap[job] = true
					data.JobMap[job].IsHardocded = true
				} else if _, ok := data.JobHardcodedMap[job]; ok {
					// External include: not hardcoded, it has overrides
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
		originData.PlumberOrigin = GitlabPipelineJobPlumberOrigin{}
		originData.GitlabComponent = GitlabPipelineJobGitlabComponent{}
		originData.GitlabIncludeOrigin = IncludeOriginWithoutRef{}
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
		if (origin.FromPlumber || origin.FromGitlabCatalog) && !origin.UpToDate {
			metrics.OriginOutdated++
		}
	}

	// Return the populated analysis data
	return data, metrics, nil
}
