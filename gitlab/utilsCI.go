package gitlab

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	errUnknownIncludedType = "unknown included type"

	IncludeFile        = "file"
	IncludeRemote      = "remote"
	includeConfPrefix  = "include:\n-"
	includeFileProject = "project"
	includeFileRef     = "ref"
	includeLocal       = "local"
	includeTemplate    = "template"
	includeComponent   = "component"
)

// GetMapKeys returns the keys of a string map as a slice (for safe logging without values)
func GetMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Convert map[interface{}]interface{} to map[string]interface{} for JSON-safe logging
func toJSONSafeMap(m interface{}) interface{} {
	switch v := m.(type) {
	case map[interface{}]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			strKey := fmt.Sprintf("%v", key)
			result[strKey] = toJSONSafeMap(value)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = toJSONSafeMap(item)
		}
		return result
	default:
		return v
	}
}

// ParseDefaultImage parses the default image from a GitLab CI configuration
func ParseDefaultImage(conf *GitlabCIConf) (string, error) {
	l := logger.WithFields(logrus.Fields{
		"action": "ParseDefaultImage",
	})

	defaultImage := ""
	var err error

	if conf.Default.Image != nil {
		defaultImage, err = GetImageName(conf.Default.Image)
		if err != nil {
			l.WithError(err).Error("Unable to parse the image name of default image")
			return defaultImage, err
		}
	} else if conf.Image != nil {
		defaultImage, err = GetImageName(conf.Image)
		if err != nil {
			l.WithError(err).Error("Unable to parse the image at root")
			return defaultImage, err
		}
	}

	return defaultImage, nil
}

// ParseGlobalVariables parses global variables of a GitLab CI conf
func ParseGlobalVariables(conf *GitlabCIConf) (map[string]string, error) {
	l := logger.WithFields(logrus.Fields{
		"action": "ParseGlobalVariables",
	})

	globalCiConfVariables := map[string]string{}
	for key, value := range conf.GlobalVariables {
		value, err := GetVariableValue(value)
		if err != nil {
			l.WithError(err).WithFields(logrus.Fields{
				"variableKey":   key,
				"variableValue": value,
			}).Error("Unable to parse a global variable")
			return globalCiConfVariables, err
		}
		globalCiConfVariables[key] = value
	}

	return globalCiConfVariables, nil
}

// ParseJobVariables parses job variables from a GitLab CI conf
func ParseJobVariables(job *GitlabJob) (map[string]string, error) {
	l := logger.WithFields(logrus.Fields{
		"action": "ParseJobVariables",
	})

	variables := map[string]string{}

	for key, value := range job.Variables {
		value, err := GetVariableValue(value)
		if err != nil {
			l.WithError(err).WithFields(logrus.Fields{
				"variableKey":   key,
				"variableValue": value,
			}).Error("Unable to parse a job variable")
			return variables, err
		}
		variables[key] = value
	}

	return variables, nil
}

// ProjectInfo contains basic project information for CI analysis
type ProjectInfo struct {
	ID                  int // Project ID on GitLab
	Path                string
	CiConfPath          string
	DefaultBranch       string // The actual default branch from GitLab (e.g., "main")
	AnalyzeBranch       string // The branch to analyze (from --branch flag, defaults to DefaultBranch)
	LatestHeadCommitSha string
	Archived            bool
	NotFound            bool
	IsGroup             bool // True if organization is a group (vs instance-wide)
}

// GetFullGitlabCI retrieves the full GitLab CI configuration for a project
func GetFullGitlabCI(project *ProjectInfo, ref, token, url string, conf *configuration.Configuration) (*GitlabCIConf, *GitlabCIConf, *MergedCIConfResponse, string, string, error) {
	l := logger.WithFields(logrus.Fields{
		"action":      "GetFullGitlabCI",
		"projectPath": project.Path,
	})

	gitlabConf := GitlabCIConf{}
	mergedConf := GitlabCIConf{}
	mergedResponse := MergedCIConfResponse{}

	if project.Archived {
		l.Info("Archived project, cannot retrieve merged CI conf")
		return nil, nil, nil, "", "", nil
	}

	if project.NotFound {
		l.Info("Project not found on GitLab, cannot retrieve merged CI conf")
		return nil, nil, nil, "", "", nil
	}

	// Get the configuration file
	confByte, errPlatform, err := FetchGitlabFile(project.Path, project.CiConfPath, ref, token, url, conf)
	confStr := string(confByte)
	if err != nil || errPlatform != nil {
		l.WithFields(logrus.Fields{
			"err":         err,
			"errPlatform": errPlatform,
		}).Error("Unable to get project's CI conf file")

		if errPlatform != nil {
			return nil, nil, nil, "", "", errPlatform
		}
		return nil, nil, nil, "", "", err
	}

	// Get the merged response
	mergedResponse, err = FetchGitlabMergedCIConf(project.Path, confStr, project.LatestHeadCommitSha, token, url, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get project's CI merged conf")
		return nil, nil, nil, confStr, "", err
	}

	// Unmarshal the original configuration
	if err := yaml.Unmarshal(confByte, &gitlabConf); err != nil {
		if mergedResponse.CiConfig.Status == "INVALID" {
			l.WithError(err).Info("Unable to unmarshal the configuration to GitlabCIConf, but the CI config is invalid")
			return nil, nil, &mergedResponse, confStr, mergedResponse.CiConfig.MergedYaml, nil
		}

		l.WithError(err).Error("Unable to unmarshal the configuration to GitlabCIConf")
		return nil, nil, &mergedResponse, confStr, mergedResponse.CiConfig.MergedYaml, err
	}

	// Extract and unmarshal the merged configuration
	if err := yaml.Unmarshal([]byte(mergedResponse.CiConfig.MergedYaml), &mergedConf); err != nil {
		l.WithError(err).Error("Unable to unmarshal the merged configuration to GitlabCIConf")
		return &gitlabConf, nil, &mergedResponse, confStr, mergedResponse.CiConfig.MergedYaml, err
	}

	return &gitlabConf, &mergedConf, &mergedResponse, confStr, mergedResponse.CiConfig.MergedYaml, nil
}

// ParseGitlabCIJob parses a job from GitLab CI conf
func ParseGitlabCIJob(jobContent interface{}) (*GitlabJob, error) {
	l := logger.WithFields(logrus.Fields{
		"action": "ParseGitlabCIJob",
	})

	job := GitlabJob{}

	switch jobType := jobContent.(type) {
	case map[interface{}]interface{}:
		l.Debug("Found a correct job")
		yamlData, err := yaml.Marshal(jobContent)
		if err != nil {
			l.WithError(err).WithFields(logrus.Fields{
				"converted": "json-safe",
				"job":       toJSONSafeMap(jobContent),
			}).Error("Could not marshal the job")
			return &job, err
		}
		err = yaml.Unmarshal(yamlData, &job)
		if err != nil {
			l.WithError(err).WithFields(logrus.Fields{
				"converted": "json-safe",
				"job":       toJSONSafeMap(jobContent),
				"yamlJob":   string(yamlData),
			}).Error("Could not unmarshal the job")
			return &job, err
		}
	default:
		l.WithFields(logrus.Fields{
			"converted": "json-safe",
			"job":       toJSONSafeMap(jobContent),
			"jobType":   jobType,
		}).Info("Found a job that is not a map")
	}

	return &job, nil
}

// ReplaceVariable replaces variables in the input string recursively up to 5 levels
func ReplaceVariable(input string, project, group, instance, job, defaultJob, predefined map[string]string) string {
	regex := `(\$[a-zA-Z_][a-zA-Z0-9_]*|\${[a-zA-Z_][a-zA-Z0-9_]*}|%[a-zA-Z_][a-zA-Z0-9_]*%)`
	r := regexp.MustCompile(regex)

	resolveVariables := func(input string) string {
		return r.ReplaceAllStringFunc(input, func(match string) string {
			varName := regexp.MustCompile(`[\$\{\}%]`).ReplaceAllString(match, "")

			if val, found := project[varName]; found {
				return val
			}
			if val, found := group[varName]; found {
				return val
			}
			if val, found := instance[varName]; found {
				return val
			}
			if val, found := job[varName]; found {
				return val
			}
			if val, found := defaultJob[varName]; found {
				return val
			}
			if val, found := predefined[varName]; found {
				return val
			}

			return match
		})
	}

	maxLevels := 5
	previous := ""
	current := input
	level := 0

	for current != previous && level < maxLevels {
		previous = current
		current = resolveVariables(previous)
		level++
	}

	return current
}

// IsRunningInCI checks if the code is running inside a GitLab CI environment
// by checking if the CI environment variable is set to "true"
func IsRunningInCI() bool {
	ciEnv := os.Getenv("CI")
	return strings.ToLower(ciEnv) == "true"
}

// ReplaceVariableFromEnv replaces variables in the input string using environment variables
// This is used when running in CI mode where all variables are available in the environment
func ReplaceVariableFromEnv(input string) string {
	regex := `(\$[a-zA-Z_][a-zA-Z0-9_]*|\${[a-zA-Z_][a-zA-Z0-9_]*}|%[a-zA-Z_][a-zA-Z0-9_]*%)`
	r := regexp.MustCompile(regex)

	resolveFromEnv := func(input string) string {
		return r.ReplaceAllStringFunc(input, func(match string) string {
			varName := regexp.MustCompile(`[\$\{\}%]`).ReplaceAllString(match, "")

			if val := os.Getenv(varName); val != "" {
				return val
			}

			// Variable not found in environment, keep it as-is
			return match
		})
	}

	// Resolve recursively up to 5 levels (for nested variables)
	maxLevels := 5
	previous := ""
	current := input
	level := 0

	for current != previous && level < maxLevels {
		previous = current
		current = resolveFromEnv(previous)
		level++
	}

	return current
}

// GetImageName gets the image name from an interface parsed from gitlab ci file
func GetImageName(imageInterface interface{}) (string, error) {
	l := logrus.WithFields(logrus.Fields{
		"action": "GetImageName",
	})

	switch image := imageInterface.(type) {
	case map[interface{}]interface{}:
		l.Debug("Found an image declaration as map")
		imageStruct := Image{}
		yamlData, err := yaml.Marshal(image)
		if err != nil {
			l.WithError(err).WithFields(logrus.Fields{
				"converted": "json-safe",
				"image":     toJSONSafeMap(image),
			}).Error("Could not marshal the image")
			return "", err
		}
		err = yaml.Unmarshal(yamlData, &imageStruct)
		if err != nil {
			l.WithError(err).WithFields(logrus.Fields{
				"converted": "json-safe",
				"image":     toJSONSafeMap(image),
				"yamlImage": string(yamlData),
			}).Error("Could not unmarshal the image")
			return "", err
		}
		return imageStruct.Name, nil

	case string:
		l.WithField("image", image).Debug("Found an image declaration as simple string")
		return image, nil

	case nil:
		l.Debug("No image declaration")
		return "", nil

	default:
		l.WithFields(logrus.Fields{
			"converted": "json-safe",
			"imageType": fmt.Sprintf("%T", image),
			"image":     toJSONSafeMap(image),
		}).Error("Found an image with unknown type")
		return "", nil
	}
}

// GetVariableValue gets the variable value from an interface parsed from gitlab ci file
func GetVariableValue(valueInterface interface{}) (string, error) {
	l := logrus.WithFields(logrus.Fields{
		"action": "GetVariableValue",
	})

	switch value := valueInterface.(type) {
	case map[interface{}]interface{}:
		currentVariable := CIConfVariable{}
		l.Debug("Found a variable of type map[string]interface")
		yamlData, err := yaml.Marshal(value)
		if err != nil {
			l.WithError(err).WithFields(logrus.Fields{
				"converted": "json-safe",
				"value":     toJSONSafeMap(value),
			}).Error("Could not marshal the variable")
			return "", err
		}
		err = yaml.Unmarshal(yamlData, &currentVariable)
		if err != nil {
			l.WithError(err).WithFields(logrus.Fields{
				"converted": "json-safe",
				"value":     toJSONSafeMap(value),
				"yamlValue": string(yamlData),
			}).Info("Could not unmarshal the variable")
		}
		return currentVariable.Value, nil

	case string:
		l.WithField("value", value).Debug("Found a variable of type string")
		return value, nil

	case int:
		l.WithField("value", value).Debug("Found a variable of type int")
		return strconv.Itoa(value), nil

	case bool:
		l.WithField("value", value).Debug("Found a variable of type bool")
		if value {
			return "true", nil
		}
		return "false", nil

	case nil:
		l.Debug("No value")
		return "", nil

	default:
		l.WithFields(logrus.Fields{
			"converted": "json-safe",
			"valueType": fmt.Sprintf("%T", value),
			"value":     toJSONSafeMap(value),
		}).Error("Found a variable with unknown type")
		return "", nil
	}
}

// GetExtends gets the extends entry and returns a slice of string with all extends
func GetExtends(extendsInterface interface{}) ([]string, error) {
	l := logrus.WithFields(logrus.Fields{
		"action": "GetExtends",
	})

	switch extends := extendsInterface.(type) {
	case string:
		return []string{extends}, nil

	case []interface{}:
		var stringsSlice []string
		for _, v := range extends {
			str, ok := v.(string)
			if !ok {
				l.WithFields(logrus.Fields{
					"converted": "json-safe",
					"valueType": fmt.Sprintf("%T", v),
					"value":     toJSONSafeMap(v),
				}).Error("Found an element in extends slice that is not a string")
				return []string{}, nil
			}
			stringsSlice = append(stringsSlice, str)
		}
		return stringsSlice, nil

	default:
		l.WithFields(logrus.Fields{
			"converted": "json-safe",
			"valueType": fmt.Sprintf("%T", extends),
			"value":     toJSONSafeMap(extends),
		}).Error("Found an extends with unknown type")
		return []string{}, nil
	}
}

// ParseGitlabCI parses a .gitlab-ci.yml file
func ParseGitlabCI(fileContent []byte) (*GitlabCIConf, error) {
	l := logrus.WithFields(logrus.Fields{
		"action": "ParseGitlabCI",
	})

	gitlabCi := GitlabCIConf{}

	if err := yaml.Unmarshal(fileContent, &gitlabCi); err != nil {
		return &gitlabCi, err
	}

	l.Info("Gitlab CI file parsed")
	return &gitlabCi, nil
}

// FetchGitlabInclude retrieves all jobs from a CI conf include
func FetchGitlabInclude(include MergedCIConfResponseInclude, projectPath, token, APIURL, sha string, conf *configuration.Configuration, inputs map[string]interface{}, stages []string) ([]string, error) {
	l := logrus.WithFields(logrus.Fields{
		"action":  "FetchGitlabInclude",
		"include": include,
		"inputs":  inputs,
		"stages":  stages,
	})

	l.Debug("Include analyze in progress")

	// Add stages from the merged configuration if present
	var includeConf string
	if len(stages) > 0 {
		includeConf = "stages:\n"
		for _, stage := range stages {
			includeConf += fmt.Sprintf("  - %s\n", stage)
		}
		includeConf += "\n"
	}

	// Build a gitlab ci conf with the include
	var includeSection string
	switch include.Type {
	case includeLocal:
		includeSection = fmt.Sprintf("%v %v: \"%v\"",
			includeConfPrefix,
			includeLocal,
			include.Location)

	case IncludeFile:
		includeSection = fmt.Sprintf("%v %v: \"%v\"\n  %v: \"%v\"",
			includeConfPrefix,
			IncludeFile,
			include.Location,
			includeFileProject,
			include.Extra.Project)

		if include.Extra.Ref != "" {
			includeSection = fmt.Sprintf("%v\n  %v: \"%v\"",
				includeSection,
				includeFileRef,
				include.Extra.Ref)
		}

	case includeTemplate:
		includeSection = fmt.Sprintf("%v %v: \"%v\"",
			includeConfPrefix,
			includeTemplate,
			include.Location)

	case IncludeRemote:
		includeSection = fmt.Sprintf("%v %v: \"%v\"",
			includeConfPrefix,
			IncludeRemote,
			include.Location)

	case includeComponent:
		includeSection = fmt.Sprintf("%v %v: \"%v\"",
			includeConfPrefix,
			includeComponent,
			include.Location)

	default:
		l.WithField("type", include.Type).Error(errUnknownIncludedType)
		return []string{}, errors.New(errUnknownIncludedType)
	}

	includeConf += includeSection

	// Add inputs if present
	if len(inputs) > 0 {
		inputsYaml, err := yaml.Marshal(inputs)
		if err != nil {
			l.WithError(err).Warn("Unable to marshal inputs to YAML")
		} else {
			includeConf += "\n  inputs:"
			inputsLines := strings.Split(strings.TrimSpace(string(inputsYaml)), "\n")
			for _, line := range inputsLines {
				includeConf += fmt.Sprintf("\n    %s", line)
			}
		}
	}

	l.WithField("includeConf", includeConf).Debug("Configuration with only include built")

	// Get the merged conf for the built conf
	mergedInclude, err := FetchGitlabMergedCIConf(projectPath, includeConf, sha, token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get merged conf for the include")
		return []string{}, err
	}
	if len(mergedInclude.CiConfig.Errors) > 0 {
		l.WithField("errors", mergedInclude.CiConfig.Errors).Debug("CI errors found in include's merged configuration (may not affect analysis)")
	}

	l.WithField("mergedYaml", mergedInclude.CiConfig.MergedYaml).Debug("Merged YAML from GitLab")

	// Unmarshal the merged configuration
	gitlabCIMerged := GitlabCIConf{}
	if err := yaml.Unmarshal([]byte(mergedInclude.CiConfig.MergedYaml), &gitlabCIMerged); err != nil {
		l.WithError(err).Error("Unable to unmarshal the include's merged configuration to GitlabCIConf")
		return []string{}, err
	}

	l.WithFields(logrus.Fields{
		"parsedJobsCount": len(gitlabCIMerged.GitlabJobs),
		"parsedStages":    gitlabCIMerged.Stages,
	}).Debug("Parsed GitLab CI configuration")

	// Add all jobs from merged conf in a slice
	jobsFromInclude := []string{}
	for name := range gitlabCIMerged.GitlabJobs {
		jobsFromInclude = append(jobsFromInclude, name)
	}

	l.WithField("jobsFromInclude", jobsFromInclude).Debug("Fetch of jobs from include done")
	return jobsFromInclude, nil
}
