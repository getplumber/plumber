package collector

import (
	"fmt"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const DataCollectionTypeGitlabPipelineImageVersion = "0.2.0"

const (
	defaultTag      = "latest"
	dockerHubDomain = "docker.io"
	unknownRegistry = "unknown"
)

////////////////////////////
// DataCollection results //
////////////////////////////

type GitlabPipelineImageDataCollection struct{}

type GitlabPipelineImageMetrics struct {
	Total                      uint `json:"total"`
	IssueUntrusted             uint `json:"issueUntrusted"`
	IssueUntrustedDismissed    uint `json:"issueUntrustedDismissed"`
	IssueForbiddenTag          uint `json:"issueForbiddenTag"`
	IssueForbiddenTagDismissed uint `json:"issueForbiddenTagDismissed"`
}

type GitlabPipelineImageData struct {
	// Gitlab CI configuration
	MergedConf *gitlab.GitlabCIConf
	CiValid    bool
	CiMissing  bool

	// Default image and variables
	DefaultImage string
	InstanceVars map[string]string
	GroupVars    map[string]string
	ProjectVars  map[string]string
	GlobalVars   map[string]string

	// Images found in the pipeline
	Images []GitlabPipelineImageInfo `json:"images"`
}

type GitlabPipelineImageInfo struct {
	Link     string `json:"link"`
	Name     string `json:"image"`
	Tag      string `json:"tag"`
	Registry string `json:"registry"`
	Job      string `json:"job"`
}

///////////////////////////////
// Data collection functions //
///////////////////////////////

// Helper function to check if character is alphanumeric or underscore
func isAlphaNumericUnderscore(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func (i *GitlabPipelineImageInfo) handlePresenceOfVariables() {

	// Check if it contains any unresolved variables
	i.Registry = unknownRegistry
	// Set the name to the original link to preserve the variable
	i.Name = i.Link
	i.Tag = ""

	// Handle special edge cases first
	// Edge case: double colon $IMAGE::$TAG
	if strings.Contains(i.Link, "::") {
		parts := strings.Split(i.Link, "::")
		if len(parts) == 2 && strings.Count(parts[0], "$") == 1 && strings.Count(parts[1], "$") == 1 {
			i.Registry = unknownRegistry
			i.Name = parts[0]
			i.Tag = parts[1]
			return
		}
	}

	// Edge case: double slash $REGISTRY//$IMAGE:$TAG
	if strings.Contains(i.Link, "//") {
		// Extract tag first
		tag := ""
		nameWithSlash := i.Link
		if strings.Contains(i.Link, ":") {
			lastColon := strings.LastIndex(i.Link, ":")
			if lastColon > 0 && !strings.Contains(i.Link[lastColon+1:], "/") && !strings.Contains(i.Link[lastColon+1:], "$") {
				tag = i.Link[lastColon+1:]
				nameWithSlash = i.Link[:lastColon]
			} else if lastColon > 0 && strings.Count(i.Link[lastColon+1:], "$") == 1 {
				tag = i.Link[lastColon+1:]
				nameWithSlash = i.Link[:lastColon]
			}
		}
		// Fix double slash - convert // to /
		nameFixed := strings.ReplaceAll(nameWithSlash, "//", "/")
		i.Registry = unknownRegistry
		i.Name = nameFixed
		i.Tag = tag
		return
	}

	// Edge case: leading slash /$IMAGE:$TAG
	if strings.HasPrefix(i.Link, "/") {
		linkWithoutLeadingSlash := i.Link[1:]
		// Extract tag first
		if strings.Contains(linkWithoutLeadingSlash, ":") {
			lastColon := strings.LastIndex(linkWithoutLeadingSlash, ":")
			if lastColon > 0 && !strings.Contains(linkWithoutLeadingSlash[lastColon+1:], "/") && !strings.Contains(linkWithoutLeadingSlash[lastColon+1:], "$") {
				i.Registry = unknownRegistry
				i.Name = linkWithoutLeadingSlash[:lastColon]
				i.Tag = linkWithoutLeadingSlash[lastColon+1:]
				return
			} else if lastColon > 0 && strings.Count(linkWithoutLeadingSlash[lastColon+1:], "$") == 1 {
				i.Registry = unknownRegistry
				i.Name = linkWithoutLeadingSlash[:lastColon]
				i.Tag = linkWithoutLeadingSlash[lastColon+1:]
				return
			}
		}
		i.Registry = unknownRegistry
		i.Name = linkWithoutLeadingSlash
		i.Tag = ""
		return
	}

	// Handle deep namespace paths with literal registry domains
	// Pattern: registry.domain.com/deep/namespace/path/$IMAGE:$TAG
	firstSlash := strings.Index(i.Link, "/")
	if firstSlash > 0 {
		potentialRegistry := i.Link[:firstSlash]
		// Only treat as literal registry if it contains . or : AND doesn't start with $
		if (strings.Contains(potentialRegistry, ".") || strings.Contains(potentialRegistry, ":")) && !strings.HasPrefix(potentialRegistry, "$") {
			// This looks like a registry domain
			remainingPath := i.Link[firstSlash+1:]

			// Extract tag if present
			tag := ""
			namespacePath := remainingPath
			if strings.Contains(remainingPath, ":") {
				lastColon := strings.LastIndex(remainingPath, ":")
				if lastColon > 0 && !strings.Contains(remainingPath[lastColon+1:], "/") {
					afterColon := remainingPath[lastColon+1:]
					// Check if tag is literal or single variable
					if !strings.Contains(afterColon, "$") || strings.Count(afterColon, "$") == 1 {
						tag = afterColon
						namespacePath = remainingPath[:lastColon]
					}
				}
			} else if strings.Contains(remainingPath, "@") {
				// Handle @digest pattern
				lastAt := strings.LastIndex(remainingPath, "@")
				if lastAt > 0 {
					afterAt := remainingPath[lastAt+1:]
					// Check if digest is literal or single variable
					if !strings.Contains(afterAt, "$") || strings.Count(afterAt, "$") == 1 {
						tag = afterAt
						namespacePath = remainingPath[:lastAt]
					}
				}
			}

			// For deep namespace paths, only extract the registry part before first slash
			i.Registry = potentialRegistry
			i.Name = namespacePath
			i.Tag = tag
			return
		}
	}

	// Get All Variables for complex patterns
	// Extract just variable names using sequential indices (0, 1, 2...)
	variables := make(map[int]string)
	varIndex := 0
	for idx := 0; idx < len(i.Link); idx++ {
		if i.Link[idx] == '$' {
			// Find the end of this variable (next non-alphanumeric/underscore char)
			varStart := idx
			varEnd := idx + 1
			for varEnd < len(i.Link) && (isAlphaNumericUnderscore(i.Link[varEnd])) {
				varEnd++
			}
			variables[varIndex] = i.Link[varStart:varEnd]
			varIndex++
			idx = varEnd - 1 // Skip ahead
		}
	}
	numberOfVariables := len(variables)

	// Handle single variable cases
	if numberOfVariables == 1 {
		variable := variables[0] // This is the actual variable like "$REGISTRY"

		// Find variable position in the original link
		varPos := strings.Index(i.Link, variable)

		// Only parse when variable is NOT at the start (i.e., there's a literal registry prefix)
		if varPos > 0 {
			beforeVar := i.Link[:varPos]
			afterVar := ""
			if varPos+len(variable) < len(i.Link) {
				afterVar = i.Link[varPos+len(variable):]
			}

			// Pattern: registry/image:$TAG or registry/image@$DIGEST
			if strings.HasSuffix(beforeVar, ":") || strings.HasSuffix(beforeVar, "@") {
				beforeSeparator := beforeVar[:len(beforeVar)-1]
				if strings.Contains(beforeSeparator, "/") {
					lastSlash := strings.LastIndex(beforeSeparator, "/")
					registryPart := beforeSeparator[:lastSlash]
					// Only parse if registry part looks like a domain (contains . or :)
					if strings.Contains(registryPart, ".") || strings.Contains(registryPart, ":") {
						i.Registry = registryPart
						i.Name = beforeSeparator[lastSlash+1:]
						i.Tag = variable + afterVar
						return
					}
				} else {
					// Pattern: image:$TAG (no registry)
					i.Registry = dockerHubDomain
					i.Name = beforeSeparator
					i.Tag = variable + afterVar
					return
				}
			}

			// Pattern: registry/$IMAGE:tag or registry/$IMAGE
			if strings.HasSuffix(beforeVar, "/") {
				registryPart := beforeVar[:len(beforeVar)-1]
				// Only parse if registry part looks like a domain (contains . or :)
				if strings.Contains(registryPart, ".") || strings.Contains(registryPart, ":") {
					if strings.HasPrefix(afterVar, ":") {
						tag := afterVar[1:]
						i.Registry = registryPart
						i.Name = variable
						i.Tag = tag
						return
					} else {
						i.Registry = registryPart
						i.Name = variable + afterVar
						i.Tag = ""
						return
					}
				}
			}
		}

		// Variable at start - check for tag extraction
		if varPos == 0 {
			// Check if it's just the variable alone
			if len(i.Link) == len(variable) {
				i.Registry = unknownRegistry
				i.Name = variable
				i.Tag = ""
				return
			}

			// Extract tag if pattern ends with :tag (literal tag, not variable)
			if strings.Contains(i.Link, ":") {
				lastColon := strings.LastIndex(i.Link, ":")
				if lastColon > 0 && !strings.Contains(i.Link[lastColon+1:], "/") && !strings.Contains(i.Link[lastColon+1:], "$") {
					// This is a literal tag
					i.Registry = unknownRegistry
					i.Name = i.Link[:lastColon]
					i.Tag = i.Link[lastColon+1:]
					return
				}
			}

			// Variable at start with other content - preserve full structure
			i.Registry = unknownRegistry
			i.Name = i.Link
			i.Tag = ""
			return
		}

		// Default: preserve full structure
		i.Registry = unknownRegistry
		i.Name = i.Link
		i.Tag = ""
		return
	}

	// Handle two variable cases
	if numberOfVariables == 2 {
		firstVariable := variables[0]
		secondVariable := variables[1]
		link := i.Link

		// Find where variables start
		firstVarStart := strings.Index(link, firstVariable)
		secondVarStart := strings.Index(link[firstVarStart+len(firstVariable):], secondVariable) + firstVarStart + len(firstVariable)

		// Extract parts
		beforeFirstVar := ""
		if firstVarStart > 0 {
			beforeFirstVar = link[:firstVarStart]
		}

		betweenVars := ""
		if secondVarStart > firstVarStart+len(firstVariable) {
			betweenVars = link[firstVarStart+len(firstVariable) : secondVarStart]
		}

		afterSecondVar := ""
		if secondVarStart+len(secondVariable) < len(link) {
			afterSecondVar = link[secondVarStart+len(secondVariable):]
		}

		// Only parse when there's a clear literal registry prefix
		if beforeFirstVar != "" && strings.HasSuffix(beforeFirstVar, "/") {
			registryPart := beforeFirstVar[:len(beforeFirstVar)-1]
			// Only parse if registry part looks like a domain (contains . or :)
			if strings.Contains(registryPart, ".") || strings.Contains(registryPart, ":") {
				if betweenVars == ":" && afterSecondVar == "" {
					// Pattern: registry.com/$IMAGE:$TAG
					i.Registry = registryPart
					i.Name = firstVariable
					i.Tag = secondVariable
					return
				} else if betweenVars == "/" && strings.HasPrefix(afterSecondVar, ":") {
					// Pattern: registry.com/$NAMESPACE/$IMAGE:tag
					i.Registry = registryPart
					i.Name = firstVariable + "/" + secondVariable
					i.Tag = strings.TrimPrefix(afterSecondVar, ":")
					return
				} else if betweenVars == "/" && afterSecondVar == "" {
					// Pattern: registry.com/$NAMESPACE/$IMAGE
					i.Registry = registryPart
					i.Name = firstVariable + "/" + secondVariable
					i.Tag = ""
					return
				} else if strings.HasSuffix(betweenVars, ":") && afterSecondVar == "" {
					// Pattern: registry.com/$IMAGE/name:$TAG
					imageWithPath := strings.TrimSuffix(betweenVars, ":")
					i.Registry = registryPart
					i.Name = firstVariable + imageWithPath
					i.Tag = secondVariable
					return
				}
			}
		}

		// Handle cases starting with variables - analyze separator patterns
		if beforeFirstVar == "" {
			if betweenVars == ":" {
				// $IMAGE:$TAG or $REGISTRY:$PORT
				if afterSecondVar == "" {
					// Simple $IMAGE:$TAG pattern (assume image:tag, not registry:port)
					i.Registry = unknownRegistry
					i.Name = firstVariable
					i.Tag = secondVariable
					return
				} else if strings.HasPrefix(afterSecondVar, "/") {
					// $REGISTRY:$PORT/... pattern
					i.Registry = firstVariable + ":" + secondVariable
					remaining := strings.TrimPrefix(afterSecondVar, "/")
					if strings.Contains(remaining, ":") {
						parts := strings.Split(remaining, ":")
						i.Name = parts[0]
						i.Tag = parts[1]
					} else {
						i.Name = remaining
						i.Tag = ""
					}
					return
				}
			} else if betweenVars == "@" {
				// $IMAGE@$DIGEST pattern
				i.Registry = unknownRegistry
				i.Name = firstVariable
				i.Tag = secondVariable
				return
			} else if betweenVars == "" {
				// Adjacent variables $VAR1$VAR2
				i.Registry = unknownRegistry
				i.Name = firstVariable + secondVariable
				i.Tag = ""
				return
			}
		}

		// Extract tag if there's a clear separator at the end
		if strings.Contains(i.Link, ":") {
			lastColon := strings.LastIndex(i.Link, ":")
			if lastColon > 0 && !strings.Contains(i.Link[lastColon+1:], "/") {
				// This might be a tag
				beforeTag := i.Link[:lastColon]
				tag := i.Link[lastColon+1:]
				// Check if the tag part contains only one variable
				if strings.Count(tag, "$") <= 1 {
					i.Registry = unknownRegistry
					i.Name = beforeTag
					i.Tag = tag
					return
				}
			}
		}

		// Default: preserve full structure
		i.Registry = unknownRegistry
		i.Name = i.Link
		i.Tag = ""
		return
	}

	// Handle three variable cases
	if numberOfVariables == 3 {
		// Handle special pattern $IMAGE:$TAG@$DIGEST
		if strings.Contains(i.Link, ":") && strings.Contains(i.Link, "@") {
			colonPos := strings.Index(i.Link, ":")
			atPos := strings.Index(i.Link, "@")
			if colonPos < atPos {
				// Check if pattern is $VAR1:$VAR2@$VAR3
				beforeColon := i.Link[:colonPos]
				betweenColonAt := i.Link[colonPos+1 : atPos]
				afterAt := i.Link[atPos+1:]

				if strings.Count(beforeColon, "$") == 1 && strings.Count(betweenColonAt, "$") == 1 && strings.Count(afterAt, "$") == 1 {
					i.Registry = unknownRegistry
					i.Name = beforeColon
					i.Tag = betweenColonAt + "@" + afterAt
					return
				}
			}
		}

		// Extract tag if pattern ends with :$TAG
		if strings.Contains(i.Link, ":") {
			lastColon := strings.LastIndex(i.Link, ":")
			if lastColon > 0 && !strings.Contains(i.Link[lastColon+1:], "/") {
				afterColon := i.Link[lastColon+1:]
				// Check if the part after colon is a single variable
				if strings.HasPrefix(afterColon, "$") && strings.Count(afterColon, "$") == 1 {
					i.Registry = unknownRegistry
					i.Name = i.Link[:lastColon]
					i.Tag = afterColon
					return
				}
			}
		}

		// Extract tag if pattern ends with @$DIGEST
		if strings.Contains(i.Link, "@") {
			lastAt := strings.LastIndex(i.Link, "@")
			if lastAt > 0 {
				afterAt := i.Link[lastAt+1:]
				// Check if the part after @ is a single variable
				if strings.HasPrefix(afterAt, "$") && strings.Count(afterAt, "$") == 1 {
					i.Registry = unknownRegistry
					i.Name = i.Link[:lastAt]
					i.Tag = afterAt
					return
				}
			}
		}

		// Special case for registry:port/image pattern
		if strings.Contains(i.Link, ":") && strings.Contains(i.Link, "/") {
			colonPos := strings.Index(i.Link, ":")
			slashPos := strings.Index(i.Link, "/")
			if colonPos < slashPos {
				// This might be $REGISTRY:$PORT/$IMAGE pattern
				registryPortPart := i.Link[:slashPos]
				imagePart := i.Link[slashPos+1:]
				if strings.Count(registryPortPart, "$") == 2 && strings.Count(imagePart, "$") == 1 {
					i.Registry = registryPortPart
					i.Name = imagePart
					i.Tag = ""
					return
				}
			}
		}

		// Default: preserve full structure (be conservative)
		i.Registry = unknownRegistry
		i.Name = i.Link
		i.Tag = ""
		return
	}

	// Handle four variable cases
	if numberOfVariables == 4 {
		// Special case for $REGISTRY:$PORT/$IMAGE:$TAG
		if strings.Contains(i.Link, ":") && strings.Contains(i.Link, "/") {
			colonPos := strings.Index(i.Link, ":")
			slashPos := strings.Index(i.Link, "/")
			if colonPos < slashPos {
				// This might be $REGISTRY:$PORT/$IMAGE:$TAG pattern
				registryPortPart := i.Link[:slashPos]
				remainingPart := i.Link[slashPos+1:]

				if strings.Count(registryPortPart, "$") == 2 {
					// Check if remaining part has image:tag pattern
					if strings.Contains(remainingPart, ":") {
						lastColon := strings.LastIndex(remainingPart, ":")
						if lastColon > 0 && !strings.Contains(remainingPart[lastColon+1:], "/") {
							imagePart := remainingPart[:lastColon]
							tagPart := remainingPart[lastColon+1:]
							if strings.Count(imagePart, "$") == 1 && strings.Count(tagPart, "$") == 1 {
								i.Registry = registryPortPart
								i.Name = imagePart
								i.Tag = tagPart
								return
							}
						}
					} else if strings.Count(remainingPart, "$") == 2 {
						// $REGISTRY:$PORT/$USER/$IMAGE pattern
						i.Registry = registryPortPart
						i.Name = remainingPart
						i.Tag = ""
						return
					}
				}
			}
		}

		// Extract tag if pattern ends with :$TAG
		if strings.Contains(i.Link, ":") {
			lastColon := strings.LastIndex(i.Link, ":")
			if lastColon > 0 && !strings.Contains(i.Link[lastColon+1:], "/") {
				afterColon := i.Link[lastColon+1:]
				// Check if the part after colon is a single variable
				if strings.HasPrefix(afterColon, "$") && strings.Count(afterColon, "$") == 1 {
					i.Registry = unknownRegistry
					i.Name = i.Link[:lastColon]
					i.Tag = afterColon
					return
				}
			}
		}

		// Default: preserve full structure
		i.Registry = unknownRegistry
		i.Name = i.Link
		i.Tag = ""
		return
	}

	// Handle five or more variable cases - preserve full structure (too complex to parse reliably)
	if numberOfVariables >= 5 {
		i.Registry = unknownRegistry
		i.Name = i.Link
		i.Tag = ""
		return
	}

	// Final fallback: preserve full structure
	i.Registry = unknownRegistry
	i.Name = i.Link
	i.Tag = ""
}

func (i *GitlabPipelineImageInfo) parseImageLink(l *logrus.Entry) {
	originalLink := i.Link

	// Check if it contains any unresolved variables
	if strings.Contains(i.Link, "$") {
		l.WithField("image", i).Debug("Image link contains variables")
		i.handlePresenceOfVariables()
		l.WithField("image registry", i.Registry).WithField("image name", i.Name).WithField("image tag", i.Tag).Debug("Image link contains variables")
		return
	}

	// First, try to find if there's a registry domain
	// A registry domain should contain a dot (e.g., registry.example.com)
	// or might have a port (containing a colon)
	firstSlash := strings.Index(i.Link, "/")
	if firstSlash == -1 {
		// No slash found, this is a simple image name
		parts := strings.Split(i.Link, ":")
		i.Registry = dockerHubDomain
		i.Name = parts[0]
		if len(parts) > 1 {
			i.Tag = parts[1]
		}
		i.Link = dockerHubDomain + "/" + originalLink
		return
	}

	// Check if the part before the first slash is a registry
	registryPart := i.Link[:firstSlash]
	if strings.Contains(registryPart, ".") || strings.Contains(registryPart, ":") {
		// This is a custom registry
		i.Registry = registryPart
		remainingPart := i.Link[firstSlash+1:]

		// Split remaining part by colon to separate tag
		parts := strings.Split(remainingPart, ":")
		i.Name = parts[0]
		if len(parts) > 1 {
			i.Tag = parts[1]
		}
	} else {
		// No registry domain found, use Docker Hub
		i.Registry = dockerHubDomain
		parts := strings.Split(i.Link, ":")
		i.Name = parts[0]
		if len(parts) > 1 {
			i.Tag = parts[1]
		}
		i.Link = dockerHubDomain + "/" + originalLink
	}
	// Safety check: if name ended up empty but we have a link, preserve the original
	if strings.TrimSpace(i.Name) == "" && strings.TrimSpace(originalLink) != "" {
		l.WithField("originalLink", originalLink).Warning("Image name is empty")
		i.Name = originalLink
		i.Registry = unknownRegistry
		i.Tag = ""
	}
}

////////////////////////
// DataCollection run //
////////////////////////

func (dc *GitlabPipelineImageDataCollection) Run(project *gitlab.ProjectInfo, token string, conf *configuration.Configuration, pipelineOriginData *GitlabPipelineOriginData) (*GitlabPipelineImageData, *GitlabPipelineImageMetrics, error) {

	// Check if project is nil first
	if project == nil {
		return nil, nil, fmt.Errorf("project cannot be nil")
	}

	l := l.WithFields(logrus.Fields{
		"dataCollection":        "GitlabPipelineImage",
		"dataCollectionVersion": DataCollectionTypeGitlabPipelineImageVersion,
		"project":               project.Path,
	})
	l.Info("Start data collection")

	// Check if pipelineOriginData is nil
	if pipelineOriginData == nil {
		l.Error("pipelineOriginData cannot be nil")
		return nil, nil, fmt.Errorf("pipelineOriginData cannot be nil")
	}

	////////////////////////
	// Initialize results //
	////////////////////////

	data := &GitlabPipelineImageData{}
	data.CiValid = true
	data.CiMissing = false
	data.InstanceVars = make(map[string]string)
	data.GroupVars = make(map[string]string)
	data.ProjectVars = make(map[string]string)
	data.GlobalVars = make(map[string]string)
	data.Images = []GitlabPipelineImageInfo{}
	data.MergedConf = nil

	metrics := &GitlabPipelineImageMetrics{}

	var err error

	///////////////////////////////////////////
	// Get CI configuration from origin data //
	///////////////////////////////////////////

	// Get all CI configuration fields from the GitLab Pipeline Origin data collection
	data.MergedConf = pipelineOriginData.MergedConf
	data.CiValid = pipelineOriginData.CiValid
	data.CiMissing = pipelineOriginData.CiMissing

	// If we weren't able to retrieve the pipelines (invalid configuration, archived project, unauthorized, ...), we stop here
	if !data.CiValid || data.CiMissing {
		// Return empty result for limited analysis
		return data, metrics, nil
	}

	//////////////////
	// Extract data //
	//////////////////

	// Get the default or global image of the configuration
	data.DefaultImage, err = gitlab.ParseDefaultImage(data.MergedConf)
	if err != nil {
		l.WithError(err).Error("Unable to retrieve default image from the project's CI conf")
		return data, metrics, err
	}

	// Get all global variables in the conf
	data.GlobalVars, err = gitlab.ParseGlobalVariables(data.MergedConf)
	if err != nil {
		l.WithError(err).Error("Unable to retrieve global variables from the project's CI conf")
		return data, metrics, err
	}

	// Get instance variables only if it's an instance wide organization (not a group)
	if !project.IsGroup {
		instanceVarsResult, err := gitlab.GetGitlabInstanceVariables(token, conf.GitlabURL, conf)
		if err != nil {
			l.WithError(err).Error("Unable to retrieve instance variables")
			return data, metrics, err
		}
		data.InstanceVars = gitlab.ConvertCICDVariableToMap(instanceVarsResult)
		l.WithField("instanceVars", data.InstanceVars).Debug("Instance vars found")
	}

	// Get value of variables inherited from group(s)
	groupVarsResult, err := gitlab.GetGitlabProjectInheritedVariables(project.Path, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to retrieve project inherited variables")
		return data, metrics, err
	}
	data.GroupVars = gitlab.ConvertCICDVariableToMap(groupVarsResult)
	l.WithField("groupVars", data.GroupVars).Debug("Group vars found")

	// Get project variables
	projectVarsResult, err := gitlab.GetGitlabProjectVariables(project.Path, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to retrieve project variables")
		return data, metrics, err
	}
	data.ProjectVars = gitlab.ConvertCICDVariableToMap(projectVarsResult)
	l.WithField("projectVars", data.ProjectVars).Debug("Project vars found")

	// Set predefined variables
	predefinedVars := map[string]string{
		"CI_TEMPLATE_REGISTRY_HOST": "registry.gitlab.com",
		"SECURE_ANALYZERS_PREFIX":   "",
	}

	// Loop over all jobs to analyze image and get its status
	for name, content := range data.MergedConf.GitlabJobs {

		// Add logging
		jobLogger := l.WithField("jobName", name)

		// Parse the job
		job, err := gitlab.ParseGitlabCIJob(content)
		if err != nil {
			jobLogger.WithError(err).Error("Unable to parse Gitlab CI job")
			return data, metrics, err
		}

		//  Get job variables
		jobVars, err := gitlab.ParseJobVariables(job)
		if err != nil {
			jobLogger.WithError(err).Error("Unable to parse Gitlab CI job's variables")
			return data, metrics, err
		}

		// Retrieve job image
		imageUnresolved, err := gitlab.GetImageName(job.Image)
		if err != nil {
			jobLogger.WithError(err).Error("Unable to parse the image name from job")
		}
		l.WithField("image", imageUnresolved).Debug("Job image found")

		// If job image is empty, use the default or global job image
		if imageUnresolved == "" {
			imageUnresolved = data.DefaultImage
		}

		// Resolve variables in image
		imageLink := gitlab.ReplaceVariable(imageUnresolved, data.ProjectVars, data.GroupVars, data.InstanceVars, jobVars, data.GlobalVars, predefinedVars)

		// Add logging
		jobLogger = jobLogger.WithField("imageLink", imageLink)

		//  If no image: next
		if imageLink == "" {
			jobLogger.Warning("Job with empty image found")
			continue
		}

		// Init image data
		image := GitlabPipelineImageInfo{
			Link:     imageLink,
			Name:     "",
			Tag:      defaultTag,
			Registry: "",
			Job:      name,
		}

		// Parse image link
		image.parseImageLink(jobLogger)

		data.Images = append(data.Images, image)
	}

	// Compute metrics
	metrics.Total = uint(len(data.Images))

	// Return the populated analysis data
	return data, metrics, nil
}
