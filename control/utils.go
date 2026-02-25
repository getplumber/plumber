package control

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/utils"
)

// overridesRegex matches forbidden override keywords in a job's JSON representation.
// These are CI/CD keywords that, when present in the hardcoded (overridden) content,
// indicate the user has meaningfully overridden a component/template's behavior.
const overridesRegex = `(?i)"(after_script|allow_failure|artifacts|before_script|cache|coverage|dast_configuration|dependencies|environment|identity|image|inherit|interruptible|manual_confirmation|needs|pages|parallel|release|resource_group|retry|rules|script|secrets|services|stage|tags|timeout|trigger|when)":`

var compiledOverridesRegex = regexp.MustCompile(overridesRegex)


// getOriginOverriddenJobs returns per-job override details for an origin.
// Jobs are deduplicated by name (the same job can appear multiple times
// in an origin's Jobs slice from both direct and extends-based matching).
// Returns nil if no jobs have forbidden overrides.
func getOriginOverriddenJobs(origin *collector.GitlabPipelineOriginDataFull, data *collector.GitlabPipelineOriginData) []utils.OverriddenJobDetail {
	seen := make(map[string]bool)
	var details []utils.OverriddenJobDetail
	for _, job := range origin.Jobs {
		if job.IsOverridden && !seen[job.Name] {
			seen[job.Name] = true
			keys := getForbiddenOverrideKeys(data.JobHardcodedContent[job.Name])
			if len(keys) > 0 {
				details = append(details, utils.OverriddenJobDetail{
					JobName:        job.Name,
					OverriddenKeys: keys,
				})
			}
		}
	}
	return details
}

// getForbiddenOverrideKeys returns the list of forbidden CI/CD keywords found
// in a job's hardcoded (overridden) content. Returns nil if none are found.
func getForbiddenOverrideKeys(job interface{}) []string {
	if job == nil {
		return nil
	}

	serializable := convertToSerializable(job)

	jobJSON, err := json.Marshal(serializable)
	if err != nil {
		l.WithError(err).WithField("job", job).Error("Unable to marshal job content to JSON for override check")
		return nil
	}

	matches := compiledOverridesRegex.FindAllSubmatch(jobJSON, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var keys []string
	for _, m := range matches {
		key := string(m[1])
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	return keys
}

// convertToSerializable converts a map[interface{}]interface{} to map[string]interface{}
// recursively to make it JSON serializable (YAML unmarshalling produces the former).
func convertToSerializable(input interface{}) interface{} {
	switch v := input.(type) {
	case map[interface{}]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			keyStr, ok := key.(string)
			if !ok {
				keyStr = fmt.Sprintf("%v", key)
			}
			result[keyStr] = convertToSerializable(value)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			result[key] = convertToSerializable(value)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = convertToSerializable(item)
		}
		return result
	default:
		return v
	}
}
