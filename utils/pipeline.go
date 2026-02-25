package utils

import "strings"

// OverriddenJobDetail captures which job was overridden and with which forbidden CI/CD keywords.
// Shared across control (detection) and pbom (reporting) packages.
type OverriddenJobDetail struct {
	JobName        string   `json:"jobName"`
	OverriddenKeys []string `json:"overriddenKeys"`
}

// CleanOriginPath normalizes a GitLab include/component path by stripping
// the version suffix and instance URL prefix, producing a bare path suitable
// for comparison (e.g. "components/sast/sast").
func CleanOriginPath(location string) string {
	if idx := strings.LastIndex(location, "@"); idx != -1 {
		location = location[:idx]
	}
	location = strings.TrimPrefix(location, "$CI_SERVER_FQDN/")
	location = strings.TrimPrefix(location, "$CI_SERVER_HOST/")
	if idx := strings.Index(location, "/"); idx != -1 {
		parts := strings.SplitN(location, "/", 2)
		if len(parts) == 2 && strings.Contains(parts[0], ".") {
			location = parts[1]
		}
	}
	return location
}
