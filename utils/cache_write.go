package utils

import (
	"path"
	"path/filepath"
	"slices"
	"sort"
)

// CacheWriteSafeTriggers are the events allowed to write the cache: the
// triggers GitHub lets create or overwrite caches in the default branch's
// scope, plus pull_request and its review events, release and merge_group, which write only
// their own ref's scope. Mirrors cache_write_safe_triggers in
// policies/cache_poisoning.rego (ISSUE-705).
var CacheWriteSafeTriggers = map[string]bool{
	"push": true, "workflow_dispatch": true, "repository_dispatch": true, "delete": true,
	"registry_package": true, "page_build": true, "schedule": true,
	"pull_request": true, "pull_request_review": true, "pull_request_review_comment": true,
	"release": true, "merge_group": true,
}

// CacheWriteRiskyTriggers returns, sorted, the triggers a job granted the
// effective cache-mode runs on that GitHub restricts to read-only cache
// access; nil when the mode grants no write (read, none, or unresolved)
// or every trigger is safe. A job it returns triggers for is the shape
// ISSUE-705 flags.
func CacheWriteRiskyTriggers(effectiveMode string, triggers []string) []string {
	if effectiveMode != "write" && effectiveMode != "write-only" {
		return nil
	}
	var out []string
	for _, t := range triggers {
		if !CacheWriteSafeTriggers[t] && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// CacheWriteExempt reports whether a job is exempted from ISSUE-705 by an
// exemptWorkflows pattern on its workflow file name or an exemptJobs
// pattern on its name (`<workflow>/<job>`), with the rule's glob matching.
func CacheWriteExempt(workflows, jobs []string, jobName, originFile string) bool {
	if originFile != "" {
		base := path.Base(filepath.ToSlash(originFile))
		for _, p := range workflows {
			if globMatch(p, base) {
				return true
			}
		}
	}
	for _, p := range jobs {
		if globMatch(p, jobName) {
			return true
		}
	}
	return false
}
