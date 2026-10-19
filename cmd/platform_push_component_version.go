package cmd

import (
	"os"
	"regexp"
	"strings"

	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
	providerPkg "github.com/getplumber/plumber/provider"
)

// pushComponentInclude is the slice of one include the component version
// selection reads (issue #562, both providers: review of PR 563 added the
// GitHub half): its type, its location, the version it pins and the names
// of the jobs it defines. The bill's platformBOMInclude carries no job
// list, so the selection reads the same origin data the bill is built from
// instead: pushComponentIncludesOf on GitLab, pushComponentIncludesOfGitHub
// on GitHub.
type pushComponentInclude struct {
	Type     string
	Location string
	Version  string
	Jobs     []string
}

// plumberComponentJob is the job name the product's own component defines.
const plumberComponentJob = "plumber"

// plumberComponentPathSuffix is the product's own component path, matched as
// a suffix so any instance prefix (gitlab.com, a self-hosted mirror or
// $CI_SERVER_FQDN) is accepted.
const plumberComponentPathSuffix = "getplumber/plumber/plumber"

// plumberActionPath is the product's own GitHub Action, the `uses:` path a
// workflow pins to run the CLI: the action lives at the root of this
// repository (action.yml, docs/*.md), so its canonical path is exactly
// getplumber/plumber, with no further subpath. Review of PR 563, the
// GitHub half of issue #562.
const plumberActionPath = "getplumber/plumber"

// componentVersionLike is the platform's componentRefLikePattern
// (platform/backend/storage/store.go): an optional leading v, three numeric
// groups, an optional semver pre-release or build suffix. A ~latest, a
// branch or a commit sha never matches.
var componentVersionLike = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)

// componentVersionForPush returns the value of the push's
// cli.component_version (issue #562) on the GitLab side. The platform
// contract (docs/contracts/openapi.yaml of the platform) describes that
// field as the pinned CI component's own version, read FIRST for the
// component_ref refresh, so a project that bumps its component pin sees the
// new pin on the same push instead of after the nightly sync. The GitHub
// side has no component include at all, so it is covered separately by
// componentVersionForGitHubPush (review of PR 563), over the run's `uses:`
// action references instead.
//
// The include is chosen among the component includes, in order:
//  1. the one that declares jobName, the CI job the CLI is running in, when
//     exactly one does
//  2. else the one that lists the plumber job, when exactly one does
//  3. else the one whose location ends with getplumber/plumber/plumber, the
//     product's own component, when exactly one does
//
// The chosen include's version is returned as the bill writes it (a leading
// v is kept, the platform normalizes) only when it is version-like. Any other
// outcome returns "", which omits the key.
//
// A pure function of its arguments.
func componentVersionForPush(includes []pushComponentInclude, jobName string) string {
	var components []pushComponentInclude
	for _, inc := range includes {
		if inc.Type == "component" {
			components = append(components, inc)
		}
	}
	declares := func(name string) func(pushComponentInclude) bool {
		return func(inc pushComponentInclude) bool {
			for _, job := range inc.Jobs {
				if job == name {
					return true
				}
			}
			return false
		}
	}
	isProduct := func(inc pushComponentInclude) bool {
		loc := strings.TrimSpace(inc.Location)
		return loc == plumberComponentPathSuffix || strings.HasSuffix(loc, "/"+plumberComponentPathSuffix)
	}

	var rules []func(pushComponentInclude) bool
	if jobName != "" {
		rules = append(rules, declares(jobName))
	}
	rules = append(rules, declares(plumberComponentJob), isProduct)

	for _, rule := range rules {
		var match []pushComponentInclude
		for _, inc := range components {
			if rule(inc) {
				match = append(match, inc)
			}
		}
		if len(match) != 1 {
			continue
		}
		version := strings.TrimSpace(match[0].Version)
		if componentVersionLike.MatchString(version) {
			return version
		}
		return ""
	}
	return ""
}

// pushComponentIncludesOf lists the run's DIRECT includes from the GitLab
// origin data the bill of materials is built from (processIncludes in
// package pbom reads the same fields), with each include's job names. An
// origin pulled in transitively (Nested true, set by
// collect_pipeline_origin.go for an include whose context project differs
// from the current project) is never a candidate: the project's own pin is
// the include its own CI file names, which is what the platform's
// component detection reads, so a nested product component (included by a
// wrapper component) is skipped the same way the GitHub side already skips
// a nested action reference (pushComponentIncludesOfGitHub, review of PR
// 563). Nil on any provider other than GitLab, and when no origin data was
// collected.
func pushComponentIncludesOf(p providerPkg.Provider, origin *gitlab.GitlabPipelineOriginData) []pushComponentInclude {
	if p == nil || p.Name() != "gitlab" || origin == nil {
		return nil
	}
	out := make([]pushComponentInclude, 0, len(origin.Origins))
	for _, o := range origin.Origins {
		if o.OriginType == "hardcoded" || o.Nested {
			continue
		}
		inc := pushComponentInclude{
			Type:     o.OriginType,
			Location: o.GitlabIncludeOrigin.Location,
			Version:  o.Version,
		}
		for _, job := range o.Jobs {
			inc.Jobs = append(inc.Jobs, job.Name)
		}
		out = append(out, inc)
	}
	return out
}

// pushComponentVersion is the cli.component_version of this run's push
// (issue #562), read from the run's origin data and CI_JOB_NAME. Empty
// outside a GitLab run with origin data.
func pushComponentVersion(p providerPkg.Provider, origin *gitlab.GitlabPipelineOriginData) string {
	return componentVersionForPush(pushComponentIncludesOf(p, origin), strings.TrimSpace(os.Getenv("CI_JOB_NAME")))
}

// componentVersionForGitHubPush returns the value of the push's
// cli.component_version on the GitHub side (issue #562, review of PR 563).
// GitHub has no component include; the CLI's own pin there is the `uses:`
// reference of the product action, getplumber/plumber@<ref>, read off the
// run's direct action references (Nested false: a reference pulled in by a
// composite action is never the project's own pin).
//
// Among the product action's references, the one is chosen, in order:
//  1. the one whose job declares jobName, the running job (GITHUB_JOB),
//     when exactly one does
//  2. else the one of the run's jobs that references the product action,
//     when exactly one does
//
// The chosen reference's ref is returned only when it is version-like
// (componentVersionLike, the same pattern the GitLab side uses): a branch
// such as main or a commit sha is never sent. Any other outcome returns "".
//
// A pure function of its arguments.
func componentVersionForGitHubPush(includes []pushComponentInclude, jobName string) string {
	var products []pushComponentInclude
	for _, inc := range includes {
		if inc.Type == "action" && strings.TrimSpace(inc.Location) == plumberActionPath {
			products = append(products, inc)
		}
	}
	declares := func(name string) func(pushComponentInclude) bool {
		return func(inc pushComponentInclude) bool {
			for _, job := range inc.Jobs {
				if job == name {
					return true
				}
			}
			return false
		}
	}
	always := func(pushComponentInclude) bool { return true }

	var rules []func(pushComponentInclude) bool
	if jobName != "" {
		rules = append(rules, declares(jobName))
	}
	rules = append(rules, always)

	for _, rule := range rules {
		var match []pushComponentInclude
		for _, inc := range products {
			if rule(inc) {
				match = append(match, inc)
			}
		}
		if len(match) != 1 {
			continue
		}
		version := strings.TrimSpace(match[0].Version)
		if componentVersionLike.MatchString(version) {
			return version
		}
		return ""
	}
	return ""
}

// pushComponentIncludesOfGitHub lists the run's DIRECT product-action `uses:`
// references, one entry per job that carries one, from the same IR the bill
// of materials reads on GitHub (processGitHubIncludes in package pbom reads
// the same job/step fields). A step pulled in by a composite action (Nested
// true) is never a candidate: it is not the project's own pin. Nil on a nil
// pipeline.
//
// The job id an entry's Jobs names is the plain GITHUB_JOB value: the part
// of the job's namespaced Name (workflowBase/jobID, github/github_workflows.go)
// after the first slash, which is how a job is identified in the IR at this
// call site.
func pushComponentIncludesOfGitHub(pipeline *ir.NormalizedPipeline) []pushComponentInclude {
	if pipeline == nil {
		return nil
	}
	var out []pushComponentInclude
	for i := range pipeline.Jobs {
		job := &pipeline.Jobs[i]
		jobID := job.Name
		if idx := strings.Index(jobID, "/"); idx >= 0 {
			jobID = jobID[idx+1:]
		}
		for _, u := range job.Uses {
			if u.Nested || strings.TrimSpace(u.Uses) == "" {
				continue
			}
			base, ref := u.Uses, ""
			if at := strings.LastIndex(base, "@"); at > 0 {
				ref = base[at+1:]
				base = base[:at]
			}
			if base != plumberActionPath {
				continue
			}
			out = append(out, pushComponentInclude{
				Type:     "action",
				Location: plumberActionPath,
				Version:  ref,
				Jobs:     []string{jobID},
			})
		}
	}
	return out
}

// pushComponentVersionForGitHub is the cli.component_version of this run's
// push on the GitHub provider (issue #562, review of PR 563: the GitHub
// half). Empty outside a GitHub run with a collected pipeline.
func pushComponentVersionForGitHub(p providerPkg.Provider, pipeline *ir.NormalizedPipeline) string {
	if p == nil || p.Name() != "github" {
		return ""
	}
	return componentVersionForGitHubPush(pushComponentIncludesOfGitHub(pipeline), strings.TrimSpace(os.Getenv("GITHUB_JOB")))
}
