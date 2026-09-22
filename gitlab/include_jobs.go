package gitlab

import (
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
)

// This file exports job ATTRIBUTION: which jobs each include contributed.
//
// FetchGitlabInclude has always been exported, but it cannot be called
// correctly on its own. It takes an `inputs` map, and building that map means
// reproducing how an include is identified: the origin record, the FNV hash
// over it, the predefined-variable substitution in a component path, and the
// rule that a nested include contributes nothing at this level. All of that
// was unexported, so an embedding host either called FetchGitlabInclude with
// the wrong inputs or wrote its own copy of the identification.
//
// Both are worse than they look. Inputs that miss produce an include whose
// jobs come back unparameterised, and an overridden component job is then
// misreported as project-authored (ISSUE-401). That is exactly the shape of
// #286, where a single unresolved $CI_PROJECT_NAMESPACE broke the hash and
// dropped the inputs.
//
// So the whole sequence is exported as one call instead of its pieces.

// IncludeJobsRequest carries what job attribution needs. Every field comes
// from a collection the caller has already made; nothing here re-fetches the
// pipeline.
type IncludeJobsRequest struct {
	// RawConfig is the project's OWN unmerged CI configuration - the file as
	// written, not the merged document. The inputs an include is called with
	// only exist there: the merged result has them already applied.
	RawConfig *GitlabCIConf

	// Includes is the merged response's include list. The result is returned
	// in THIS order and the index is the join key.
	Includes []MergedCIConfResponseInclude

	// Stages from the MERGED configuration. A component may reference a stage
	// defined at the root, and an include re-merged without them fails to
	// resolve.
	Stages []string

	// ProjectPath is the project being analysed, and is what decides whether
	// an include is nested: an include whose ContextProject differs was
	// pulled in by another include, not by this project.
	ProjectPath string

	Token  string
	APIURL string

	// SHA the includes are resolved at.
	SHA string

	Conf *configuration.Configuration
}

// IncludeJobs is one include's attribution. Returned one per request include,
// in the same order.
type IncludeJobs struct {
	// Jobs the include contributed, by name.
	Jobs []string

	// Known reports whether the attribution was established. False means the
	// include could not be resolved, and the caller must NOT read the empty
	// Jobs as "this include contributed nothing": the jobs it did contribute
	// are still in the merged pipeline with nothing attributing them
	// upstream, so rules keyed on that distinction fire on them as though the
	// project had written them.
	Known bool

	// Nested marks an include pulled in by another include rather than by
	// this project. Its jobs are attributed to the include that pulled it in,
	// so it contributes none at this level: an empty Jobs with Known true.
	Nested bool

	// ObservationMissing marks an include a host served WITHOUT the
	// attribution that goes with it, on a run where that attribution is the
	// host's to supply. It is a Known false with a cause: the question was
	// never asked rather than asked and refused.
	//
	// The caller needs the two apart to say anything useful about it. An
	// unresolved include points at this run's own credentials; an
	// unobserved one points at what the host has collected so far, and no
	// change to the runner's token would alter it.
	ObservationMissing bool
}

// DeriveIncludeJobs answers "which jobs did each include contribute" for every
// include in the request, in order.
//
// This is the CLI's own attribution, exported whole so an embedding host does
// not reimplement the identification around it. It makes one config-merge
// request per non-nested include, against the ANALYSED project rather than the
// include's source, and reads the job names out of the result.
//
// An include that cannot be resolved yields Known false rather than an error:
// one unreachable include must not cost the caller the attribution of every
// other one. The returned error is reserved for a request that could not be
// started at all.
func DeriveIncludeJobs(req IncludeJobsRequest) ([]IncludeJobs, error) {
	l := logger.WithFields(logrus.Fields{
		"action":      "DeriveIncludeJobs",
		"projectPath": req.ProjectPath,
		"includes":    len(req.Includes),
	})

	out := make([]IncludeJobs, len(req.Includes))
	if len(req.Includes) == 0 {
		return out, nil
	}

	// Built once from the raw configuration, keyed by the same hash the
	// origin loop uses. A nil RawConfig yields an empty map rather than an
	// error: every include is then fetched without inputs, which is the
	// correct answer for a project whose includes declare none and a
	// degraded one for a project whose includes do.
	inputsByHash := buildIncludeInputsMap(req.RawConfig, req.Conf.GitlabURL, req.ProjectPath)
	specInputFiles := specIncludeLocalPaths(req.RawConfig)

	for i, inc := range req.Includes {
		lInclude := l.WithField("location", inc.Location)

		// An include pulled in by another include is attributed to its
		// parent, not to this project.
		//
		// Compared case-insensitively because this is a PUBLIC entry point:
		// ProjectPath comes from the caller, while ContextProject comes from
		// GitLab, and GitLab matches project paths without regard to case. A
		// caller whose stored path differs only in case from GitLab's would
		// classify EVERY include as nested - every one reporting zero jobs,
		// Known true. That is not a silent pass but a fabricating one: the
		// jobs those includes really contributed stay in the merged pipeline
		// with nothing attributing them upstream, so they read as
		// project-authored and the rules keyed on that distinction fire on
		// them.
		//
		// The origin loop compares exactly and is safe doing so: both of its
		// sides come from GitLab (PathWithNamespace or $CI_PROJECT_PATH, and
		// the ciConfig response), so they always agree on form. Only an
		// exported entry point can be handed a path from somewhere else.
		if !strings.EqualFold(inc.ContextProject, req.ProjectPath) {
			out[i] = IncludeJobs{Jobs: []string{}, Known: true, Nested: true}
			continue
		}

		// A file the project loads through `spec:include` holds input
		// definitions, not jobs. GitLab still lists it in the merged
		// response's include list as a plain local include, and re-merging
		// it on its own reads its top-level `inputs:` key as a job named
		// "inputs" that the merged pipeline does not have (#471): one
		// config-merge call nobody needed, then an error log per file for
		// a phantom job. It is a KNOWN empty contribution, decided here
		// before any host-served or fetched attribution, so every mode
		// agrees on it.
		if inc.Type == glOriginLocal && specInputFiles[normalizeLocalIncludePath(inc.Location)] {
			lInclude.Debug("spec:include input file; it contributes no jobs")
			out[i] = IncludeJobs{Jobs: []string{}, Known: true}
			continue
		}

		// Already resolved by a host that served the attribution. JobsKnown
		// is what permits skipping the request, not a non-empty Jobs: an
		// include contributing only variables legitimately has none.
		if inc.JobsKnown {
			jobs := inc.Jobs
			if jobs == nil {
				jobs = []string{}
			}
			out[i] = IncludeJobs{Jobs: jobs, Known: true}
			continue
		}

		// The host that served this configuration owns the attribution that
		// belongs to it, and served this include without it. Resolving the
		// include here is not a second chance at the same answer: the run
		// this path exists for is a pipeline job whose token reaches its own
		// project and nothing else, so the config-merge request answers 401
		// and the attribution ends exactly as unknown as it started - after
		// a call nobody asked for and an error nobody can act on. Record the
		// gap instead, and let the controls that need it abstain.
		//
		// A standalone run keeps the fallback in full: there the CLI is the
		// only one who could have asked.
		if req.Conf != nil && req.Conf.PlatformRun.Engaged() {
			lInclude.Debug("Include served without its job attribution; the controls that need it are not evaluable")
			out[i] = IncludeJobs{Known: false, ObservationMissing: true}
			continue
		}

		inputs := inputsByHash[includeOriginHash(inc, req.Conf.GitlabURL)]

		jobs, err := FetchGitlabInclude(
			inc, req.ProjectPath, req.Token, req.APIURL, req.SHA,
			req.Conf, inputs, req.Stages,
		)
		if err != nil {
			lInclude.WithError(err).Debug("Could not resolve include; its attribution is unknown, not empty")
			out[i] = IncludeJobs{Known: false}
			continue
		}
		if jobs == nil {
			jobs = []string{}
		}
		out[i] = IncludeJobs{Jobs: jobs, Known: true}
	}
	return out, nil
}

// specIncludeLocalPaths returns the local file paths a raw configuration
// loads through `spec:include` (#471), normalized with
// normalizeLocalIncludePath so they compare equal to the merged response's
// include locations. The raw `spec` is kept as a generic yaml value
// (GitlabCIConf.Spec, first document wins in a multi-document file), so
// this walks it defensively: a missing or oddly shaped spec yields an
// empty set, and every include is then handled exactly as before.
//
// Only `local:` entries (and bare string entries, which GitLab reads as
// local paths) are recognized. A spec:include of another type is left to
// the ordinary path: it is not the reported shape, and guessing at how
// GitLab would list it in the merged response is worse than one spurious
// merge call.
func specIncludeLocalPaths(raw *GitlabCIConf) map[string]bool {
	out := map[string]bool{}
	if raw == nil || raw.Spec == nil {
		return out
	}
	spec := asStringKeyedMap(raw.Spec)
	entries, ok := spec["include"].([]interface{})
	if !ok {
		return out
	}
	for _, entry := range entries {
		switch e := entry.(type) {
		case string:
			out[normalizeLocalIncludePath(e)] = true
		default:
			if local, ok := asStringKeyedMap(e)["local"].(string); ok {
				out[normalizeLocalIncludePath(local)] = true
			}
		}
	}
	return out
}

// normalizeLocalIncludePath makes a `local:` include path comparable across
// the two places it appears: the raw file, where GitLab accepts an optional
// leading "/", and the merged response, where the location is served
// without it.
func normalizeLocalIncludePath(p string) string {
	return strings.TrimPrefix(strings.TrimSpace(p), "/")
}

// asStringKeyedMap reads a generic yaml mapping whichever map type the
// decoder produced (yaml.v2 yields map[interface{}]interface{}; a JSON or
// yaml.v3 round-trip yields map[string]interface{}). Anything else reads
// as an empty map.
func asStringKeyedMap(v interface{}) map[string]interface{} {
	switch m := v.(type) {
	case map[string]interface{}:
		return m
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			if ks, ok := k.(string); ok {
				out[ks] = val
			}
		}
		return out
	default:
		return map[string]interface{}{}
	}
}

// includeOriginHash is the key an include's inputs are stored under.
//
// It mirrors the origin loop's own computation exactly, including the second
// pass components get: the version is stripped from the location and the hash
// recomputed, so two includes of the same component at different versions
// share one key.
//
// Note what is deliberately NOT here: predefined project variables are not
// substituted. These locations come from the MERGED response, which GitLab
// already resolved. The raw-config side (extractInputsFromInclude) does
// substitute, because the file as written still says
// $CI_PROJECT_NAMESPACE - and the two meeting in the middle is what #286
// fixed. Adding substitution here would break the hash from the other
// direction.
//
// TestIncludeOriginHashMatchesTheOriginLoop pins this against the loop.
func includeOriginHash(inc MergedCIConfResponseInclude, instanceURL string) uint64 {
	origin := IncludeOriginWithoutRef{
		Location: inc.Location,
		Type:     inc.Type,
		Project:  inc.Extra.Project,
	}
	if inc.Type == glOriginComponent {
		instance, cleanPath, _ := ParseGitlabComponentPath(origin.Location, instanceURL)
		origin.Location = instance + "/" + cleanPath
	}
	hash, err := generateIncludeHash(origin)
	if err != nil {
		return 0
	}
	return hash
}
