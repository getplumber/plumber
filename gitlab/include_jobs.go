package gitlab

import (
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

	for i, inc := range req.Includes {
		lInclude := l.WithField("location", inc.Location)

		// An include pulled in by another include is attributed to its
		// parent, not to this project.
		if inc.ContextProject != req.ProjectPath {
			out[i] = IncludeJobs{Jobs: []string{}, Known: true, Nested: true}
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
