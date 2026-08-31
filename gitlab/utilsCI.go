package gitlab

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// platformMergedConfig returns the merged CI configuration platform mode
// supplies for this run, and whether platform mode is the source at all.
//
// A false second return means STANDALONE mode: the caller resolves the
// merge through the GitLab API exactly as it always has, so no existing run
// changes behaviour.
//
// A true second return with an EMPTY MergedYaml is the honest
// "platform mode, nothing resolved" state, not an error: the run continues
// so that collections on other lanes (branch protection, settings) still
// produce verdicts, and the controls that read the pipeline are marked
// not_evaluable by the caller rather than silently passing over an empty
// job list.
//
// Status describes whether the git host could MERGE the configuration,
// which is a different question from whether this CLI obtained one. An
// unavailable resolution is reported VALID: telling users their CI file is
// broken because a third party was unreachable would be a diagnosis the run
// has no evidence for.
//
// A resolution the git host itself judged INVALID is the opposite case, and
// it is carried through. That verdict is about the user's own config, and
// an invalid merge is partial or empty - so reporting it valid would hand
// the analysis a pipeline with the unmergeable jobs simply missing, and
// every control would pass over what remained. A standalone run of the same
// commit reports INCOMPLETE; platform mode has to agree with it.
func platformMergedConfig(conf *configuration.Configuration) (MergedCIConfResponse, bool) {
	var out MergedCIConfResponse
	if conf == nil || !conf.PlatformRun.Engaged() {
		return out, false
	}
	merged, _ := conf.PlatformRun.MergedYAML()
	out.CiConfig.MergedYaml = merged
	out.CiConfig.Status = "VALID"
	if conf.PlatformRun.ConfigInvalid() {
		out.CiConfig.Status = "INVALID"
		out.CiConfig.Errors = []string{
			"the git host reported this CI configuration as invalid; the merged pipeline it returned is incomplete",
		}
	}
	out.CiConfig.Includes = platformIncludes(conf)
	return out, true
}

// platformIncludes decodes the snapshot's per-include attribution into the
// CLI's own include shape. The platform carries these AS-IS - they ARE
// MergedCIConfResponseInclude values, never a translation - so a decode
// failure means the contract was broken, not that a field moved.
//
// An entry that fails to decode is DROPPED rather than partially applied.
// Attribution is used to decide whether a job came from upstream or from the
// project, and a half-decoded include produces a confidently wrong answer;
// dropping it leaves the list short, which the caller detects as missing
// attribution and degrades honestly.
// It also returns nothing when the merged configuration in use did NOT come
// from the same snapshot these includes did. The snapshot's attribution
// describes the anchor's configuration; on a digest-divergent branch the
// config being evaluated is the branch's own, and attaching the anchor's
// attribution to it mis-classifies every job the branch's include changes
// touched. See RunContext.ConfigAndIncludesAgree.
func platformIncludes(conf *configuration.Configuration) []MergedCIConfResponseInclude {
	if !conf.PlatformRun.ConfigAndIncludesAgree() {
		return nil
	}
	raw, ok := conf.PlatformRun.SnapshotIncludes()
	if !ok {
		return nil
	}
	out := make([]MergedCIConfResponseInclude, 0, len(raw))
	for _, r := range raw {
		var inc MergedCIConfResponseInclude
		if err := json.Unmarshal(r, &inc); err != nil {
			logger.WithError(err).Warn("platform snapshot carried an include this CLI could not decode; dropping it")
			continue
		}
		out = append(out, inc)
	}
	return out
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
	var err error

	if project.Archived {
		l.Info("Archived project, cannot retrieve merged CI conf")
		return nil, nil, nil, "", "", nil
	}

	if project.NotFound {
		l.Info("Project not found on GitLab, cannot retrieve merged CI conf")
		return nil, nil, nil, "", "", nil
	}

	// Get the configuration file
	// If local CI config content is provided (via --local or auto-detected), use it
	// instead of fetching from the remote repository
	var confByte []byte
	switch {
	case conf != nil && conf.LocalCIConfigContent != nil && conf.PlatformRun.Engaged():
		// Platform mode reads the project's own unmerged CI file off disk to
		// avoid an API call, and must hand back exactly what that API call
		// would have returned: the file as committed.
		//
		// Inlining local includes (the branch below) is right for --local,
		// where the point is to merge uncommitted edits, and wrong here. The
		// merge itself comes from the platform, so inlining buys nothing,
		// and it moves every job from an `include: local` file into the
		// project's own job map - which is what decides whether a job counts
		// as hardcoded. The same commit would then score differently
		// depending only on whether the runner happened to have a checkout.
		confByte = conf.LocalCIConfigContent
		l.Info("Using the checkout's CI configuration file instead of fetching it")
	case conf != nil && conf.LocalCIConfigContent != nil:
		// Resolve include:local entries from the local filesystem so they use
		// local content instead of being resolved from the remote repo by GitLab.
		// Since include:local jobs are always treated as hardcoded in the analysis,
		// inlining them doesn't affect include attribution.
		resolved, resolveErr := ResolveLocalIncludes(conf.LocalCIConfigContent, conf.GitRepoRoot)
		if resolveErr != nil {
			l.WithError(resolveErr).Error("Failed to resolve local includes")
			return nil, nil, nil, "", "", resolveErr
		}
		confByte = resolved
		l.Info("Using local CI configuration file instead of remote")
	case conf != nil && conf.PlatformRun.Engaged() && CIConfigPathIsExternal(project.CiConfPath):
		// The root config lives in another project, or at a URL. Neither is
		// readable through THIS project's file API, so the fetch below would
		// be a request guaranteed to 404. Skip it and take the same route a
		// refused read takes: the merged pipeline still comes from the
		// platform, and the two controls that compare against the pre-merge
		// document report not_evaluable.
		l.WithField("ciConfPath", project.CiConfPath).Info("CI configuration is hosted outside this project; the merged pipeline still comes from the platform")
		confByte = nil

	default:
		var errPlatform error
		confByte, errPlatform, err = FetchGitlabFile(project.Path, project.CiConfPath, ref, token, url, conf)
		if err != nil || errPlatform != nil {
			// In platform mode this is not fatal. The MERGED pipeline comes
			// from the platform and is what almost every rule reads; the
			// project's own unmerged file is needed by two controls only.
			// Aborting here would discard a complete, analysable pipeline
			// because of a file two checks wanted - and the run would end
			// with no findings and no explanation, which is the least useful
			// report there is.
			//
			// The caller detects the gap (an empty root beside a merged
			// pipeline that has jobs is not a configuration anyone writes)
			// and reports those two controls not_evaluable.
			if conf != nil && conf.PlatformRun.Engaged() {
				l.WithFields(logrus.Fields{
					"err":         err,
					"errPlatform": errPlatform,
				}).Warn("Could not read the project's own CI file; continuing on the platform's merged configuration")
				confByte = nil
				break
			}

			l.WithFields(logrus.Fields{
				"err":         err,
				"errPlatform": errPlatform,
			}).Error("Unable to get project's CI conf file")

			if errPlatform != nil {
				return nil, nil, nil, "", "", errPlatform
			}
			return nil, nil, nil, "", "", err
		}
	}
	confStr := string(confByte)

	// Get the merged response.
	//
	// Resolving a CI configuration means merging every include, which only
	// GitLab can do and only through an API a CI job token cannot reach. In
	// PLATFORM MODE that makes it an extended-rights collection: it is read
	// from the platform, which resolved it out of band, and the runner
	// makes no such call itself.
	//
	// A platform-supplied merge carries the merged document but NOT the
	// per-include attribution GitLab's own response adds, and when the
	// platform could resolve nothing it carries no document at all. Neither
	// gap is papered over here: this returns what it actually has, and
	// control/task.go marks the affected controls not_evaluable so an empty
	// job or include list can never read as a clean pipeline.
	if platformMerged, usePlatform := platformMergedConfig(conf); usePlatform {
		mergedResponse = platformMerged
	} else {
		mergedResponse, err = FetchGitlabMergedCIConf(project.Path, confStr, project.LatestHeadCommitSha, token, url, conf)
		if err != nil {
			l.WithError(err).Error("Unable to get project's CI merged conf")
			return nil, nil, nil, confStr, "", err
		}
	}

	// Unmarshal the original configuration. CI component template files use a
	// multi-document YAML layout where `spec:` is the first document and job
	// definitions come after the `---` separator. yaml.Unmarshal only reads
	// the first document, so jobs in the second document would be invisible
	// to the hardcoded-job detector. unmarshalMultiDocGitlabCI merges all
	// documents so that jobs defined after a `spec:` block are still seen.
	var unmarshalErr error
	gitlabConf, unmarshalErr = unmarshalMultiDocGitlabCI(confByte)
	if unmarshalErr != nil {
		if mergedResponse.CiConfig.Status == "INVALID" {
			l.WithError(unmarshalErr).Info("Unable to unmarshal the configuration to GitlabCIConf, but the CI config is invalid")
			return nil, nil, &mergedResponse, confStr, mergedResponse.CiConfig.MergedYaml, nil
		}

		l.WithError(unmarshalErr).Error("Unable to unmarshal the configuration to GitlabCIConf")
		return nil, nil, &mergedResponse, confStr, mergedResponse.CiConfig.MergedYaml, unmarshalErr
	}

	// Extract and unmarshal the merged configuration
	if err := yaml.Unmarshal([]byte(mergedResponse.CiConfig.MergedYaml), &mergedConf); err != nil {
		l.WithError(err).Error("Unable to unmarshal the merged configuration to GitlabCIConf")
		return &gitlabConf, nil, &mergedResponse, confStr, mergedResponse.CiConfig.MergedYaml, err
	}

	return &gitlabConf, &mergedConf, &mergedResponse, confStr, mergedResponse.CiConfig.MergedYaml, nil
}

// unmarshalMultiDocGitlabCI decodes all YAML documents in data and merges
// them into a single GitlabCIConf. This handles CI component template files
// that start with a `spec:` block in the first document and define jobs
// after a `---` separator in subsequent documents. With a plain
// yaml.Unmarshal only the first document would be read, causing jobs and
// any top-level settings in later documents to be invisible to the
// hardcoded-job detector and other downstream consumers.
//
// Merge contract:
//   - GitlabJobs is the union across every document (a job defined in any
//     document is visible to the detector). Later documents win on key
//     collisions, mirroring how a user would expect a later override.
//   - Every other GitlabCIConf field uses first-doc-wins: the first
//     document that sets the field is the authoritative value, mirroring
//     the typical `spec:` (doc 1) + real config (doc 2+) layout. Default
//     is treated structurally — Default.Image is the only sub-field and
//     is checked individually.
//
// All exported fields of GitlabCIConf are handled. When a field is added
// to GitlabCIConf, extend the merge logic here too — the
// TestUnmarshalMultiDocGitlabCI_AllFieldsCovered test fails fast if a
// new field lands without a merge branch.
func unmarshalMultiDocGitlabCI(data []byte) (GitlabCIConf, error) {
	result := GitlabCIConf{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc GitlabCIConf
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, err
		}
		// Jobs: union across documents.
		if doc.GitlabJobs != nil {
			if result.GitlabJobs == nil {
				result.GitlabJobs = make(map[string]interface{})
			}
			for k, v := range doc.GitlabJobs {
				result.GitlabJobs[k] = v
			}
		}
		// Everything else: first-doc-wins.
		if result.Spec == nil && doc.Spec != nil {
			result.Spec = doc.Spec
		}
		if result.Include == nil && doc.Include != nil {
			result.Include = doc.Include
		}
		if result.Stages == nil && doc.Stages != nil {
			result.Stages = doc.Stages
		}
		if result.GlobalVariables == nil && doc.GlobalVariables != nil {
			result.GlobalVariables = doc.GlobalVariables
		}
		if result.Workflow == nil && doc.Workflow != nil {
			result.Workflow = doc.Workflow
		}
		if result.Image == nil && doc.Image != nil {
			result.Image = doc.Image
		}
		if result.BeforeScript == nil && doc.BeforeScript != nil {
			result.BeforeScript = doc.BeforeScript
		}
		if result.AfterScript == nil && doc.AfterScript != nil {
			result.AfterScript = doc.AfterScript
		}
		if result.DefaultScript == nil && doc.DefaultScript != nil {
			result.DefaultScript = doc.DefaultScript
		}
		if result.Cache == nil && doc.Cache != nil {
			result.Cache = doc.Cache
		}
		// CIConfDefault is a struct (not interface{}). Its only field is
		// Image, so the zero-value test is whether that nested field is
		// still unset. Do NOT switch this to `result.Default ==
		// CIConfDefault{}`: Image is an interface that can hold a map
		// (image: {name:, entrypoint:}), and struct == on an interface
		// holding a map panics at runtime.
		//
		// LIMITATION: this is sub-field-blind. The merge decision keys on
		// Image alone, and TestUnmarshalMultiDocGitlabCI_AllFieldsCovered
		// only checks that the top-level Default field is non-zero. When
		// CIConfDefault grows to match GitLab's full `default:` block
		// (services, cache, before_script, tags, retry, …), a doc that
		// sets those but not Image would be dropped, and the tripwire
		// would NOT catch it. Revisit both this branch and the test then.
		if result.Default.Image == nil && doc.Default.Image != nil {
			result.Default = doc.Default
		}
	}
	return result, nil
}

// ResolveLocalIncludes pre-processes a local CI configuration to inline include:local entries
// from the local filesystem. Other include types (component, template, project, remote) are
// preserved for GitLab's ciConfig API to resolve server-side.
//
// If the YAML cannot be parsed or no local includes are found, the original content is returned
// unchanged. If a local include file cannot be read, it is left in the include list for GitLab
// to resolve from the remote repository.
func ResolveLocalIncludes(content []byte, repoRoot string) ([]byte, error) {
	l := logger.WithFields(logrus.Fields{
		"action":   "ResolveLocalIncludes",
		"repoRoot": repoRoot,
	})

	if repoRoot == "" {
		return content, nil
	}

	// Parse the YAML into a generic map to inspect includes
	var yamlDoc map[interface{}]interface{}
	if err := yaml.Unmarshal(content, &yamlDoc); err != nil {
		l.WithError(err).Debug("Unable to parse YAML for local include resolution, using content as-is")
		return content, nil
	}

	includeRaw, ok := yamlDoc["include"]
	if !ok {
		return content, nil // No includes at all
	}

	// Normalize include entries to a slice
	var includes []interface{}
	switch v := includeRaw.(type) {
	case []interface{}:
		includes = v
	case string:
		// Single string is shorthand for local include
		includes = []interface{}{v}
	case map[interface{}]interface{}:
		// Single map entry
		includes = []interface{}{v}
	default:
		l.WithField("type", fmt.Sprintf("%T", includeRaw)).Debug("Unexpected include type, skipping resolution")
		return content, nil
	}

	var nonLocalIncludes []interface{}
	var localContents [][]byte
	hasLocalIncludes := false

	for _, inc := range includes {
		switch entry := inc.(type) {
		case string:
			// A bare string in the include list is a local include
			fileContent, err := readLocalInclude(repoRoot, entry)
			if err != nil {
				return nil, fmt.Errorf("unable to read local include '%s': %w", entry, err)
			}
			l.WithField("path", entry).Info("Resolved local include from filesystem")
			localContents = append(localContents, fileContent)
			hasLocalIncludes = true

		case map[interface{}]interface{}:
			if localPath, ok := entry["local"]; ok {
				pathStr := fmt.Sprintf("%v", localPath)
				fileContent, err := readLocalInclude(repoRoot, pathStr)
				if err != nil {
					return nil, fmt.Errorf("unable to read local include '%s': %w", pathStr, err)
				}
				l.WithField("path", pathStr).Info("Resolved local include from filesystem")
				localContents = append(localContents, fileContent)
				hasLocalIncludes = true
			} else {
				nonLocalIncludes = append(nonLocalIncludes, entry)
			}

		default:
			nonLocalIncludes = append(nonLocalIncludes, entry)
		}
	}

	if !hasLocalIncludes {
		return content, nil // No local includes to resolve
	}

	// Update the include list to only keep non-local entries
	if len(nonLocalIncludes) > 0 {
		yamlDoc["include"] = nonLocalIncludes
	} else {
		delete(yamlDoc, "include")
	}

	// Marshal the modified main config back to YAML
	mainYaml, err := yaml.Marshal(yamlDoc)
	if err != nil {
		l.WithError(err).Warn("Unable to marshal modified YAML, using original content")
		return content, nil
	}

	// Build combined YAML: local file contents first, then main config
	var combined []byte
	for _, lc := range localContents {
		combined = append(combined, lc...)
		combined = append(combined, '\n')
	}
	combined = append(combined, mainYaml...)

	l.WithFields(logrus.Fields{
		"localIncludesResolved": len(localContents),
		"nonLocalIncludes":      len(nonLocalIncludes),
	}).Info("Local includes resolved from filesystem")

	return combined, nil
}

// readLocalInclude reads a GitLab `include:local` target, resolving it only
// within the analyzed repository. GitLab resolves include:local relative to
// the project root and never outside it, so a target that resolves outside
// repoRoot is rejected. Symlinks are resolved on both sides before the
// containment check so the decision is made on the real target.
// maxLocalIncludeBytes caps a single include:local file. GitLab bounds CI
// config size similarly; the cap keeps an oversized or pathologically nested
// committed file from exhausting memory or the YAML decoder's stack when the
// content is later unmarshalled.
const maxLocalIncludeBytes = 1 << 20 // 1 MiB

// ResolveWithinRepo joins relPath onto repoRoot and returns the joined path,
// but only after confirming it does not escape repoRoot. Symlinks are resolved
// on both sides so a link planted in the checkout cannot disguise an
// out-of-repo target. It is the shared containment guard for repository-
// relative paths taken from the analyzed project (include:local targets and
// the CI config path).
func ResolveWithinRepo(repoRoot, relPath string) (string, error) {
	// Resolve the root first, then join onto it, so a target that does not yet
	// exist (EvalSymlinks below fails) is still compared against the same
	// resolved base — otherwise a repoRoot that itself lives under a symlink
	// (e.g. macOS /var -> /private/var) yields a false mismatch.
	rootReal := repoRoot
	if real, err := filepath.EvalSymlinks(repoRoot); err == nil {
		rootReal = real
	}
	joined := filepath.Join(rootReal, relPath)
	targetReal := joined
	if real, err := filepath.EvalSymlinks(joined); err == nil {
		targetReal = real
	}
	if !pathWithin(rootReal, targetReal) {
		return "", fmt.Errorf("%q resolves to %q outside the repository %q", relPath, targetReal, rootReal)
	}
	return joined, nil
}

func readLocalInclude(repoRoot, includePath string) ([]byte, error) {
	joined, err := ResolveWithinRepo(repoRoot, includePath)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(joined) //nolint:gosec // path validated: contained within the analyzed repository
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxLocalIncludeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxLocalIncludeBytes {
		return nil, fmt.Errorf("include:local %q exceeds the %d-byte limit", includePath, maxLocalIncludeBytes)
	}
	return data, nil
}

// pathWithin reports whether target is root itself or lies beneath it.
func pathWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
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

	// An EMPTY value is not a substitution. Rendering `$SECURE_ANALYZERS_PREFIX/semgrep:5`
	// as `/semgrep:5` produces a reference that looks resolved, carries no
	// `$` for the caller to notice, and is not the reference the job uses -
	// so the registry and tag checks then answer confidently about an image
	// that does not exist. Leaving the placeholder in place is what lets
	// parseImageReference mark the ref unresolved and the rules abstain.
	lookup := func(m map[string]string, name string) (string, bool) {
		val, found := m[name]
		return val, found && val != ""
	}

	resolveVariables := func(input string) string {
		return r.ReplaceAllStringFunc(input, func(match string) string {
			varName := regexp.MustCompile(`[\$\{\}%]`).ReplaceAllString(match, "")

			for _, source := range []map[string]string{project, group, instance, job, defaultJob, predefined} {
				if val, found := lookup(source, varName); found {
					return val
				}
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
