package capability

import (
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
)

var logger = logrus.WithField("context", "capability")

// maxWrapperScriptBytes caps a wrapper script read from the checkout (spec section 4.3).
const maxWrapperScriptBytes = 256 << 10

// Recognize returns one Match per (job, capability) over pipe, by the first rule that
// matches in the order image, include, report, command, wrapper script, with recognizers
// tried in their list order. repoRoot is the checkout root wrapper scripts are read under;
// an empty root disables wrapper scripts. A nil pipeline or an empty list yields nil.
func Recognize(pipe *ir.NormalizedPipeline, repoRoot string, recs []Recognizer) []Match {
	if pipe == nil || len(recs) == 0 {
		return nil
	}
	includeTools := includeEvidence(pipe.Includes, recs)
	var out []Match
	for _, j := range pipe.Jobs {
		if m, ok := recognizeJob(j, repoRoot, recs, includeTools); ok {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Job != out[b].Job {
			return out[a].Job < out[b].Job
		}
		return out[a].Kind < out[b].Kind
	})
	return out
}

// includeEvidence maps an include's identity (its template path, source or component name)
// to the tool whose Includes name it; jobs defined by that include match by EvidenceInclude.
func includeEvidence(includes []ir.Include, recs []Recognizer) map[string]string {
	out := map[string]string{}
	for _, inc := range includes {
		for _, r := range recs {
			for _, want := range r.Includes {
				if want == inc.TemplatePath || want == inc.Source || want == inc.Path || want == inc.ComponentName {
					for _, key := range []string{inc.TemplatePath, inc.Source, inc.Path} {
						if key != "" {
							if _, dup := out[key]; !dup {
								out[key] = r.Tool
							}
						}
					}
				}
			}
		}
	}
	return out
}

func recognizeJob(j ir.Job, repoRoot string, recs []Recognizer, includeTools map[string]string) (Match, bool) {
	// 1. image
	if j.Image != nil {
		ref := imageKey(j.Image)
		for _, r := range recs {
			for _, pat := range r.Images {
				if globMatch(pat, ref) {
					return Match{KindSecretDetection, j.Name, r.Tool, EvidenceImage}, true
				}
			}
		}
	}
	// 2. include: the job is defined by an include a recognizer names (OriginInclude is that
	// include's Source or Path, both keys of includeTools)
	if tool, ok := includeTools[j.OriginInclude]; ok && j.OriginInclude != "" {
		return Match{KindSecretDetection, j.Name, tool, EvidenceInclude}, true
	}
	// 3. report artifact
	for _, rt := range j.ReportTypes {
		for _, r := range recs {
			for _, want := range r.ReportTypes {
				if rt == want {
					return Match{KindSecretDetection, j.Name, r.Tool, EvidenceReport}, true
				}
			}
		}
	}
	// 4. command tokens of the job's own lines: all lines are tokenized first so the
	// recognizers, not the line order, decide which tool a job names.
	var tokens []string
	for _, line := range j.Scripts {
		tokens = append(tokens, commandTokens(line)...)
	}
	if tool, ok := toolOfTokens(tokens, recs); ok {
		return Match{KindSecretDetection, j.Name, tool, EvidenceCommand}, true
	}
	// 5. wrapper scripts, one level: the lines of every script the job runs, same order rule
	if repoRoot != "" {
		var inner []string
		for _, line := range j.Scripts {
			rel, ok := wrapperPath(line)
			if !ok {
				continue
			}
			for _, l := range readWrapper(repoRoot, rel, j.Name) {
				inner = append(inner, commandTokens(l)...)
			}
		}
		if tool, ok := toolOfTokens(inner, recs); ok {
			return Match{KindSecretDetection, j.Name, tool, EvidenceWrapperScript}, true
		}
	}
	return Match{}, false
}

func toolOfTokens(tokens []string, recs []Recognizer) (string, bool) {
	for _, r := range recs {
		for _, want := range r.Commands {
			for _, tok := range tokens {
				if tok == want {
					return r.Tool, true
				}
			}
		}
	}
	return "", false
}

// imageKey is `<registry>/<name>` with the tag and digest stripped; a bare Docker Hub name
// is keyed under docker.io so `zricethezav/gitleaks` and `docker.io/zricethezav/gitleaks`
// compare equal.
func imageKey(img *ir.Image) string {
	name := img.Name
	if i := strings.IndexAny(name, ":@"); i >= 0 {
		name = name[:i]
	}
	registry := utils.CanonicalizeDockerHubRegistry(img.Registry)
	if registry == "" || registry == "unknown" {
		registry = "docker.io"
	}
	return registry + "/" + name
}

// globMatch matches pat against ref, pat being `<registry>/<name>` with optional `*`; a
// pattern without a registry is tried under docker.io.
func globMatch(pat, ref string) bool {
	if !strings.Contains(pat, "/") || !strings.ContainsAny(strings.SplitN(pat, "/", 2)[0], ".:") {
		pat = "docker.io/" + pat
	}
	ok, err := path.Match(pat, ref)
	return err == nil && ok
}

// readWrapper returns the lines of one wrapper script under repoRoot, or nothing: a path
// outside the root, an absent or unreadable file, or one over the cap yields no evidence
// and a debug line (spec decision 5: never a failure).
func readWrapper(repoRoot, rel, job string) []string {
	l := logger.WithFields(logrus.Fields{"job": job, "script": rel})
	abs, err := gitlab.ResolveWithinRepo(repoRoot, rel)
	if err != nil {
		l.WithError(err).Debug("capability: wrapper script not under the repository, skipped")
		return nil
	}
	f, err := os.Open(abs)
	if err != nil {
		l.WithError(err).Debug("capability: wrapper script not readable, skipped")
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxWrapperScriptBytes+1))
	if err != nil || len(data) > maxWrapperScriptBytes {
		l.Debug("capability: wrapper script unreadable or over 256 KiB, skipped")
		return nil
	}
	return strings.Split(string(data), "\n")
}
