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
		// A hidden job (leading `.`) never runs on its own; a job that extends it is listed under its own name and judged on its own merged content.
		if strings.HasPrefix(j.Name, ".") {
			continue
		}
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
	// 4. command tokens of the job's own lines, and the image arguments of its container-run
	// lines (`docker run <image>`): all lines are tokenized first so the recognizers, not the
	// line order, decide which tool a job names.
	var tokens, images []string
	var following [][]string
	for _, line := range j.Scripts {
		c, im, f := lineTokens(line)
		tokens = append(tokens, c...)
		images = append(images, im...)
		following = append(following, f...)
	}
	if tool, ok := toolOfTokens(tokens, following, images, recs); ok {
		return Match{KindSecretDetection, j.Name, tool, EvidenceCommand}, true
	}
	// 5. wrapper scripts, one level: the lines of every script the job runs, same order rule
	if repoRoot != "" {
		var inner, innerImages []string
		var innerFollowing [][]string
		for _, line := range j.Scripts {
			rel, ok := wrapperPath(line)
			if !ok {
				continue
			}
			for _, l := range readWrapper(repoRoot, rel, j.Name) {
				c, im, f := lineTokens(l)
				inner = append(inner, c...)
				innerImages = append(innerImages, im...)
				innerFollowing = append(innerFollowing, f...)
			}
		}
		if tool, ok := toolOfTokens(inner, innerFollowing, innerImages, recs); ok {
			return Match{KindSecretDetection, j.Name, tool, EvidenceWrapperScript}, true
		}
	}
	return Match{}, false
}

// toolOfTokens returns the tool of the first recognizer (in list order) one of whose
// commands matches a token (and, for a multi-word command, the fields following it, same
// index as tokens) or one of whose image patterns matches an image candidate, the
// candidate canonicalized like a job image.
func toolOfTokens(tokens []string, following [][]string, images []string, recs []Recognizer) (string, bool) {
	keys := make([]string, len(images))
	for i, ref := range images {
		keys[i] = imageKey(parseImageRef(ref))
	}
	for _, r := range recs {
		for _, want := range r.Commands {
			head, tail := commandHeadAndTail(want)
			for i, tok := range tokens {
				if tok == head && followsFields(following[i], tail) {
					return r.Tool, true
				}
			}
		}
		for _, pat := range r.Images {
			for _, key := range keys {
				if globMatch(pat, key) {
					return r.Tool, true
				}
			}
		}
	}
	return "", false
}

// commandHeadAndTail splits a recognizer command on spaces into its first word (matched
// against a cmds token) and the words that must follow it in order (a multi-purpose tool's
// subcommand, `ggshield secret` disambiguating from `ggshield iac`). A single-word command
// has no tail, so it matches regardless of what follows.
func commandHeadAndTail(want string) (head string, tail []string) {
	fields := strings.Fields(want)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields[1:]
}

// followsFields reports whether tail appears, contiguously and in order, in fields at a
// position where a subcommand may stand: an index whose field is not a flag (a leading `-`)
// and before which every field is a flag or a flag's value, so global flags may precede the
// subcommand (`ggshield --config f.yaml secret scan`) but another positional word may not
// (`ggshield iac scan` never matches `secret`). A field is a flag's value only under
// flagValueField; a bare word is never one, so `ggshield -v iac scan .` stops at `iac` and
// does not reach the legacy `scan` tail. The cost, accepted: a bare-word value before the
// subcommand (`corp-scan --profile ci secrets`) is taken as a positional word and the
// command is not recognized. The candidates are tried in order and the first that matches
// wins. An empty tail always matches, a single-word command's case.
func followsFields(fields, tail []string) bool {
	if len(tail) == 0 {
		return true
	}
	afterValueFlag := false
	for i, f := range fields {
		if strings.HasPrefix(f, "-") {
			afterValueFlag = !strings.Contains(f, "=")
			continue
		}
		if hasPrefixFields(fields[i:], tail) {
			return true
		}
		if !afterValueFlag || !flagValueField(f) {
			return false
		}
		afterValueFlag = false
	}
	return false
}

// flagValueField reports whether f, standing right after a flag without `=`, is taken as
// that flag's value: any field that is not a bare word. A bare word is made only of letters,
// hyphens and underscores (`iac`, `sca`, `secret`, `scan`), the shape of a subcommand, so it
// is never a flag value; a field holding a digit, a quote or one of `. / : = @ ~ ,` (a path,
// a number, a host, a list), or any other character (`$CONFIG`), is. This is the one place
// the rule lives.
func flagValueField(f string) bool {
	for _, r := range f {
		if !isBareWordRune(r) {
			return true
		}
	}
	return false
}

// isBareWordRune reports whether r may appear in a bare word: a letter, a hyphen or an
// underscore.
func isBareWordRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '_'
}

// hasPrefixFields reports whether fields starts with tail, in order.
func hasPrefixFields(fields, tail []string) bool {
	if len(fields) < len(tail) {
		return false
	}
	for i, w := range tail {
		if fields[i] != w {
			return false
		}
	}
	return true
}

// parseImageRef splits an image reference into the registry and the name imageKey reads:
// the part before the first `/` is a registry when it holds a `.` or a `:` or is
// `localhost`; otherwise the whole reference is a Docker Hub name.
func parseImageRef(ref string) *ir.Image {
	if i := strings.IndexByte(ref, '/'); i > 0 {
		if host := ref[:i]; strings.ContainsAny(host, ".:") || host == "localhost" {
			return &ir.Image{Registry: host, Name: ref[i+1:]}
		}
	}
	return &ir.Image{Name: ref}
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
