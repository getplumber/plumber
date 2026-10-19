package capability

import (
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/ir"
)

var logger = logrus.WithField("context", "capability")

// maxWrapperScriptBytes caps a wrapper script read from the checkout (spec section 4.3).
const maxWrapperScriptBytes = 256 << 10

// The include kinds that yield a subject (ir.Include.Kind): a template's and a component's
// identity, a project include's project path.
const (
	includeKindTemplate  = "template"
	includeKindComponent = "component"
	includeKindProject   = "project"
)

// Recognize returns one Match per (job, capability) over pipe (spec 4.3), sorted by job then
// kind. Hidden jobs (a dot-prefixed name) are skipped. For each capability, its recognizers
// are tried in list order, each recognizer's fields in their precedence order (images,
// gitlab_include_template, gitlab_include_component, gitlab_include_project,
// gitlab_report_types, commands, wrapper_script) and each field's patterns in order against the field's subjects; the first
// hit names the tool (the recognizer's, else the pattern's text) and the evidence (the
// field's name). repoRoot is the checkout root wrapper scripts are read under; the caller
// passes it only when the checkout is the analyzed project at its ref, and an empty root
// turns the wrapper_script subject off. A nil pipeline or an empty list yields nil.
func Recognize(pipe *ir.NormalizedPipeline, repoRoot string, decls []Compiled) []Match {
	if pipe == nil || len(decls) == 0 {
		return nil
	}
	kinds := includeKinds(pipe.Includes)
	wrappers := map[string][]string{}
	var out []Match
	for _, j := range pipe.Jobs {
		// A hidden job never runs on its own; a job that extends it is listed under its own
		// name and judged on its own merged content.
		if strings.HasPrefix(j.Name, ".") {
			continue
		}
		s := newJobSubjects(j, kinds, repoRoot, wrappers)
		for _, c := range decls {
			if tool, evidence, ok := s.match(c); ok {
				out = append(out, Match{Kind: c.Name, Job: j.Name, Tool: tool, Evidence: evidence})
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Job != out[b].Job {
			return out[a].Job < out[b].Job
		}
		return out[a].Kind < out[b].Kind
	})
	return out
}

// includeOrigin is what a job's include origin resolves to: the include's kind and, for a
// project include, its project path as written.
type includeOrigin struct {
	kind    string
	project string
}

// includeKinds maps the identity of each template, component or project include (its Source,
// and its Path, the identity a job's OriginInclude carries when the include has no Source) to
// its kind and project; any other include kind is not a subject. The first include of an
// identity wins. A component identity is also keyed by its version-stripped form (spec 4.3 /
// docs/PBOM.md: the component subject is host/path/name without "@<version>"), so a job's
// OriginInclude is found here whichever side, if any, carries the version.
func includeKinds(includes []ir.Include) map[string]includeOrigin {
	out := map[string]includeOrigin{}
	for _, inc := range includes {
		if inc.Kind != includeKindTemplate && inc.Kind != includeKindComponent && inc.Kind != includeKindProject {
			continue
		}
		origin := includeOrigin{kind: inc.Kind, project: inc.Project}
		for _, key := range []string{inc.Source, inc.Path} {
			if key == "" {
				continue
			}
			if _, dup := out[key]; !dup {
				out[key] = origin
			}
			if inc.Kind == includeKindComponent {
				if stripped := stripComponentVersion(key); stripped != key {
					if _, dup := out[stripped]; !dup {
						out[stripped] = origin
					}
				}
			}
		}
	}
	return out
}

// stripComponentVersion strips a trailing "@<version>" from a component identity (the last
// "@" and what follows): spec 4.3 / docs/PBOM.md promise the gitlab_include_component subject
// as host/path/name, never the pinned version. A value with no "@" is returned unchanged.
func stripComponentVersion(id string) string {
	if i := strings.LastIndex(id, "@"); i >= 0 {
		return id[:i]
	}
	return id
}

// jobSubjects holds the subjects of one job, computed once; the wrapper scripts' lines are
// read lazily, the first time a recognizer reaches the wrapper_script field, and each file at
// most once per Recognize call (the wrappers cache).
type jobSubjects struct {
	job       string
	images    []string
	templates []string
	compons   []string
	projects  []string
	reports   []string
	lines     []string
	entries   []string
	repoRoot  string
	wrappers  map[string][]string
	wrapped   []string
	readDone  bool
}

func newJobSubjects(j ir.Job, kinds map[string]includeOrigin, repoRoot string, wrappers map[string][]string) *jobSubjects {
	s := &jobSubjects{job: j.Name, reports: j.ReportTypes, entries: j.Scripts, repoRoot: repoRoot, wrappers: wrappers}
	if j.Image != nil {
		s.images = append(s.images, imageKey(j.Image))
	}
	s.lines = scriptLines(j.Scripts)
	for _, l := range s.lines {
		if ref, ok := containerRunImage(l); ok {
			s.images = append(s.images, imageKey(parseImageRef(ref)))
		}
	}
	if id := j.OriginInclude; id != "" {
		o, found := kinds[id]
		if !found {
			if stripped := stripComponentVersion(id); stripped != id {
				o, found = kinds[stripped]
			}
		}
		if found {
			switch o.kind {
			case includeKindTemplate:
				s.templates = []string{id}
			case includeKindComponent:
				// The subject is host/path/name: strip the version whichever side carried it.
				s.compons = []string{stripComponentVersion(id)}
			case includeKindProject:
				// The project path only: the identity is the file, and the ref is never a subject.
				if o.project != "" {
					s.projects = []string{o.project}
				}
			}
		}
	}
	return s
}

// match returns the tool and evidence of the first recognizer of c that matches the job.
func (s *jobSubjects) match(c Compiled) (tool, evidence string, ok bool) {
	for _, r := range c.Recognizers {
		for _, f := range r.Fields {
			if len(f.Patterns) == 0 {
				continue
			}
			subjects := s.of(f.Name)
			for _, p := range f.Patterns {
				for _, subj := range subjects {
					if p.Glob.Match(subj) {
						if tool = r.Tool; tool == "" {
							tool = p.Source
						}
						return tool, f.Name, true
					}
				}
			}
		}
	}
	return "", "", false
}

// of returns the subjects of one field.
func (s *jobSubjects) of(field string) []string {
	switch field {
	case EvidenceImages:
		return s.images
	case EvidenceGitlabIncludeTemplate:
		return s.templates
	case EvidenceGitlabIncludeComponent:
		return s.compons
	case EvidenceGitlabIncludeProject:
		return s.projects
	case EvidenceGitlabReportTypes:
		return s.reports
	case EvidenceCommands:
		return s.lines
	case EvidenceWrapperScript:
		return s.wrapperLines()
	}
	return nil
}

// wrapperLines returns the lines of every wrapper script the job's entries run (every
// qualifying call of every entry, each script once per job), one level only (a script the
// wrapper itself calls is never followed), each file read at most once per Recognize call.
func (s *jobSubjects) wrapperLines() []string {
	if s.readDone || s.repoRoot == "" {
		return s.wrapped
	}
	s.readDone = true
	added := map[string]bool{}
	for _, e := range s.entries {
		for _, rel := range wrapperPaths(e) {
			if added[rel] {
				continue
			}
			added[rel] = true
			lines, seen := s.wrappers[rel]
			if !seen {
				lines = readWrapper(s.repoRoot, rel, s.job)
				s.wrappers[rel] = lines
			}
			s.wrapped = append(s.wrapped, lines...)
		}
	}
	return s.wrapped
}

// readWrapper returns the lines of one wrapper script under repoRoot, comments removed (see
// scriptLines), or nothing: a path outside the root, an absent or unreadable file, or one
// over the cap yields no evidence and a debug line (spec decision 5: never a failure). The
// file's content is never logged.
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
	return scriptLines([]string{string(data)})
}
