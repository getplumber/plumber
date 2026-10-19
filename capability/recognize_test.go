package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	"github.com/getplumber/plumber/capability/capdecl"
	"github.com/getplumber/plumber/internal/ir"
)

func job(name string, image string, scripts ...string) ir.Job {
	j := ir.Job{Name: name, Scripts: scripts}
	if image != "" {
		j.Image = imageOf(image)
	}
	return j
}

// imageOf splits a reference the way the collector does for the fields Recognize reads.
func imageOf(ref string) *ir.Image {
	registry, name := "docker.io", ref
	if i := indexRegistry(ref); i >= 0 {
		registry, name = ref[:i], ref[i+1:]
	}
	if j := strings.IndexAny(name, ":@"); j >= 0 {
		name = name[:j]
	}
	return &ir.Image{Registry: registry, Name: name}
}

// indexRegistry is the index of the first `/` whose prefix contains a `.` or a `:` (a registry
// host), or -1.
func indexRegistry(ref string) int {
	i := strings.IndexByte(ref, '/')
	if i > 0 && strings.ContainsAny(ref[:i], ".:") {
		return i
	}
	return -1
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// builtin compiles the CLI's built-in list; it never warns.
func builtin(t *testing.T) []Compiled {
	t.Helper()
	return Compile(Builtin(), func(s string) { t.Fatalf("the built-in list warns: %s", s) })
}

// compiled compiles one capability declared with recs.
func compiled(t *testing.T, name string, recs ...capdecl.Recognizer) []Compiled {
	t.Helper()
	return Compile([]Declaration{{Name: name, Recognizers: recs}}, func(s string) { t.Fatalf("unexpected warning: %s", s) })
}

// assertMatchesByJob fails t unless got holds exactly the matches of want, keyed by job.
func assertMatchesByJob(t *testing.T, got []Match, want map[string]Match) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for _, m := range got {
		if w, ok := want[m.Job]; !ok || w != m {
			t.Errorf("job %q: got %+v, want %+v", m.Job, m, w)
		}
	}
}

// Spec 4.3, the images subject: the job's image as <registry>/<name>, tag and digest
// stripped, a Docker Hub short name expanded (an unresolved `zricethezav/gitleaks:$TAG`,
// registry unknown, is docker.io/zricethezav/gitleaks), and the image argument of a
// container-run line. The crane mirror line runs crane, not gitleaks, so it never matches
// on images; its text still contains gitleaks, which the user's `*gitleaks*` command
// pattern matches by design (the line is matched whole).
func TestRecognize_Spec43_Images(t *testing.T) {
	decls := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "gitleaks", Images: []string{"*gitleaks*"}, Commands: []string{"*gitleaks*"}})
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "var-tag", Image: &ir.Image{Registry: "unknown", Name: "zricethezav/gitleaks", Tag: "$TAG", Unresolved: true}, Scripts: []string{"detect"}},
		job("ghcr", "ghcr.io/gitleaks/gitleaks:v8", "detect"),
		job("alpine", "alpine:3", "make test"),
		job("docker-run", "docker:27", `docker run --rm -v "$PWD:/pwd" --entrypoint gitleaks zricethezav/gitleaks:v8 detect`),
		job("crane", "docker:27", "docker run --rm gcr.io/go-containerregistry/crane copy zricethezav/gitleaks:v8 x"),
	}}
	assertMatchesByJob(t, Recognize(pipe, "", decls), map[string]Match{
		"var-tag":    {"secret_detection", "var-tag", "gitleaks", EvidenceImages},
		"ghcr":       {"secret_detection", "ghcr", "gitleaks", EvidenceImages},
		"docker-run": {"secret_detection", "docker-run", "gitleaks", EvidenceImages},
		"crane":      {"secret_detection", "crane", "gitleaks", EvidenceCommands},
	})

	// The subject is exactly <registry>/<name>: an anchored pattern names it whole.
	exact := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "gitleaks", Images: []string{"docker.io/zricethezav/gitleaks"}})
	assertMatchesByJob(t, Recognize(pipe, "", exact), map[string]Match{
		"var-tag":    {"secret_detection", "var-tag", "gitleaks", EvidenceImages},
		"docker-run": {"secret_detection", "docker-run", "gitleaks", EvidenceImages},
	})
}

// Spec 4.3, the images subject on the built-in list: Docker Hub and GHCR names, a digest, a
// container-run line under podman and inside `sh -c`.
func TestRecognize_Spec43_Images_Builtin(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("by-image", "zricethezav/gitleaks:v8.18.0", "detect"),
		job("by-image-digest", "ghcr.io/gitleaks/gitleaks@sha256:abc", "detect"),
		job("trufflehog-ghcr", "ghcr.io/trufflesecurity/trufflehog:latest", "filesystem ."),
		job("podman", "quay.io/podman/stable", "podman run ghcr.io/betterleaks/betterleaks:v1 dir ."),
		job("gitlab", "registry.gitlab.com/security-products/secrets:6", "/analyzer run"),
		job("docker-alpine", "docker:27", "docker run alpine:3 echo"),
	}}
	assertMatchesByJob(t, Recognize(pipe, "", builtin(t)), map[string]Match{
		"by-image":        {"secret_detection", "by-image", "gitleaks", EvidenceImages},
		"by-image-digest": {"secret_detection", "by-image-digest", "gitleaks", EvidenceImages},
		"trufflehog-ghcr": {"secret_detection", "trufflehog-ghcr", "trufflehog", EvidenceImages},
		"podman":          {"secret_detection", "podman", "betterleaks", EvidenceImages},
		"gitlab":          {"secret_detection", "gitlab", "gitlab-secret-detection", EvidenceImages},
	})
}

// Spec 4.3, the gitlab_include_template and gitlab_include_component subjects: the job's
// include origin resolved against the pipeline's includes; a template's subject is its path
// as written, a component's is host/path/name without the version. Each pattern list sees
// only its own kind: a template path is never a component subject and vice versa, and a
// local include or an unknown origin is neither.
func TestRecognize_Spec43_IncludeTemplateAndComponent(t *testing.T) {
	const (
		tpl     = "Jobs/Secret-Detection.gitlab-ci.yml"
		comp    = "gitlab.com/components/secret-detection/secret-detection"
		tplLike = "ci/secret-detection/x.yml"
	)
	pipe := &ir.NormalizedPipeline{
		Jobs: []ir.Job{
			{Name: "tpl-job", Scripts: []string{"/analyzer run"}, OriginInclude: tpl},
			{Name: "comp-job", Scripts: []string{"/analyzer run"}, OriginInclude: comp},
			{Name: "plumber-tpl", Scripts: []string{"/analyzer run"}, OriginInclude: "Jobs/Secret-Detection.v2"},
			{Name: "tpl-shaped-like-comp", Scripts: []string{"run"}, OriginInclude: tplLike},
			{Name: "local", Scripts: []string{"run"}, OriginInclude: "Jobs/Secret-Detection.local.yml"},
			{Name: "unknown-origin", Scripts: []string{"run"}, OriginInclude: "Jobs/Secret-Detection.absent.yml"},
			{Name: "own", Scripts: []string{"run"}},
		},
		Includes: []ir.Include{
			{Kind: "template", Source: tpl, TemplatePath: tpl},
			{Kind: "component", Source: comp, Path: comp, ComponentName: "secret-detection"},
			{Kind: "template", Path: "Jobs/Secret-Detection.v2"}, // a Plumber template: no Source, the identity is its Path
			{Kind: "template", Source: tplLike},
			{Kind: "local", Source: "Jobs/Secret-Detection.local.yml"},
		},
	}
	decls := compiled(t, "secret_detection",
		capdecl.Recognizer{Tool: "tpl", GitlabIncludeTemplate: []string{"Jobs/Secret-Detection*"}},
		capdecl.Recognizer{Tool: "comp", GitlabIncludeComponent: []string{"*/secret-detection/*"}},
	)
	assertMatchesByJob(t, Recognize(pipe, "", decls), map[string]Match{
		"tpl-job":     {"secret_detection", "tpl-job", "tpl", EvidenceGitlabIncludeTemplate},
		"comp-job":    {"secret_detection", "comp-job", "comp", EvidenceGitlabIncludeComponent},
		"plumber-tpl": {"secret_detection", "plumber-tpl", "tpl", EvidenceGitlabIncludeTemplate},
	})

	// The kinds never cross: a template pattern that would match the component's text, and a
	// component pattern that would match the template's text, match nothing.
	crossed := compiled(t, "secret_detection",
		capdecl.Recognizer{Tool: "tpl", GitlabIncludeTemplate: []string{"gitlab.com/*"}},
		capdecl.Recognizer{Tool: "comp", GitlabIncludeComponent: []string{"Jobs/*", "*/secret-detection/*"}},
	)
	assertMatchesByJob(t, Recognize(&ir.NormalizedPipeline{Jobs: pipe.Jobs[:2], Includes: pipe.Includes}, "", crossed), map[string]Match{
		"comp-job": {"secret_detection", "comp-job", "comp", EvidenceGitlabIncludeComponent},
	})

	// The built-in list names GitLab's own template and component.
	assertMatchesByJob(t, Recognize(&ir.NormalizedPipeline{Jobs: pipe.Jobs[:2], Includes: pipe.Includes}, "", builtin(t)), map[string]Match{
		"tpl-job":  {"secret_detection", "tpl-job", "gitlab-secret-detection", EvidenceGitlabIncludeTemplate},
		"comp-job": {"secret_detection", "comp-job", "gitlab-secret-detection", EvidenceGitlabIncludeComponent},
	})
}

// Spec 4.3 / docs/PBOM.md: the gitlab_include_component subject never carries the version,
// even when a job's OriginInclude (or the matching ir.Include identity) does. A production
// component job's OriginInclude is already version-free (the collector strips it before
// building both the include's Source and the job's OriginInclude, gitlab/collect_pipeline_
// origin.go), but the matcher stays robust to either shape: a pattern naming the bare
// host/path/name matches whether or not the identity carries "@<version>", and a pattern
// naming the version matches nothing, because the subject the recognizer sees never carries
// it.
func TestRecognize_Spec43_IncludeComponentVersionNeverInSubject(t *testing.T) {
	const bare = "gitlab.com/acme/ci/secret-detection"
	versioned := bare + "@1.0.0"
	pipe := &ir.NormalizedPipeline{
		Jobs: []ir.Job{
			{Name: "comp-job", Scripts: []string{"run"}, OriginInclude: versioned},
		},
		Includes: []ir.Include{
			{Kind: "component", Source: bare, Path: bare, ComponentName: "secret-detection"},
		},
	}
	for _, pattern := range []string{bare, "*/acme/ci/*"} {
		decls := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "comp", GitlabIncludeComponent: []string{pattern}})
		assertMatchesByJob(t, Recognize(pipe, "", decls), map[string]Match{
			"comp-job": {"secret_detection", "comp-job", "comp", EvidenceGitlabIncludeComponent},
		})
	}
	for _, pattern := range []string{"*@1.0.0", "*@~latest"} {
		decls := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "comp", GitlabIncludeComponent: []string{pattern}})
		if got := Recognize(pipe, "", decls); len(got) != 0 {
			t.Fatalf("pattern %q: got %+v, want nothing: the version is never in the subject", pattern, got)
		}
	}
}

// Spec 4.3 / docs/PBOM.md: the same, with the version on the other side, the identity map
// (pipe.Includes) holding the versioned form and the job's OriginInclude holding the bare
// form. The lookup tolerates either side carrying the version.
func TestRecognize_Spec43_IncludeComponentVersionEitherSide(t *testing.T) {
	const bare = "gitlab.com/acme/ci/secret-detection"
	versioned := bare + "@1.0.0"
	pipe := &ir.NormalizedPipeline{
		Jobs: []ir.Job{
			{Name: "comp-job", Scripts: []string{"run"}, OriginInclude: bare},
		},
		Includes: []ir.Include{
			{Kind: "component", Source: versioned, Path: versioned, ComponentName: "secret-detection"},
		},
	}
	decls := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "comp", GitlabIncludeComponent: []string{bare}})
	assertMatchesByJob(t, Recognize(pipe, "", decls), map[string]Match{
		"comp-job": {"secret_detection", "comp-job", "comp", EvidenceGitlabIncludeComponent},
	})
}

// Spec 4.3, the gitlab_include_project subject: the project path of the `include: project:`
// entry that defines the job, as written, without the ref and without the file. The file
// path and the ref are never this subject, a template whose text looks like a project is not
// a project subject, and the built-in list declares no project pattern.
func TestRecognize_Spec43_IncludeProject(t *testing.T) {
	const (
		file    = "templates/secrets.yml"
		project = "security/ci-templates"
	)
	pipe := &ir.NormalizedPipeline{
		Jobs: []ir.Job{
			{Name: "proj-job", Scripts: []string{"run"}, OriginInclude: file},
			{Name: "tpl-job", Scripts: []string{"run"}, OriginInclude: project},
			{Name: "own", Scripts: []string{"run"}},
		},
		Includes: []ir.Include{
			{Kind: "project", Source: file, Path: file, Ref: "v2", Project: project},
			{Kind: "template", Source: project},
		},
	}
	for _, pattern := range []string{"security/ci-templates", "*/ci-templates"} {
		decls := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "corp", GitlabIncludeProject: []string{pattern}})
		assertMatchesByJob(t, Recognize(pipe, "", decls), map[string]Match{
			"proj-job": {"secret_detection", "proj-job", "corp", EvidenceGitlabIncludeProject},
		})
	}
	for _, pattern := range []string{"*secrets.yml*", "*v2*", "*@*"} {
		decls := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "corp", GitlabIncludeProject: []string{pattern}})
		if got := Recognize(pipe, "", decls); len(got) != 0 {
			t.Fatalf("pattern %q: got %+v, want nothing: the file and the ref are never the project subject", pattern, got)
		}
	}
	// The kinds never cross: a project pattern never reaches a component or template
	// subject, and a component pattern never reaches the project.
	crossed := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "comp", GitlabIncludeComponent: []string{"*"}, GitlabIncludeTemplate: []string{"templates/*"}})
	if got := Recognize(&ir.NormalizedPipeline{Jobs: pipe.Jobs[:1], Includes: pipe.Includes}, "", crossed); len(got) != 0 {
		t.Fatalf("got %+v, want nothing: a project include is neither a template nor a component subject", got)
	}
	// The built-in list declares no project pattern: a project-defined job is not recognized.
	if got := Recognize(pipe, "", builtin(t)); len(got) != 0 {
		t.Fatalf("got %+v, want nothing from the built-in list", got)
	}
	for _, r := range Builtin()[0].Recognizers {
		if len(r.GitlabIncludeProject) != 0 {
			t.Fatalf("the built-in recognizer %q declares a project pattern", r.Tool)
		}
	}
}

// Spec 4.3: the compiled fields follow the precedence order, gitlab_include_component before
// gitlab_include_project before gitlab_report_types.
func TestCompile_Spec43_FieldOrder(t *testing.T) {
	c := compiled(t, "x", capdecl.Recognizer{Commands: []string{"*"}})
	var names []string
	for _, f := range c[0].Recognizers[0].Fields {
		names = append(names, f.Name)
	}
	want := []string{EvidenceImages, EvidenceGitlabIncludeTemplate, EvidenceGitlabIncludeComponent, EvidenceGitlabIncludeProject, EvidenceGitlabReportTypes, EvidenceCommands, EvidenceWrapperScript}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("fields = %v, want %v", names, want)
	}
}

// Spec 4.3, the gitlab_report_types subject: each key of the job's artifacts:reports.
func TestRecognize_Spec43_ReportTypes(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "secrets", Image: imageOf("alpine:3"), Scripts: []string{"./run-scanner"}, ReportTypes: []string{"junit", "secret_detection"}},
		{Name: "sast", Image: imageOf("alpine:3"), Scripts: []string{"./run-scanner"}, ReportTypes: []string{"sast"}},
	}}
	decls := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "gl", GitlabReportTypes: []string{"secret_detection"}})
	assertMatchesByJob(t, Recognize(pipe, "", decls), map[string]Match{
		"secrets": {"secret_detection", "secrets", "gl", EvidenceGitlabReportTypes},
	})
	assertMatchesByJob(t, Recognize(pipe, "", builtin(t)), map[string]Match{
		"secrets": {"secret_detection", "secrets", "gitlab-secret-detection", EvidenceGitlabReportTypes},
	})
}

// Spec 4.3, the commands subject: each script line, a `- |` entry split on newlines, an
// unquoted `#` comment removed, trimmed, and matched whole: prefixes, launchers, `python
// -m` and `sh -c` need no special handling since the line glob sees the tool's name in the
// text. A commented-out call is not a command; a `#` inside quotes is not a comment.
// ggshield's IaC subcommand is not secret detection.
func TestRecognize_Spec43_Commands_Builtin(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("sudo", "alpine", "sudo -u ci gitleaks detect"),
		job("npx", "node:22", "npx @gitleaks/gitleaks detect"),
		job("module", "python:3.12", "python -m detect_secrets scan"),
		job("hook", "python:3.12", "detect-secrets-hook --baseline x"),
		job("timeout", "alpine", "timeout 300 trufflehog filesystem ."),
		job("block", "alpine", "echo start\ngitleaks detect --no-git\n"),
		job("shc", "alpine", `sh -c "gitleaks detect"`),
		job("pipe", "alpine", "cat x | detect-secrets scan"),
		job("env", "alpine", "env GITLEAKS_CONFIG=.gl.toml gitleaks detect"),
		job("before-after", "alpine", "make build", "betterleaks dir ."),
		job("comment", "alpine", "# gitleaks detect"),
		job("trailing-comment", "alpine", "echo done # gitleaks"),
		job("quoted-hash", "alpine", `echo "a # b" && gitleaks detect`),
		job("ggshield-iac", "alpine", "ggshield iac scan ci"),
		job("ggshield-secret", "alpine", "ggshield secret scan ci"),
		job("ggshield-legacy", "alpine", "ggshield scan ci"),
		job("none", "alpine", "make test"),
	}}
	assertMatchesByJob(t, Recognize(pipe, "", builtin(t)), map[string]Match{
		"sudo":            {"secret_detection", "sudo", "gitleaks", EvidenceCommands},
		"npx":             {"secret_detection", "npx", "gitleaks", EvidenceCommands},
		"module":          {"secret_detection", "module", "detect-secrets", EvidenceCommands},
		"hook":            {"secret_detection", "hook", "detect-secrets", EvidenceCommands},
		"timeout":         {"secret_detection", "timeout", "trufflehog", EvidenceCommands},
		"block":           {"secret_detection", "block", "gitleaks", EvidenceCommands},
		"shc":             {"secret_detection", "shc", "gitleaks", EvidenceCommands},
		"pipe":            {"secret_detection", "pipe", "detect-secrets", EvidenceCommands},
		"env":             {"secret_detection", "env", "gitleaks", EvidenceCommands},
		"before-after":    {"secret_detection", "before-after", "betterleaks", EvidenceCommands},
		"quoted-hash":     {"secret_detection", "quoted-hash", "gitleaks", EvidenceCommands},
		"ggshield-secret": {"secret_detection", "ggshield-secret", "ggshield", EvidenceCommands},
		"ggshield-legacy": {"secret_detection", "ggshield-legacy", "ggshield", EvidenceCommands},
	})
}

// Spec 4.3, the wrapper_script subject: a script line running a relative .sh/.bash file
// under the repository; the file's lines (comments removed) are matched against the
// recognizer's commands. The job's own line `./ci/scan.sh` is tried as a command first and
// `*trufflehog*` does not match it; the file's container-run line does, as a line.
func TestRecognize_Spec43_WrapperScript(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "ci"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "ci", "scan.sh"), []byte("#!/bin/sh\n# gitleaks is not run here\ndocker run trufflesecurity/trufflehog:latest filesystem .\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "ci", "secrets.sh"), []byte("#!/bin/sh\ndetect-secrets scan\n"), 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("wrapper", "alpine:3.20", "./ci/scan.sh"),
		job("block-cd", "alpine:3.20", "set -e\ncd ci\n./secrets.sh\n"),
		job("bash", "alpine:3.20", "make prep && bash ci/secrets.sh --fast"),
	}}
	decls := compiled(t, "secret_detection", capdecl.Recognizer{Tool: "trufflehog", Commands: []string{"*trufflehog*"}})
	assertMatchesByJob(t, Recognize(pipe, root, decls), map[string]Match{
		"wrapper": {"secret_detection", "wrapper", "trufflehog", EvidenceWrapperScript},
	})
	assertMatchesByJob(t, Recognize(pipe, root, builtin(t)), map[string]Match{
		"wrapper":  {"secret_detection", "wrapper", "trufflehog", EvidenceWrapperScript},
		"block-cd": {"secret_detection", "block-cd", "detect-secrets", EvidenceWrapperScript},
		"bash":     {"secret_detection", "bash", "detect-secrets", EvidenceWrapperScript},
	})
	// An empty root (the checkout is not the analyzed project at its ref) turns the subject off.
	if got := Recognize(pipe, "", builtin(t)); len(got) != 0 {
		t.Fatalf("got %+v, want no wrapper evidence without a root", got)
	}
}

// Spec 4.3: the launcher's options are skipped before its script path (bash -x ci/scan.sh),
// so the wrapper rule still finds and reads it.
func TestRecognize_Spec43_WrapperScript_LauncherWithOptions(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "ci"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "ci", "scan.sh"), []byte("#!/bin/sh\ngitleaks detect\n"), 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("flagged", "alpine:3.20", "bash -x ci/scan.sh"),
	}}
	assertMatchesByJob(t, Recognize(pipe, root, builtin(t)), map[string]Match{
		"flagged": {"secret_detection", "flagged", "gitleaks", EvidenceWrapperScript},
	})
}

// Spec 4.3 and decision 5: an absent, escaping, unreadable or oversized wrapper script, or a
// script a wrapper itself calls (a second level), yields no evidence and never an error; a
// commented-out call is never read.
func TestRecognize_Spec43_WrapperScript_NeverFails(t *testing.T) {
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "big.sh"), append([]byte("gitleaks detect\n"), make([]byte, maxWrapperScriptBytes)...), 0o755))
	must(t, os.MkdirAll(filepath.Join(root, "dir.sh"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "level1.sh"), []byte("./level2.sh\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "level2.sh"), []byte("gitleaks detect\n"), 0o755))
	must(t, os.MkdirAll(filepath.Join(root, "ci"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "ci", "scan.sh"), []byte("gitleaks detect\n"), 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("missing", "alpine", "./scripts/absent.sh"),
		job("escape", "alpine", "sh ../../etc/passwd.sh"),
		job("oversized", "alpine", "./big.sh"),
		job("unreadable", "alpine", "./dir.sh"),
		job("nested", "alpine", "./level1.sh"),
		job("commented", "alpine", "# ./ci/scan.sh"),
		job("commented-after", "alpine", "echo hi # ./ci/scan.sh"),
	}}
	hook := capturedLog(t)
	if got := Recognize(pipe, root, builtin(t)); len(got) != 0 {
		t.Fatalf("got %+v, want no match: absent, escaping, unreadable, oversized, second-level and commented scripts yield no evidence", got)
	}
	assertDebugLinesNameJobAndPathOnly(t, hook, "gitleaks detect")
}

// capturedLog hooks the standard logger at debug level (the package logger hangs off it)
// and restores it afterwards.
func capturedLog(t *testing.T) *logrustest.Hook {
	t.Helper()
	std := logrus.StandardLogger()
	savedLevel, savedHooks := std.GetLevel(), std.Hooks
	std.SetLevel(logrus.DebugLevel)
	hook := logrustest.NewLocal(std)
	t.Cleanup(func() {
		std.ReplaceHooks(savedHooks)
		std.SetLevel(savedLevel)
	})
	return hook
}

// assertDebugLinesNameJobAndPathOnly checks the contract's logging rule on the wrapper read:
// at least one debug line was logged, every one carries the job and the script path, and
// none carries a byte of the script content (the message, the fields and the error alike).
func assertDebugLinesNameJobAndPathOnly(t *testing.T, hook *logrustest.Hook, content string) {
	t.Helper()
	n := 0
	for _, e := range hook.AllEntries() {
		if e.Level != logrus.DebugLevel || !strings.Contains(e.Message, "wrapper script") {
			continue
		}
		n++
		if e.Data["job"] == nil || e.Data["script"] == nil {
			t.Errorf("debug line %q fields %v: want the job and the script path", e.Message, e.Data)
		}
		line, err := e.String()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(line, content) {
			t.Errorf("debug line %q carries the script content %q", line, content)
		}
	}
	if n == 0 {
		t.Fatal("want at least one wrapper-script debug line")
	}
}

// Spec 4.3 and decision 5: a wrapper path inside the root that is a symlink to a file
// outside it is refused by ResolveWithinRepo (the resolved target is compared, not the
// path as written, unlike the `..` refusal of wrapperPaths): no read, no match, no error,
// and the debug line names the job and the path, never the target's content.
func TestRecognize_Spec43_WrapperScript_SymlinkOutsideTheRootIsNotRead(t *testing.T) {
	outside := t.TempDir()
	must(t, os.WriteFile(filepath.Join(outside, "scan.sh"), []byte("gitleaks detect --outside-content\n"), 0o755))
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "ci"), 0o755))
	if err := os.Symlink(filepath.Join(outside, "scan.sh"), filepath.Join(root, "ci", "scan.sh")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("wrapper", "alpine", "./ci/scan.sh")}}
	hook := capturedLog(t)
	if got := Recognize(pipe, root, builtin(t)); len(got) != 0 {
		t.Fatalf("got %+v, want no match: a symlink out of the root is never read", got)
	}
	assertDebugLinesNameJobAndPathOnly(t, hook, "outside-content")
	var refused bool
	for _, e := range hook.AllEntries() {
		if e.Message == "capability: wrapper script not under the repository, skipped" && e.Data["job"] == "wrapper" && e.Data["script"] == "ci/scan.sh" {
			refused = true
		}
	}
	if !refused {
		t.Fatal("want the ResolveWithinRepo refusal logged for job wrapper and script ci/scan.sh")
	}
}

// Spec 4.3: a wrapper script of exactly the 256 KiB cap is read.
func TestRecognize_Spec43_WrapperScript_ExactlyAtCapIsRead(t *testing.T) {
	root := t.TempDir()
	tail := []byte("\ngitleaks detect\n")
	data := make([]byte, maxWrapperScriptBytes)
	for i := range data {
		data[i] = '#'
	}
	copy(data[len(data)-len(tail):], tail)
	must(t, os.WriteFile(filepath.Join(root, "atcap.sh"), data, 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("atcap", "alpine", "./atcap.sh")}}
	got := Recognize(pipe, root, builtin(t))
	if len(got) != 1 || got[0] != (Match{"secret_detection", "atcap", "gitleaks", EvidenceWrapperScript}) {
		t.Fatalf("got %+v, want one gitleaks match by wrapper script: a script of exactly the cap is read", got)
	}
}

// Spec 4.3, precedence inside one recognizer: images, gitlab_include_template,
// gitlab_include_component, gitlab_include_project, gitlab_report_types, commands,
// wrapper_script; the first field that matches names the evidence.
func TestRecognize_Spec43_FieldPrecedence(t *testing.T) {
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "w.sh"), []byte("corp-scan\n"), 0o755))
	rec := capdecl.Recognizer{
		Tool:                   "t",
		Images:                 []string{"*corp-scan*"},
		GitlabIncludeTemplate:  []string{"Jobs/*"},
		GitlabIncludeComponent: []string{"*/comp/*"},
		GitlabIncludeProject:   []string{"g/proj"},
		GitlabReportTypes:      []string{"secret_detection"},
		Commands:               []string{"*corp-scan*"},
	}
	const tpl, comp, projFile = "Jobs/x.yml", "gitlab.com/g/comp/c", "ci/scan.yml"
	report := []string{"secret_detection"}
	pipe := &ir.NormalizedPipeline{
		Jobs: []ir.Job{
			{Name: "a-image", Image: imageOf("corp/corp-scan:1"), OriginInclude: tpl, ReportTypes: report, Scripts: []string{"corp-scan"}},
			{Name: "b-template", Image: imageOf("alpine"), OriginInclude: tpl, ReportTypes: report, Scripts: []string{"corp-scan"}},
			{Name: "c-component", Image: imageOf("alpine"), OriginInclude: comp, ReportTypes: report, Scripts: []string{"corp-scan"}},
			{Name: "c2-project", Image: imageOf("alpine"), OriginInclude: projFile, ReportTypes: report, Scripts: []string{"corp-scan"}},
			{Name: "d-report", Image: imageOf("alpine"), ReportTypes: report, Scripts: []string{"corp-scan"}},
			{Name: "e-commands", Image: imageOf("alpine"), Scripts: []string{"corp-scan", "./w.sh"}},
			{Name: "f-wrapper", Image: imageOf("alpine"), Scripts: []string{"./w.sh"}},
		},
		Includes: []ir.Include{{Kind: "template", Source: tpl}, {Kind: "component", Source: comp}, {Kind: "project", Source: projFile, Project: "g/proj"}},
	}
	assertMatchesByJob(t, Recognize(pipe, root, compiled(t, "secret_detection", rec)), map[string]Match{
		"a-image":     {"secret_detection", "a-image", "t", EvidenceImages},
		"b-template":  {"secret_detection", "b-template", "t", EvidenceGitlabIncludeTemplate},
		"c-component": {"secret_detection", "c-component", "t", EvidenceGitlabIncludeComponent},
		"c2-project":  {"secret_detection", "c2-project", "t", EvidenceGitlabIncludeProject},
		"d-report":    {"secret_detection", "d-report", "t", EvidenceGitlabReportTypes},
		"e-commands":  {"secret_detection", "e-commands", "t", EvidenceCommands},
		"f-wrapper":   {"secret_detection", "f-wrapper", "t", EvidenceWrapperScript},
	})
}

// Spec 4.3: a job whose image and script both say gitleaks records images.
func TestRecognize_Spec43_ImageBeforeCommandInOneRecognizer(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("both", "zricethezav/gitleaks:v8", "gitleaks detect")}}
	got := Recognize(pipe, "", builtin(t))
	if len(got) != 1 || got[0] != (Match{"secret_detection", "both", "gitleaks", EvidenceImages}) {
		t.Fatalf("got %+v, want one gitleaks match by images", got)
	}
}

// Spec 4.3: recognizers are tried in list order and the first that matches names the tool,
// whatever field it matched on: the order of the list outranks the field precedence, which
// only applies inside one recognizer.
func TestRecognize_Spec43_RecognizerOrder(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("job", "corp/b-image:1", "run-scan --all")}}
	same := compiled(t, "secret_detection",
		capdecl.Recognizer{Tool: "first", Commands: []string{"*scan*"}},
		capdecl.Recognizer{Tool: "second", Commands: []string{"*scan*"}},
	)
	if got := Recognize(pipe, "", same); len(got) != 1 || got[0] != (Match{"secret_detection", "job", "first", EvidenceCommands}) {
		t.Fatalf("got %+v, want one match naming the first recognizer", got)
	}
	listBeatsField := compiled(t, "secret_detection",
		capdecl.Recognizer{Tool: "a", Commands: []string{"*run-scan*"}},
		capdecl.Recognizer{Tool: "b", Images: []string{"*b-image*"}},
	)
	if got := Recognize(pipe, "", listBeatsField); len(got) != 1 || got[0] != (Match{"secret_detection", "job", "a", EvidenceCommands}) {
		t.Fatalf("got %+v, want one match naming a by commands: the earlier recognizer wins", got)
	}
	// Within a recognizer, patterns are tried in their order: the first that matches names the
	// tool when none is declared.
	twoPatterns := compiled(t, "secret_detection", capdecl.Recognizer{Commands: []string{"*--all*", "*run-scan*"}})
	if got := Recognize(pipe, "", twoPatterns); len(got) != 1 || got[0].Tool != "*--all*" {
		t.Fatalf("got %+v, want the first matching pattern as the tool", got)
	}
}

// Spec 4.3: one entry per (job, capability); a job matching two capabilities yields two
// entries, sorted by job then kind.
func TestRecognize_Spec43_TwoCapabilitiesOneJob(t *testing.T) {
	decls := Compile(append(Builtin(), Declaration{Name: "sast", Recognizers: []capdecl.Recognizer{{Tool: "semgrep", Commands: []string{"*semgrep*"}}}}), nil)
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("zeta", "alpine", "gitleaks detect && trufflehog git file://. && semgrep ci"),
		job("alpha", "alpine", "trufflehog git file://."),
	}}
	got := Recognize(pipe, "", decls)
	want := []Match{
		{"secret_detection", "alpha", "trufflehog", EvidenceCommands},
		{"sast", "zeta", "semgrep", EvidenceCommands},
		{"secret_detection", "zeta", "gitleaks", EvidenceCommands},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("match %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Spec 4.3: `tool` on the edge is the recognizer's tool when declared, else the pattern that
// matched.
func TestRecognize_Spec43_ToolFallsBackToThePattern(t *testing.T) {
	decls := compiled(t, "secret_detection", capdecl.Recognizer{Commands: []string{"*corp-scan secrets*"}})
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("secrets", "alpine", "corp-scan secrets --all"),
		job("deps", "alpine", "corp-scan deps"),
	}}
	assertMatchesByJob(t, Recognize(pipe, "", decls), map[string]Match{
		"secrets": {"secret_detection", "secrets", "*corp-scan secrets*", EvidenceCommands},
	})
}

// Spec 4.3: hidden jobs (a dot-prefixed name) never run on their own and are skipped.
func TestRecognize_Spec43_HiddenJobsAreSkipped(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job(".secret-analyzer", "alpine", "gitleaks detect"),
		job("secret_detection", "alpine", "gitleaks detect"),
	}}
	got := Recognize(pipe, "", builtin(t))
	if len(got) != 1 || got[0].Job != "secret_detection" {
		t.Fatalf("got %+v, want exactly one entry for secret_detection: a hidden job carries no capability", got)
	}
}

func TestRecognize_NilAndEmpty(t *testing.T) {
	if got := Recognize(nil, "", builtin(t)); got != nil {
		t.Fatalf("nil pipeline: got %+v", got)
	}
	if got := Recognize(&ir.NormalizedPipeline{Jobs: []ir.Job{job("a", "zricethezav/gitleaks", "x")}}, "", nil); got != nil {
		t.Fatalf("no capability: got %+v", got)
	}
}

// recognizeWithin fails t unless Recognize, without a repository root, returns within 2 s.
func recognizeWithin(t *testing.T, pipe *ir.NormalizedPipeline, decls []Compiled) []Match {
	t.Helper()
	return recognizeWithinRoot(t, pipe, "", decls)
}

// recognizeWithinRoot fails t unless Recognize under root (the wrapper_script subject on
// when root is set) returns within 2 s.
func recognizeWithinRoot(t *testing.T, pipe *ir.NormalizedPipeline, root string, decls []Compiled) []Match {
	t.Helper()
	var got []Match
	done := make(chan struct{})
	go func() { got = Recognize(pipe, root, decls); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Recognize on a 256 KiB script entry took over 2 s")
	}
	return got
}

// Spec 4.3: script lines come from any analyzed project's CI config, so the subjects stay
// linear: a 256 KiB line of repeated `sh -c ` and a 256 KiB `docker run` line are matched
// well within 2 s.
func TestRecognize_Spec43_LongLinesAreBounded(t *testing.T) {
	shc := strings.Repeat("sh -c ", (256<<10)/len("sh -c ")) + "gitleaks detect"
	got := recognizeWithin(t, &ir.NormalizedPipeline{Jobs: []ir.Job{job("shc", "alpine", shc)}}, builtin(t))
	if len(got) != 1 || got[0] != (Match{"secret_detection", "shc", "gitleaks", EvidenceCommands}) {
		t.Fatalf("got %+v, want one gitleaks match by commands", got)
	}
	run := "docker run " + strings.Repeat("-v a:b ", (256<<10)/len("-v a:b ")) + "trufflesecurity/trufflehog:latest"
	got = recognizeWithin(t, &ir.NormalizedPipeline{Jobs: []ir.Job{job("long", "docker:27", run)}}, builtin(t))
	if len(got) != 1 || got[0] != (Match{"secret_detection", "long", "trufflehog", EvidenceImages}) {
		t.Fatalf("got %+v, want one trufflehog match by images", got)
	}
}

// Spec 4.3: a pattern is the user's and a subject any developer's script line, so a user
// pattern with several literal runs never makes matching super-linear: each of these pairs
// is decided well within 2 s through Recognize.
func TestRecognize_Spec43_UserPatternsAreBounded(t *testing.T) {
	const size = 256 << 10
	for _, c := range []struct{ pattern, line string }{
		{"*b*a*a*", strings.Repeat("a", size) + "b"},
		{"*ggshield*secret*", strings.Repeat("ggshield ", size/len("ggshield "))},
		{"*a*a*a*a*a*a*a*a*", strings.Repeat("b", size)},
	} {
		decls := compiled(t, "custom", capdecl.Recognizer{Tool: "t", Commands: []string{c.pattern}})
		if got := recognizeWithin(t, &ir.NormalizedPipeline{Jobs: []ir.Job{job("j", "alpine", c.line)}}, decls); len(got) != 0 {
			t.Fatalf("%q: got %+v, want no match", c.pattern, got)
		}
	}
}

// Spec 4.3: the wrapper rule follows a relative `cd` chain, but only a short one (16
// segments, 1024 bytes of directory): a 256 KiB chain of `cd a&&` before `./x.sh`, on one
// line or as a `- |` block, is decided well within 2 s and yields no wrapper evidence.
func TestRecognize_Spec43_LongCdChainIsBounded(t *testing.T) {
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "x.sh"), []byte("gitleaks detect\n"), 0o755))
	n := (256 << 10) / len("cd a&&")
	for name, entry := range map[string]string{
		"one line": strings.Repeat("cd a&&", n) + "./x.sh",
		"a block":  strings.Repeat("cd a\n", n) + "./x.sh\n",
	} {
		pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("chain", "alpine", entry)}}
		if got := recognizeWithinRoot(t, pipe, root, builtin(t)); len(got) != 0 {
			t.Fatalf("%s: got %+v, want no wrapper evidence past the cd cap", name, got)
		}
	}
}

// Spec 4.3: every wrapper call of a script entry is a wrapper subject, not only the first:
// a `- |` block that runs a setup script then a scan script is recognized by the scan
// script's lines.
func TestRecognize_Spec43_WrapperScript_EveryLineOfAnEntry(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "ci"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "ci", "setup.sh"), []byte("apk add git\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "ci", "scan.sh"), []byte("gitleaks detect --source .\n"), 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("block", "alpine", "./ci/setup.sh\n./ci/scan.sh\n")}}
	assertMatchesByJob(t, Recognize(pipe, root, builtin(t)), map[string]Match{
		"block": {"secret_detection", "block", "gitleaks", EvidenceWrapperScript},
	})
}
