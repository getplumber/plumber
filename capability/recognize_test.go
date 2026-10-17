package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if j := indexAny(name, ":@"); j >= 0 {
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

func indexAny(s, chars string) int { return strings.IndexAny(s, chars) }

func TestRecognize_EvidenceSources(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "scripts"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "scripts", "scan.sh"), []byte("#!/bin/sh\nset -e\ntrufflehog git file://.\n"), 0o755))
	pipe := &ir.NormalizedPipeline{
		Jobs: []ir.Job{
			job("by-image", "zricethezav/gitleaks:v8.18.0", "gitleaks detect"),
			job("by-image-digest", "ghcr.io/gitleaks/gitleaks@sha256:abc", "gitleaks detect"),
			job("by-command", "alpine:3.20", "apk add gitleaks", "gitleaks detect --no-git"),
			job("by-pipe", "alpine:3.20", "cat x | detect-secrets scan"),
			job("by-wrapper", "alpine:3.20", "./scripts/scan.sh"),
			{Name: "by-report", Image: imageOf("alpine:3.20"), Scripts: []string{"./run-scanner"}, ReportTypes: []string{"secret_detection"}},
			job("by-include", "", "noop"),
			job("none", "alpine:3.20", "make test"),
		},
		Includes: []ir.Include{{Kind: "template", Source: "Security/Secret-Detection.gitlab-ci.yml", TemplatePath: "Security/Secret-Detection.gitlab-ci.yml"}},
	}
	pipe.Jobs[6].OriginInclude = "Security/Secret-Detection.gitlab-ci.yml" // the job the template defines
	got := Recognize(pipe, root, Defaults())
	want := map[string]Match{
		"by-image":        {KindSecretDetection, "by-image", "gitleaks", EvidenceImage},
		"by-image-digest": {KindSecretDetection, "by-image-digest", "gitleaks", EvidenceImage},
		"by-command":      {KindSecretDetection, "by-command", "gitleaks", EvidenceCommand},
		"by-pipe":         {KindSecretDetection, "by-pipe", "detect-secrets", EvidenceCommand},
		"by-wrapper":      {KindSecretDetection, "by-wrapper", "trufflehog", EvidenceWrapperScript},
		"by-report":       {KindSecretDetection, "by-report", "gitlab-secret-detection", EvidenceReport},
		"by-include":      {KindSecretDetection, "by-include", "gitlab-secret-detection", EvidenceInclude},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d matches %+v, want %d", len(got), got, len(want))
	}
	for _, m := range got {
		if w, ok := want[m.Job]; !ok || w != m {
			t.Errorf("job %q: got %+v, want %+v", m.Job, m, w)
		}
	}
}

// Spec section 4.3 rule 4 and section 4.4: a `- |` script entry reaches the collector as one
// string with newlines; the tool or the wrapper script on its second line is still evidence.
func TestRecognize_MultiLineScriptEntry(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "scripts"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "scripts", "scan.sh"), []byte("#!/bin/sh\ndetect-secrets scan\n"), 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("block-command", "alpine:3.20", "echo start\ngitleaks detect --no-git\n"),
		job("block-wrapper", "alpine:3.20", "set -e\n./scripts/scan.sh\n"),
	}}
	got := Recognize(pipe, root, Defaults())
	want := []Match{
		{KindSecretDetection, "block-command", "gitleaks", EvidenceCommand},
		{KindSecretDetection, "block-wrapper", "detect-secrets", EvidenceWrapperScript},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// Spec section 7 (the include rule covers a template and a component): a job defined by a
// component whose name a recognizer's Includes lists matches by include. The collector gives
// a component include its include path as Source and the job that path as OriginInclude.
func TestRecognize_ComponentInclude(t *testing.T) {
	const src = "gitlab.com/components/secret-detection/secret-detection@1.2.0"
	pipe := &ir.NormalizedPipeline{
		Jobs:     []ir.Job{{Name: "secret_detection", Scripts: []string{"/analyzer run"}, OriginInclude: src}},
		Includes: []ir.Include{{Kind: "component", Source: src, Path: src, ComponentName: "secret-detection"}},
	}
	got := Recognize(pipe, t.TempDir(), Defaults())
	if len(got) != 1 || got[0] != (Match{KindSecretDetection, "secret_detection", "gitlab-secret-detection", EvidenceInclude}) {
		t.Fatalf("got %+v, want one gitlab-secret-detection match by include for the component's job", got)
	}
}

// L1 fix (bot review round 6): a merged list (Merge(Defaults(), served)) still recognizes a
// job by report type. This guards the defaults' ReportTypes surviving Merge, not just the
// rule itself (TestRecognize_EvidenceSources already covers the rule on an unmerged list).
func TestRecognize_MergedList_ReportEvidence(t *testing.T) {
	served := []Recognizer{{Capability: KindSecretDetection, Tool: "in-house-scanner", Images: []string{"registry.corp/sec/scanner"}, Commands: []string{"scan-secrets"}}}
	recs := Merge(Defaults(), served)
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "by-report", Image: imageOf("alpine:3.20"), Scripts: []string{"./run-scanner"}, ReportTypes: []string{"secret_detection"}},
	}}
	got := Recognize(pipe, t.TempDir(), recs)
	if len(got) != 1 || got[0] != (Match{KindSecretDetection, "by-report", "gitlab-secret-detection", EvidenceReport}) {
		t.Fatalf("got %+v, want one gitlab-secret-detection match by report type on the merged list", got)
	}
}

func TestRecognize_EvidencePriority_ImageBeatsCommand(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("both", "trufflesecurity/trufflehog:latest", "gitleaks detect")}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	if len(got) != 1 || got[0].Tool != "trufflehog" || got[0].Evidence != EvidenceImage {
		t.Fatalf("got %+v, want one trufflehog match by image (image is checked before commands)", got)
	}
}

// Spec section 4.3 (the rules apply in order image, include, report, command, wrapper): a
// job carrying both a secret_detection report and a tool command matches by report, the
// earlier rule, and only once.
func TestRecognize_EvidencePriority_ReportBeatsCommand(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "both", Image: imageOf("alpine:3.20"), Scripts: []string{"trufflehog filesystem ."}, ReportTypes: []string{"secret_detection"}},
	}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	if len(got) != 1 || got[0] != (Match{KindSecretDetection, "both", "gitlab-secret-detection", EvidenceReport}) {
		t.Fatalf("got %+v, want one gitlab-secret-detection match by report (report is checked before commands)", got)
	}
}

// Spec section 4.3 (rule order): a job the Secret-Detection template defines, that also
// declares the report and runs a tool command, matches by include, the earliest of the three.
func TestRecognize_EvidencePriority_IncludeBeatsReportAndCommand(t *testing.T) {
	const tpl = "Security/Secret-Detection.gitlab-ci.yml"
	pipe := &ir.NormalizedPipeline{
		Jobs: []ir.Job{{
			Name: "secret_detection", Scripts: []string{"gitleaks detect"},
			ReportTypes: []string{"secret_detection"}, OriginInclude: tpl,
		}},
		Includes: []ir.Include{{Kind: "template", Source: tpl, TemplatePath: tpl}},
	}
	got := Recognize(pipe, t.TempDir(), Defaults())
	if len(got) != 1 || got[0] != (Match{KindSecretDetection, "secret_detection", "gitlab-secret-detection", EvidenceInclude}) {
		t.Fatalf("got %+v, want one gitlab-secret-detection match by include (include is checked before report and commands)", got)
	}
}

func TestRecognize_WrapperScript_NeverFails(t *testing.T) {
	root := t.TempDir()
	big := make([]byte, maxWrapperScriptBytes+1)
	must(t, os.WriteFile(filepath.Join(root, "big.sh"), big, 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("missing", "alpine", "./scripts/absent.sh"),
		job("escape", "alpine", "sh ../../etc/passwd.sh"),
		job("oversized", "alpine", "./big.sh"),
		job("nested", "alpine", "./level1.sh"),
	}}
	must(t, os.WriteFile(filepath.Join(root, "level1.sh"), []byte("./level2.sh\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "level2.sh"), []byte("gitleaks detect\n"), 0o755))
	if got := Recognize(pipe, root, Defaults()); len(got) != 0 {
		t.Fatalf("got %+v, want no match: absent, escaping, oversized and second-level scripts yield no evidence", got)
	}
}

func TestRecognize_WrapperScript_ExactlyAtCapIsRead(t *testing.T) {
	root := t.TempDir()
	tail := []byte("\ngitleaks detect\n")
	data := make([]byte, maxWrapperScriptBytes)
	for i := range data {
		data[i] = '#'
	}
	copy(data[len(data)-len(tail):], tail)
	must(t, os.WriteFile(filepath.Join(root, "atcap.sh"), data, 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("atcap", "alpine", "./atcap.sh")}}
	got := Recognize(pipe, root, Defaults())
	if len(got) != 1 || got[0].Tool != "gitleaks" || got[0].Evidence != EvidenceWrapperScript {
		t.Fatalf("got %+v, want one gitleaks match by wrapper script: a script of exactly the cap is read", got)
	}
}

func TestRecognize_SortedByJobThenKind(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("zeta", "alpine", "gitleaks detect"),
		job("alpha", "alpine", "trufflehog git file://."),
	}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	if len(got) != 2 || got[0].Job != "alpha" || got[1].Job != "zeta" {
		t.Fatalf("got %+v, want alpha then zeta", got)
	}
}

func TestRecognize_ServedRecognizerAndOnePerJob(t *testing.T) {
	served := []Recognizer{{Capability: KindSecretDetection, Tool: "in-house", Commands: []string{"scan-secrets"}}}
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("custom", "alpine", "scan-secrets --all", "gitleaks detect")}}
	got := Recognize(pipe, t.TempDir(), Merge(Defaults(), served))
	if len(got) != 1 || got[0].Tool != "gitleaks" {
		t.Fatalf("got %+v, want one match naming gitleaks: the defaults come before the served list and one entry per job", got)
	}
}

func TestRecognize_HiddenJobsAreSkipped(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job(".secret-analyzer", "alpine", "gitleaks detect"),
		job("secret_detection", "alpine", "gitleaks detect"),
	}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	if len(got) != 1 || got[0].Job != "secret_detection" {
		t.Fatalf("got %+v, want exactly one entry for secret_detection: a hidden job never runs, so it carries no capability", got)
	}
}

func TestRecognize_NilAndEmpty(t *testing.T) {
	if got := Recognize(nil, "", Defaults()); got != nil {
		t.Fatalf("nil pipeline: got %+v", got)
	}
	if got := Recognize(&ir.NormalizedPipeline{Jobs: []ir.Job{job("a", "zricethezav/gitleaks", "x")}}, "", nil); got != nil {
		t.Fatalf("no recognizer: got %+v", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Spec section 4.3 rule 4, container-run form (bot review of PR #557, controller ruling): a
// job that runs a scanner image through `docker run`, `podman run` or `nerdctl run` names the
// tool by that image argument, canonicalized like the image rule (a Docker Hub short name is
// keyed under docker.io). The script line is the evidence, so it is `command`; the job image
// is untouched. An image no recognizer names, or a `docker` subcommand other than `run`,
// matches nothing.
func TestRecognize_ContainerRunImageIsCommandEvidence(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("docker-trufflehog", "docker:27", `docker run --rm -v "$PWD:/pwd" trufflesecurity/trufflehog:latest filesystem /pwd`),
		job("podman-gitleaks", "quay.io/podman/stable", "podman run ghcr.io/gitleaks/gitleaks:v8 detect"),
		job("nerdctl-unwrapped", "alpine", `sh -c "nerdctl run --rm zricethezav/gitleaks:v8.18.0 detect"`),
		job("docker-alpine", "docker:27", "docker run alpine:3 echo"),
		job("docker-build", "docker:27", "docker build -t trufflesecurity/trufflehog:latest ."),
		job("env-flag", "docker:27", "docker run -e IMAGE=trufflesecurity/trufflehog alpine:3 echo"),
	}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	want := []Match{
		{KindSecretDetection, "docker-trufflehog", "trufflehog", EvidenceCommand},
		{KindSecretDetection, "nerdctl-unwrapped", "gitleaks", EvidenceCommand},
		{KindSecretDetection, "podman-gitleaks", "gitleaks", EvidenceCommand},
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

// Spec section 4.3 rule 1 before rule 4: the container-run form belongs to the command rule,
// so a job whose own image already matches keeps evidence image.
func TestRecognize_ContainerRun_JobImageStillWins(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("both", "zricethezav/gitleaks:v8", "docker run trufflesecurity/trufflehog:latest filesystem .")}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	if len(got) != 1 || got[0] != (Match{KindSecretDetection, "both", "gitleaks", EvidenceImage}) {
		t.Fatalf("got %+v, want one gitleaks match by image", got)
	}
}

// Spec section 4.3 rule 4: script lines come from any analyzed project's CI config, so the
// container-run form stays linear: a 256 KiB `docker run` line is recognized well within 2 s.
func TestRecognize_ContainerRunLineIsBounded(t *testing.T) {
	line := "docker run " + strings.Repeat("-v a:b ", (256<<10)/len("-v a:b ")) + "trufflesecurity/trufflehog:latest"
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("long", "docker:27", line)}}
	var got []Match
	done := make(chan struct{})
	go func() { got = Recognize(pipe, "", Defaults()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Recognize on a 256 KiB `docker run` line took over 2 s")
	}
	if len(got) != 1 || got[0].Tool != "trufflehog" || got[0].Evidence != EvidenceCommand {
		t.Fatalf("got %+v, want one trufflehog match by command", got)
	}
}

// Spec section 4.3 rule 4, command prefixes (bot review of PR #557, controller ruling): the
// known prefixes `env` (with its VAR=value fields), `sudo` (with its flags), `time`, `nice`,
// `exec`, `command` and `nohup` are skipped, and `python -m <module>` runs the module.
func TestRecognize_CommandPrefixesAndModules(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("env", "alpine", "env GITLEAKS_CONFIG=.gl.toml gitleaks detect"),
		job("sudo", "alpine", "sudo -E trufflehog filesystem ."),
		job("module", "python:3.12", "python -m detect_secrets scan"),
		job("hook", "python:3.12", "detect-secrets-hook --baseline x"),
		job("chain", "alpine", "nohup nice time exec command ggshield secret scan path ."),
	}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	want := map[string]Match{
		"env":    {KindSecretDetection, "env", "gitleaks", EvidenceCommand},
		"sudo":   {KindSecretDetection, "sudo", "trufflehog", EvidenceCommand},
		"module": {KindSecretDetection, "module", "detect-secrets", EvidenceCommand},
		"hook":   {KindSecretDetection, "hook", "detect-secrets", EvidenceCommand},
		"chain":  {KindSecretDetection, "chain", "ggshield", EvidenceCommand},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for _, m := range got {
		if w := want[m.Job]; w != m {
			t.Errorf("job %q: got %+v, want %+v", m.Job, m, w)
		}
	}
}

// Spec section 4.3 rule 1 with a served recognizer (bot review of PR #557): a recognizer the
// platform serves may carry image globs only, and a job running such an image matches by
// image, naming the served tool.
func TestRecognize_ServedRecognizerByImage(t *testing.T) {
	served := []Recognizer{{Capability: KindSecretDetection, Tool: "corp-scanner", Images: []string{"registry.corp/sec/scanner*"}}}
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("corp", "registry.corp/sec/scanner-v2:1.4", "run-scan")}}
	got := Recognize(pipe, t.TempDir(), Merge(Defaults(), served))
	if len(got) != 1 || got[0] != (Match{KindSecretDetection, "corp", "corp-scanner", EvidenceImage}) {
		t.Fatalf("got %+v, want one corp-scanner match by image", got)
	}
}

// Spec section 4.3 rule 4 and section 4.4 (bot review round 3 of PR #557): the wrapper
// script rule reads a container-run line the same way the command rule does, so the image
// argument of a `docker run` inside the wrapper is evidence too, not only the command
// tokens of the wrapper's own lines. Without the wrapper rule collecting the wrapper's
// container-run images, this case would fall through to no match.
func TestRecognize_WrapperScript_ContainerRunImageIsEvidence(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "ci"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "ci", "scan.sh"), []byte("#!/bin/sh\ndocker run --rm trufflesecurity/trufflehog:latest filesystem .\n"), 0o755))
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("wrapped-container-run", "alpine:3.20", "./ci/scan.sh")}}
	got := Recognize(pipe, root, Defaults())
	if len(got) != 1 || got[0] != (Match{KindSecretDetection, "wrapped-container-run", "trufflehog", EvidenceWrapperScript}) {
		t.Fatalf("got %+v, want one trufflehog match by wrapper script", got)
	}
}

// Spec section 4.3 rule 4 (bot review round 3 of PR #557, false-positive fix): ggshield is
// multi-purpose, so the default command is the two-word `ggshield secret`, matching only
// its secret-detection subcommand. A prefix before the command is still skipped, and a
// served recognizer may use the same multi-word form.
func TestRecognize_MultiWordCommand_GgshieldSecretOnly(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("secret", "alpine", "ggshield secret scan ci"),
		job("iac", "alpine", "ggshield iac scan ci"),
		job("sudo-secret", "alpine", "sudo ggshield secret scan"),
	}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	want := map[string]Match{
		"secret":      {KindSecretDetection, "secret", "ggshield", EvidenceCommand},
		"sudo-secret": {KindSecretDetection, "sudo-secret", "ggshield", EvidenceCommand},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v (ggshield iac scan ci names no secret-detection tool)", got, want)
	}
	for _, m := range got {
		if w := want[m.Job]; w != m {
			t.Errorf("job %q: got %+v, want %+v", m.Job, m, w)
		}
	}
}

// Spec section 4.3 rule 4, served recognizer form (bot review round 3 of PR #557): a
// recognizer the platform serves may also carry a multi-word command, matched the same way
// as a default.
func TestRecognize_MultiWordCommand_ServedRecognizer(t *testing.T) {
	served := []Recognizer{{Capability: KindSecretDetection, Tool: "corp-scan", Commands: []string{"corp-scan secrets"}}}
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("secrets", "alpine", "corp-scan secrets --all"),
		job("deps", "alpine", "corp-scan deps"),
	}}
	got := Recognize(pipe, t.TempDir(), Merge(Defaults(), served))
	if len(got) != 1 || got[0] != (Match{KindSecretDetection, "secrets", "corp-scan", EvidenceCommand}) {
		t.Fatalf("got %+v, want one corp-scan match for job secrets only (corp-scan deps names no tool)", got)
	}
}

// Spec section 4.3 rule 1 and rule 4, recall fix (bot review round 3 of PR #557): trufflehog
// is also published under its GHCR mirror, mirroring the gitleaks default's two registries.
// A job imaging that mirror, or running it through `docker run`, is recognized.
func TestRecognize_TrufflehogGHCRImage(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("ghcr-image", "ghcr.io/trufflesecurity/trufflehog:latest", "filesystem ."),
		job("ghcr-container-run", "alpine", "docker run ghcr.io/trufflesecurity/trufflehog:latest filesystem ."),
	}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	want := map[string]Match{
		"ghcr-image":         {KindSecretDetection, "ghcr-image", "trufflehog", EvidenceImage},
		"ghcr-container-run": {KindSecretDetection, "ghcr-container-run", "trufflehog", EvidenceCommand},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for _, m := range got {
		if w := want[m.Job]; w != m {
			t.Errorf("job %q: got %+v, want %+v", m.Job, m, w)
		}
	}
}

// assertMatchesByJob fails t unless got holds exactly the matches of want, keyed by job.
func assertMatchesByJob(t *testing.T, got []Match, want map[string]Match) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for _, m := range got {
		if w := want[m.Job]; w != m {
			t.Errorf("job %q: got %+v, want %+v", m.Job, m, w)
		}
	}
}

// Spec section 4.3 rule 4, container-run form (bot review round 4 of PR #557, J1 false
// positive): the image of `docker run` is only the first field after `run` that is neither
// a flag nor a flag's value; the fields after it are the container's command and are never
// image candidates. So a crane mirror job that copies a gitleaks image is not a gitleaks
// job, the image after value-taking flags (`-v`, `-e`, `--entrypoint`) is still found, a
// later scanner argument does not outrank the real image, the `sh -c` handed to the
// container is the container's command (not unwrapped as the runner's shell), and a
// `docker run` with only flags names nothing.
func TestRecognize_ContainerRunImageIsFirstPositional(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("crane-mirror", "docker:27", "docker run --rm gcr.io/go-containerregistry/crane copy zricethezav/gitleaks:v8 registry.corp/mirror/gitleaks:v8"),
		job("value-flags", "docker:27", `docker run --rm -v "$PWD:/pwd" -e GITLEAKS_CONFIG=/pwd/.gl.toml --entrypoint gitleaks zricethezav/gitleaks:v8 detect`),
		job("later-arg", "docker:27", "docker run -it --name scan trufflesecurity/trufflehog:latest filesystem /pwd zricethezav/gitleaks"),
		job("container-sh-c", "docker:27", `docker run --rm alpine:3 sh -c "gitleaks detect"`),
		job("flags-only", "docker:27", "docker run --rm -it -v a:b"),
	}}
	assertMatchesByJob(t, Recognize(pipe, t.TempDir(), Defaults()), map[string]Match{
		"later-arg":   {KindSecretDetection, "later-arg", "trufflehog", EvidenceCommand},
		"value-flags": {KindSecretDetection, "value-flags", "gitleaks", EvidenceCommand},
	})
}

// Spec section 4.3 rule 4, multi-word command (bot review round 4 of PR #557, J2 false
// negative): the subcommand of a multi-word recognizer command may follow global flags and
// their values (`ggshield --config f secret scan ci`, `ggshield -v secret scan ci`), but
// never another positional word (`ggshield iac scan ci` and `ggshield sca scan ci` stay
// unmatched). The legacy top-level `ggshield scan` (ggshield before 1.14) is a second
// ggshield default command.
func TestRecognize_MultiWordCommand_FlagsBeforeSubcommand(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("config-flag", "alpine", "ggshield --config .gitguardian.yaml secret scan ci"),
		job("short-flag", "alpine", "ggshield -v secret scan ci"),
		job("legacy", "alpine", "ggshield scan ci"),
		job("secret", "alpine", "ggshield secret scan ci"),
		job("iac", "alpine", "ggshield iac scan ci"),
		job("sca", "alpine", "ggshield sca scan ci"),
	}}
	assertMatchesByJob(t, Recognize(pipe, t.TempDir(), Defaults()), map[string]Match{
		"config-flag": {KindSecretDetection, "config-flag", "ggshield", EvidenceCommand},
		"short-flag":  {KindSecretDetection, "short-flag", "ggshield", EvidenceCommand},
		"legacy":      {KindSecretDetection, "legacy", "ggshield", EvidenceCommand},
		"secret":      {KindSecretDetection, "secret", "ggshield", EvidenceCommand},
	})
}

// Spec section 4.3 rule 4, multi-word command (J2): a served multi-word command tolerates
// flags before its subcommand too (`corp-scan --json secrets --all`), and a different
// subcommand (`corp-scan deps`) still matches nothing.
func TestRecognize_MultiWordCommand_ServedFlagsBeforeSubcommand(t *testing.T) {
	served := []Recognizer{{Capability: KindSecretDetection, Tool: "corp-scan", Commands: []string{"corp-scan secrets"}}}
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("plain", "alpine", "corp-scan secrets"),
		job("json", "alpine", "corp-scan --json secrets --all"),
		job("deps", "alpine", "corp-scan deps"),
	}}
	assertMatchesByJob(t, Recognize(pipe, t.TempDir(), Merge(Defaults(), served)), map[string]Match{
		"plain": {KindSecretDetection, "plain", "corp-scan", EvidenceCommand},
		"json":  {KindSecretDetection, "json", "corp-scan", EvidenceCommand},
	})
}

// Spec section 4.3 rule 4 (J2): the subcommand search checked on the fields directly: the
// tail may start after flags and flag values, never after another positional word or after
// the value-less field of an `=` flag, and must match contiguously.
func TestFollowsFields(t *testing.T) {
	cases := []struct {
		fields, tail []string
		want         bool
	}{
		{[]string{"--config", ".gitguardian.yaml", "secret", "scan"}, []string{"secret"}, true},
		{[]string{"-v", "secret", "scan"}, []string{"secret"}, true},
		{[]string{"iac", "scan", "ci"}, []string{"secret"}, false},
		{[]string{"iac", "scan"}, []string{"scan"}, false},
		{[]string{"--json=true", "x", "secrets"}, []string{"secrets"}, false},
		{[]string{"--x", "secret", "foo", "scan"}, []string{"secret", "scan"}, false},
		{nil, nil, true},
		{nil, []string{"secret"}, false},
		// K2: a bare word after a value-less flag is a positional word, not the flag's value
		{[]string{"-v", "iac", "scan", "."}, []string{"scan"}, false},
		// K2: a value with a digit, a quote or one of `. / : = @ ~ ,` is skipped
		{[]string{"--level", "3", "secret"}, []string{"secret"}, true},
		{[]string{"--config", `"cfg"`, "secret"}, []string{"secret"}, true},
		{[]string{"--host", "a@b", "secret"}, []string{"secret"}, true},
		{[]string{"--home", "~", "secret"}, []string{"secret"}, true},
		{[]string{"--tags", "a,b", "secret"}, []string{"secret"}, true},
	}
	for _, c := range cases {
		if got := followsFields(c.fields, c.tail); got != c.want {
			t.Errorf("followsFields(%v, %v) = %v, want %v", c.fields, c.tail, got, c.want)
		}
	}
}

// Spec section 4.3 rule 4, multi-word command (bot review round 5 of PR #557, K2 false
// positive): after a flag without `=`, the next field is taken as the flag's value only when
// it does not look like a bare word (letters, hyphens and underscores only). So `ggshield -v
// iac scan .` does not skip `iac` as the value of `-v` and reach the legacy `ggshield scan`
// tail; a path-like value (`--config .gitguardian.yaml`) is still skipped.
func TestRecognize_MultiWordCommand_BareWordIsNeverAFlagValue(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("v-iac", "alpine", "ggshield -v iac scan ."),
		job("debug-sca", "alpine", "ggshield --debug sca scan"),
		job("self-signed-iac", "alpine", "ggshield --allow-self-signed iac scan ci"),
		job("config-secret", "alpine", "ggshield --config .gitguardian.yaml secret scan ci"),
		job("v-secret", "alpine", "ggshield -v secret scan"),
		job("config-eq-secret", "alpine", "ggshield --config=x.yaml secret scan"),
		job("legacy", "alpine", "ggshield scan ci"),
		job("secret", "alpine", "ggshield secret scan ci"),
	}}
	assertMatchesByJob(t, Recognize(pipe, t.TempDir(), Defaults()), map[string]Match{
		"config-secret":    {KindSecretDetection, "config-secret", "ggshield", EvidenceCommand},
		"v-secret":         {KindSecretDetection, "v-secret", "ggshield", EvidenceCommand},
		"config-eq-secret": {KindSecretDetection, "config-eq-secret", "ggshield", EvidenceCommand},
		"legacy":           {KindSecretDetection, "legacy", "ggshield", EvidenceCommand},
		"secret":           {KindSecretDetection, "secret", "ggshield", EvidenceCommand},
	})
}

// Spec section 4.3 rule 4, multi-word command (K2, accepted cost): a served command keeps
// tolerating flags before its subcommand (`corp-scan --json secrets --all`), but a bare-word
// flag value before the subcommand (`corp-scan --profile ci secrets`) is not understood: `ci`
// is taken as a positional word, so the job is not recognized.
func TestRecognize_MultiWordCommand_ServedBareWordFlagValueIsNotUnderstood(t *testing.T) {
	served := []Recognizer{{Capability: KindSecretDetection, Tool: "corp-scan", Commands: []string{"corp-scan secrets"}}}
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("json", "alpine", "corp-scan --json secrets --all"),
		job("profile", "alpine", "corp-scan --profile ci secrets"),
	}}
	assertMatchesByJob(t, Recognize(pipe, t.TempDir(), Merge(Defaults(), served)), map[string]Match{
		"json": {KindSecretDetection, "json", "corp-scan", EvidenceCommand},
	})
}

// Spec section 4.3 rule 4, known limitation (K3): an all-hooks `pre-commit run` is not
// recognized, even when the repository's hooks include a secret scanner, because the hook
// list is in `.pre-commit-config.yaml`, which the rules deliberately do not read.
func TestRecognize_PreCommitAllHooksIsNotRecognized(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{
		job("all-files", "python:3.12", "pre-commit run --all-files"),
		job("bare", "python:3.12", "pre-commit run"),
	}}
	if got := Recognize(pipe, t.TempDir(), Defaults()); len(got) != 0 {
		t.Fatalf("got %+v, want no match: the pre-commit hook list is not read", got)
	}
}
