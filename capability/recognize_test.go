package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestRecognize_EvidencePriority_ImageBeatsCommand(t *testing.T) {
	pipe := &ir.NormalizedPipeline{Jobs: []ir.Job{job("both", "trufflesecurity/trufflehog:latest", "gitleaks detect")}}
	got := Recognize(pipe, t.TempDir(), Defaults())
	if len(got) != 1 || got[0].Tool != "trufflehog" || got[0].Evidence != EvidenceImage {
		t.Fatalf("got %+v, want one trufflehog match by image (image is checked before commands)", got)
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
