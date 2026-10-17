package capability

import (
	"reflect"
	"testing"
)

func TestDefaults_SecretDetectionToolsAreListed(t *testing.T) {
	tools := map[string]bool{}
	for _, r := range Defaults() {
		if r.Capability != KindSecretDetection {
			t.Fatalf("default recognizer %q names capability %q, want %q", r.Tool, r.Capability, KindSecretDetection)
		}
		if len(r.Images)+len(r.Commands)+len(r.Includes)+len(r.ReportTypes) == 0 {
			t.Fatalf("default recognizer %q carries no pattern at all", r.Tool)
		}
		tools[r.Tool] = true
	}
	for _, want := range []string{"gitleaks", "betterleaks", "trufflehog", "detect-secrets", "ggshield", "gitlab-secret-detection"} {
		if !tools[want] {
			t.Errorf("Defaults() lacks the %q recognizer", want)
		}
	}
}

func TestDefaults_ReturnsACopy(t *testing.T) {
	a := Defaults()
	a[0].Commands = append(a[0].Commands, "mutated")
	for _, r := range Defaults() {
		for _, c := range r.Commands {
			if c == "mutated" {
				t.Fatal("Defaults() shares its backing arrays with the caller")
			}
		}
	}
}

func TestMerge_DefaultsFirstThenServed_UnknownAndEmptyDropped(t *testing.T) {
	served := []Recognizer{
		{Capability: KindSecretDetection, Tool: "in-house-scanner", Images: []string{"registry.corp/sec/scanner*"}, Commands: []string{"scan-secrets"}},
		{Capability: "sast", Tool: "semgrep", Commands: []string{"semgrep"}},        // unknown kind: dropped
		{Capability: KindSecretDetection, Tool: "", Commands: []string{"nameless"}}, // no tool: dropped
	}
	out := Merge(Defaults(), served)
	n := len(Defaults())
	if len(out) != n+1 {
		t.Fatalf("Merge kept %d entries, want the %d defaults plus one served", len(out), n)
	}
	if out[n].Tool != "in-house-scanner" {
		t.Fatalf("the served recognizer is not last: %+v", out[n])
	}
	// A served recognizer carries images as well as commands: Merge keeps both.
	if len(out[n].Images) != 1 || out[n].Images[0] != "registry.corp/sec/scanner*" {
		t.Fatalf("the served recognizer lost its images: %+v", out[n])
	}
	if out[0].Tool != Defaults()[0].Tool {
		t.Fatalf("the defaults do not come first: %+v", out[0])
	}
}

// L1 fix (bot review round 6): Merge copies a served recognizer's Images and Commands only
// (by design, served recognizers never carry Includes or ReportTypes), but the defaults
// themselves must survive Merge verbatim: the gitlab-secret-detection default's Includes and
// ReportTypes are what the include and report rules match on in platform mode, so a bug that
// dropped them while rebuilding the list would silently stop both rules from ever matching
// on a merged list without a single test noticing.
func TestMerge_DefaultsKeepIncludesAndReportTypes(t *testing.T) {
	out := Merge(Defaults(), nil)
	var merged, want *Recognizer
	for i := range out {
		if out[i].Tool == "gitlab-secret-detection" {
			merged = &out[i]
		}
	}
	for i := range defaults {
		if defaults[i].Tool == "gitlab-secret-detection" {
			want = &defaults[i]
		}
	}
	if merged == nil || want == nil {
		t.Fatal("gitlab-secret-detection is missing from Defaults() or from the merged list")
	}
	if !reflect.DeepEqual(merged.Includes, want.Includes) {
		t.Errorf("merged gitlab-secret-detection Includes = %v, want %v", merged.Includes, want.Includes)
	}
	if !reflect.DeepEqual(merged.ReportTypes, want.ReportTypes) {
		t.Errorf("merged gitlab-secret-detection ReportTypes = %v, want %v", merged.ReportTypes, want.ReportTypes)
	}
}

func TestKnownKind(t *testing.T) {
	if !KnownKind(KindSecretDetection) || KnownKind("sast") || KnownKind("") {
		t.Fatal("KnownKind must accept exactly secret_detection")
	}
}
