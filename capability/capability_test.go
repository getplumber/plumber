package capability

import "testing"

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
		{Capability: KindSecretDetection, Tool: "in-house-scanner", Commands: []string{"scan-secrets"}},
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
	if out[0].Tool != Defaults()[0].Tool {
		t.Fatalf("the defaults do not come first: %+v", out[0])
	}
}

func TestKnownKind(t *testing.T) {
	if !KnownKind(KindSecretDetection) || KnownKind("sast") || KnownKind("") {
		t.Fatal("KnownKind must accept exactly secret_detection")
	}
}
