package capability

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/capability/capdecl"
)

// Spec 4.2: the schema decodes from YAML and from JSON with the same keys, the YAML (the
// file a user types) strictly, the served JSON tolerantly (spec 4.6).
func TestDeclaration_DecodeYAMLStrict_JSONTolerant(t *testing.T) {
	y := []byte("capabilities:\n  - name: secret_detection\n    recognizers:\n      - tool: gitleaks\n        images: [\"*gitleaks*\"]\n        commands: [\"*gitleaks*\"]\n      - gitlab_report_types: [secret_detection]\n        gitlab_include_template: [\"Jobs/Secret-Detection*\"]\n        gitlab_include_component: [\"*/secret-detection/*\"]\n")
	decls, err := DecodeYAML(y)
	if err != nil || len(decls) != 1 || decls[0].Name != "secret_detection" || len(decls[0].Recognizers) != 2 || decls[0].Recognizers[1].GitlabReportTypes[0] != "secret_detection" {
		t.Fatalf("yaml: %v %+v", err, decls)
	}
	j := []byte(`[{"name":"secret_detection","recognizers":[{"tool":"gitleaks","images":["*gitleaks*"]}]}]`)
	if d2, err := DecodeJSON(j); err != nil || d2[0].Recognizers[0].Tool != "gitleaks" {
		t.Fatalf("json: %v %+v", err, d2)
	}
	if _, err := DecodeYAML([]byte("capabilities:\n  - name: a\n    recognisers: []\n")); err == nil || !strings.Contains(err.Error(), "recognisers") {
		t.Fatalf("an unknown key must be refused by name, got %v", err)
	}
	// Spec 4.6 (ruling): the served JSON is decoded tolerantly, an unknown key ignored and
	// the known fields kept, so a newer platform's field never drops the list.
	tolerant, err := DecodeJSON([]byte(`[{"name":"a","future":1,"recognizers":[{"github_actions":["x"],"commands":["y"]}]}]`))
	if err != nil || len(tolerant) != 1 || tolerant[0].Name != "a" || !reflect.DeepEqual(tolerant[0].Recognizers[0].Commands, []string{"y"}) {
		t.Fatalf("an unknown JSON key must be ignored and the known fields kept, got %v %+v", err, tolerant)
	}
	if _, err := DecodeJSON([]byte(`{"name":"a"}`)); err == nil {
		t.Fatal("a JSON value that is not an array must be refused")
	}
}

// Spec 4.2 bounds and the name grammar, each refused with the violation named.
func TestValidate_Bounds(t *testing.T) {
	validDecl := Declaration{Name: "secret_detection", Recognizers: []capdecl.Recognizer{{Tool: "gitleaks", Images: []string{"*gitleaks*"}}}}

	manyCapabilities := make([]Declaration, 51)
	for i := range manyCapabilities {
		manyCapabilities[i] = Declaration{Name: fmt.Sprintf("cap%d", i), Recognizers: []capdecl.Recognizer{{Images: []string{"*x*"}}}}
	}

	manyRecognizers := make([]capdecl.Recognizer, 33)
	for i := range manyRecognizers {
		manyRecognizers[i] = capdecl.Recognizer{Images: []string{"*x*"}}
	}

	manyPatterns := make([]string, 65)
	for i := range manyPatterns {
		manyPatterns[i] = "*x*"
	}

	longPattern := strings.Repeat("a", 257)

	tests := []struct {
		name    string
		decls   []Declaration
		wantErr string
	}{
		{
			name:    "nil passes",
			decls:   nil,
			wantErr: "",
		},
		{
			name:    "a valid list passes",
			decls:   []Declaration{validDecl},
			wantErr: "",
		},
		{
			name:    "51 capabilities",
			decls:   manyCapabilities,
			wantErr: "at most 50 capabilities",
		},
		{
			name:    `name "Secret Detection"`,
			decls:   []Declaration{{Name: "Secret Detection", Recognizers: []capdecl.Recognizer{{Images: []string{"*x*"}}}}},
			wantErr: "a capability name must be 1 to 64 bytes of lowercase letters, digits, underscore or hyphen",
		},
		{
			name: "duplicate names",
			decls: []Declaration{
				{Name: "dup", Recognizers: []capdecl.Recognizer{{Images: []string{"*x*"}}}},
				{Name: "dup", Recognizers: []capdecl.Recognizer{{Images: []string{"*y*"}}}},
			},
			wantErr: "capability names must be unique",
		},
		{
			name:    "33 recognizers",
			decls:   []Declaration{{Name: "cap", Recognizers: manyRecognizers}},
			wantErr: "at most 32 recognizers per capability",
		},
		{
			name:    "a recognizer with no pattern",
			decls:   []Declaration{{Name: "cap", Recognizers: []capdecl.Recognizer{{Tool: "noop"}}}},
			wantErr: "a recognizer must carry at least one pattern",
		},
		{
			name:    "tool 65 bytes",
			decls:   []Declaration{{Name: "cap", Recognizers: []capdecl.Recognizer{{Tool: strings.Repeat("a", 65), Images: []string{"*x*"}}}}},
			wantErr: "tool must be 1 to 64 bytes without control characters",
		},
		{
			name:    "65 patterns",
			decls:   []Declaration{{Name: "cap", Recognizers: []capdecl.Recognizer{{Images: manyPatterns}}}},
			wantErr: "at most 64 patterns per field",
		},
		{
			name:    "a 257-byte pattern",
			decls:   []Declaration{{Name: "cap", Recognizers: []capdecl.Recognizer{{Images: []string{longPattern}}}}},
			wantErr: "a pattern must be 1 to 256 bytes without control characters",
		},
		{
			name:    "an empty pattern",
			decls:   []Declaration{{Name: "cap", Recognizers: []capdecl.Recognizer{{Images: []string{""}}}}},
			wantErr: "a pattern must be 1 to 256 bytes without control characters",
		},
		{
			name:    "a pattern with NEL",
			decls:   []Declaration{{Name: "cap", Recognizers: []capdecl.Recognizer{{Images: []string{"a\u0085b"}}}}},
			wantErr: "a pattern must be 1 to 256 bytes without control characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.decls)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

// Spec 4.2: the built-in list declares secret_detection with its six tools and nothing else;
// it is valid against its own bounds; each call is a fresh copy.
func TestBuiltin(t *testing.T) {
	b := Builtin()
	names := make([]string, len(b))
	for i, d := range b {
		names[i] = d.Name
	}
	if len(names) != 1 || names[0] != "secret_detection" {
		t.Fatalf("Builtin() names = %v, want exactly [secret_detection]", names)
	}
	var tools []string
	for _, r := range b[0].Recognizers {
		tools = append(tools, r.Tool)
	}
	want := []string{"gitleaks", "betterleaks", "trufflehog", "detect-secrets", "ggshield", "gitlab-secret-detection"}
	if !reflect.DeepEqual(tools, want) {
		t.Fatalf("Builtin() tools = %v, want %v in order", tools, want)
	}
	if err := Validate(Builtin()); err != nil {
		t.Fatalf("Validate(Builtin()) = %v, want nil", err)
	}
	a := Builtin()
	a[0].Recognizers[0].Tool = "mutated"
	fresh := Builtin()
	if fresh[0].Recognizers[0].Tool == "mutated" {
		t.Fatal("Builtin() shares its backing storage across calls")
	}
}

// Spec 4.2: the user list first, then the built-ins the user did not redeclare; a
// redeclared name replaces the built-in whole.
func TestEffective(t *testing.T) {
	if got := Effective(nil); !reflect.DeepEqual(got, Builtin()) {
		t.Fatalf("Effective(nil) = %+v, want Builtin()", got)
	}

	sast := Declaration{Name: "sast", Recognizers: []capdecl.Recognizer{{Tool: "semgrep", Commands: []string{"*semgrep*"}}}}
	got := Effective([]Declaration{sast})
	if len(got) != 2 || got[0].Name != "sast" || got[1].Name != "secret_detection" {
		t.Fatalf("Effective([sast]) = %+v, want [sast, secret_detection]", got)
	}

	narrowed := Declaration{Name: "secret_detection", Recognizers: []capdecl.Recognizer{{Tool: "corp-scanner", Commands: []string{"*corp-scanner*"}}}}
	got = Effective([]Declaration{narrowed})
	if len(got) != 1 || got[0].Name != "secret_detection" || len(got[0].Recognizers) != 1 || got[0].Recognizers[0].Tool != "corp-scanner" {
		t.Fatalf("Effective([narrowed secret_detection]) = %+v, want exactly the user's own declaration", got)
	}
	for _, r := range got[0].Recognizers {
		if r.Tool == "gitleaks" {
			t.Fatal("Effective() merged the built-in's recognizers into the user's redeclared capability")
		}
	}
}

// Spec 4.3: plain globs, * crosses /, ? one rune, classes, case-sensitive, whole subject; a
// bad pattern is skipped with one warning naming it.
func TestCompile_Globs(t *testing.T) {
	decl := Declaration{Name: "secret_detection", Recognizers: []capdecl.Recognizer{{
		Tool:                   "gitleaks",
		Images:                 []string{"*gitleaks*"},
		GitlabIncludeTemplate:  []string{"Jobs/Secret-Detection*"},
		GitlabIncludeComponent: []string{"*/secret-detection/*"},
	}}}

	compiled := Compile([]Declaration{decl}, nil)
	if len(compiled) != 1 || len(compiled[0].Recognizers) != 1 {
		t.Fatalf("Compile() = %+v", compiled)
	}
	rec := compiled[0].Recognizers[0]

	matchField := func(fieldName, subject string) bool {
		for _, f := range rec.Fields {
			if f.Name != fieldName {
				continue
			}
			for _, p := range f.Patterns {
				if p.Glob.Match(subject) {
					return true
				}
			}
		}
		return false
	}

	if !matchField("images", "docker.io/zricethezav/gitleaks") {
		t.Fatal(`"*gitleaks*" must match "docker.io/zricethezav/gitleaks"`)
	}
	// "gitleaks" alone (no wildcard) must not match a subject that merely contains it: the
	// whole subject is matched, not a substring (spec 4.3).
	noWildcard := Compile([]Declaration{{Name: "x", Recognizers: []capdecl.Recognizer{{Images: []string{"gitleaks"}}}}}, nil)
	if noWildcard[0].Recognizers[0].Fields[0].Patterns[0].Glob.Match("docker.io/zricethezav/gitleaks") {
		t.Fatal(`"gitleaks" must not match "docker.io/zricethezav/gitleaks"`)
	}

	if !matchField("gitlab_include_template", "Jobs/Secret-Detection.gitlab-ci.yml") {
		t.Fatal(`"Jobs/Secret-Detection*" must match "Jobs/Secret-Detection.gitlab-ci.yml"`)
	}
	if !matchField("gitlab_include_component", "gitlab.com/components/secret-detection/secret-detection") {
		t.Fatal(`"*/secret-detection/*" must match "gitlab.com/components/secret-detection/secret-detection"`)
	}

	var warnings []string
	bad := Declaration{Name: "secret_detection", Recognizers: []capdecl.Recognizer{{Tool: "gitleaks", Images: []string{"[abc"}}}}
	Compile([]Declaration{bad}, func(msg string) { warnings = append(warnings, msg) })
	if len(warnings) != 1 {
		t.Fatalf("warn called %d times, want exactly once: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "secret_detection") || !strings.Contains(warnings[0], "images") || !strings.Contains(warnings[0], "[abc") {
		t.Fatalf("warn message %q must name the capability, the field and the pattern", warnings[0])
	}
}
