// Package capability recognizes what a pipeline job does from the facts the CLI already
// parsed (the job's image, the includes, its report artifacts, its script lines) and from
// the scripts it calls in the checkout. The platform's dependencies graph lists the result
// as the `capability` resource kind ("which projects run secret detection"). The vocabulary
// is closed on both axes; the recognizers ship as defaults and are extended, never
// narrowed, by the list the platform serves through /context.
package capability

// KindSecretDetection is the only capability of this version.
const KindSecretDetection = "secret_detection"

// The evidence a match rests on, in the order the rules run.
const (
	EvidenceImage         = "image"
	EvidenceInclude       = "include"
	EvidenceReport        = "report"
	EvidenceCommand       = "command"
	EvidenceWrapperScript = "wrapper_script"
)

// KnownKind reports whether kind is in the closed vocabulary.
func KnownKind(kind string) bool { return kind == KindSecretDetection }

// Recognizer names one tool and the patterns that reveal it: image globs on
// `<registry>/<name>` (tag and digest stripped), command tokens, include names (a template
// path or a component name) and artifacts.reports keys. Includes and ReportTypes are
// defaults-only: a served recognizer carries images and commands.
type Recognizer struct {
	Capability  string   `json:"capability"`
	Tool        string   `json:"tool"`
	Images      []string `json:"images,omitempty"`
	Commands    []string `json:"commands,omitempty"`
	Includes    []string `json:"includes,omitempty"`
	ReportTypes []string `json:"report_types,omitempty"`
}

// Match is one recognized capability of one job.
type Match struct {
	Kind     string `json:"kind"`
	Job      string `json:"job"`
	Tool     string `json:"tool"`
	Evidence string `json:"evidence"`
}

// defaults is the shipped list; Defaults returns a deep copy so callers never alias it.
// Image names are verified against the tools' published registries (Task 2, Step 2 of the
// plan); a tool without a verified image is recognized by its command alone.
var defaults = []Recognizer{
	{Capability: KindSecretDetection, Tool: "gitleaks", Images: []string{"zricethezav/gitleaks", "ghcr.io/gitleaks/gitleaks"}, Commands: []string{"gitleaks"}},
	{Capability: KindSecretDetection, Tool: "betterleaks", Images: []string{"ghcr.io/betterleaks/betterleaks"}, Commands: []string{"betterleaks"}},
	{Capability: KindSecretDetection, Tool: "trufflehog", Images: []string{"trufflesecurity/trufflehog"}, Commands: []string{"trufflehog"}},
	{Capability: KindSecretDetection, Tool: "detect-secrets", Commands: []string{"detect-secrets"}},
	{Capability: KindSecretDetection, Tool: "ggshield", Images: []string{"gitguardian/ggshield"}, Commands: []string{"ggshield"}},
	{Capability: KindSecretDetection, Tool: "gitlab-secret-detection", Images: []string{"registry.gitlab.com/security-products/secrets"},
		Includes: []string{"Security/Secret-Detection.gitlab-ci.yml", "Jobs/Secret-Detection.gitlab-ci.yml", "secret-detection"}, ReportTypes: []string{"secret_detection"}},
}

// Defaults returns a deep copy of the shipped recognizer list; callers never alias its
// backing arrays.
func Defaults() []Recognizer {
	out := make([]Recognizer, len(defaults))
	for i, r := range defaults {
		out[i] = Recognizer{Capability: r.Capability, Tool: r.Tool,
			Images: append([]string(nil), r.Images...), Commands: append([]string(nil), r.Commands...),
			Includes: append([]string(nil), r.Includes...), ReportTypes: append([]string(nil), r.ReportTypes...)}
	}
	return out
}

// Merge returns the effective list: the defaults in their order, then every served
// recognizer with a known capability and a non-empty tool, images and commands only.
func Merge(defaults, served []Recognizer) []Recognizer {
	out := append([]Recognizer(nil), defaults...)
	for _, r := range served {
		if !KnownKind(r.Capability) || r.Tool == "" {
			continue
		}
		out = append(out, Recognizer{Capability: r.Capability, Tool: r.Tool,
			Images: append([]string(nil), r.Images...), Commands: append([]string(nil), r.Commands...)})
	}
	return out
}
