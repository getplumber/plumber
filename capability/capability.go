// Package capability recognizes what a pipeline job does from the facts the CLI already
// parsed (the job's image, the include that defined it, its report artifacts, its script
// lines) and from the wrapper scripts it calls in the checkout. A capability is a name a
// user declares, or the CLI's built-in list does (builtin.yaml), with glob recognizers over
// seven subjects (spec 4.2, 4.3); the platform's dependencies graph lists the result as the
// `capability` resource kind ("which projects run secret detection").
package capability

// The evidence a match rests on: the name of the recognizer field that matched (spec 4.4),
// listed in the precedence order a recognizer's fields are tried in (spec 4.3).
const (
	EvidenceImages                 = "images"
	EvidenceGitlabIncludeTemplate  = "gitlab_include_template"
	EvidenceGitlabIncludeComponent = "gitlab_include_component"
	EvidenceGitlabIncludeProject   = "gitlab_include_project"
	EvidenceGitlabReportTypes      = "gitlab_report_types"
	EvidenceCommands               = "commands"
	EvidenceWrapperScript          = "wrapper_script"
)

// Match is one recognized capability of one job: the capability's name, the job, the tool
// (the recognizer's declared tool, else the pattern that matched) and the evidence (the
// name of the field that matched).
type Match struct {
	Kind     string `json:"kind"`
	Job      string `json:"job"`
	Tool     string `json:"tool"`
	Evidence string `json:"evidence"`
}
