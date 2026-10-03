package control

import "strings"

// entryRolePrefix is FindingLine's own "this finding anchors path <id>"
// phrasing (control/explain.go). AnnotateFindingsV4 reads it back to know
// which path's sentence belongs in a finding's explanation, rather than
// reaching into explain.go's unexported path-lookup helpers.
const entryRolePrefix = "Entry of path "

// AnnotateFindingsV4 writes the contextual severity, the base (registered)
// severity, the role line and the path ids onto every finding, and the path
// sentence onto every finding that anchors a path, so that each v4 output
// (JSON, SARIF, push, comment) tells the same story (spec section 3). The
// caller gates this: it must run only when the run was actually priced
// under scoring-v4 (never on a v3 run, and never on a v4 request that fell
// back to v3 for lack of a situation), so a v3 finding's Severity and Data
// are left exactly as the registry and the engine produced them.
func AnnotateFindingsV4(result *AnalysisResult) {
	for i := range result.Findings {
		f := &result.Findings[i]
		if f.Data == nil {
			f.Data = map[string]any{}
		}
		f.Data["baseSeverity"] = string(SeverityForCode(ErrorCode(f.Code)))
		f.Severity = string(ContextualSeverity(*f, result.Paths))
		role := FindingLine(*f, result.Paths)
		f.Data["role"] = role
		if ids := PathIDsFor(*f, result.Paths); len(ids) > 0 {
			f.Data["pathIds"] = ids
		}
		if anchorID, ok := strings.CutPrefix(role, entryRolePrefix); ok {
			for _, p := range result.Paths {
				if p.ID == anchorID {
					f.Data["explanation"] = PathSentence(p)
					break
				}
			}
		}
	}
}
