package control

import (
	"io/fs"
	"regexp"
	"testing"

	"github.com/getplumber/plumber/policies"
)

// minFilesWithLiteral is how many policies/*.rego files carry at least one
// literal code/severity pair today (all 72 but placeholder.rego). A rule
// rewritten to build its finding through a helper would drop out of this
// test silently; the floor makes that loss of coverage fail instead.
const minFilesWithLiteral = 71

var findingLiteral = regexp.MustCompile(`"code":\s*"(ISSUE-\d+)"[^}]*?"severity":\s*"(\w+)"|"severity":\s*"(\w+)"[^}]*?"code":\s*"(ISSUE-\d+)"`)

// TestRegoSeverityLiteralsMatchRegistry: the registry is the one severity
// source (spec: base severity). A rule that says "critical" while the registry
// says "high" made the JSON findings[].severity contradict the score.
func TestRegoSeverityLiteralsMatchRegistry(t *testing.T) {
	covered := 0
	err := fs.WalkDir(policies.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !regexp.MustCompile(`\.rego$`).MatchString(path) {
			return err
		}
		src, err := fs.ReadFile(policies.FS, path)
		if err != nil {
			return err
		}
		matches := findingLiteral.FindAllStringSubmatch(string(src), -1)
		if len(matches) > 0 {
			covered++
		}
		for _, m := range matches {
			code, sev := m[1], m[2]
			if code == "" {
				code, sev = m[4], m[3]
			}
			if want := string(SeverityForCode(ErrorCode(code))); sev != want {
				t.Errorf("%s: %s says %q, registry says %q", path, code, sev, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if covered < minFilesWithLiteral {
		t.Errorf("only %d rego files carry a literal code/severity pair, want at least %d: a rule stopped being checked against the registry", covered, minFilesWithLiteral)
	}
}
