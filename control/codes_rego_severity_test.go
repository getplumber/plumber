package control

import (
	"io/fs"
	"regexp"
	"testing"

	"github.com/getplumber/plumber/policies"
)

// minLiteralPairs is how many literal code/severity pairs policies/*.rego
// carry today, counted per rule, not per file: a file such as
// security_jobs_weakened.rego emits ISSUE-410 from three rules, and a
// per-file floor would not notice one of them rewritten to build its
// finding through a helper. Any rule dropping out of this test makes the
// floor fail instead of passing silently.
const minLiteralPairs = 86

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
		covered += len(matches)
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
	if covered < minLiteralPairs {
		t.Errorf("only %d literal code/severity pairs found across the rego rules, want at least %d: a rule stopped being checked against the registry", covered, minLiteralPairs)
	}
}
