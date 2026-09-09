package control

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// ISSUE-XXX codes are the immutable ids of issue types (#458): the platform
// keys durable state on them, so a code is never renumbered and never
// reused. Uniqueness across the registry is the enforceable half of that
// contract; never-reuse is enforced by review of this file's diff.
func TestIssueCodesAreUnique(t *testing.T) {
	seen := map[ErrorCode]string{}
	for _, info := range AllCodes() {
		if prev, dup := seen[info.Code]; dup {
			t.Errorf("code %s registered twice (%q and %q)", info.Code, prev, info.Title)
		}
		seen[info.Code] = info.Title
	}
}

// Every ISSUE-XXX literal in the rego policies is a registered code. An
// unregistered code would ship findings with no title, no severity and a
// message-only identity that collapses N findings into one platform issue
// (#448): this pin makes that impossible to merge.
func TestEveryRegoIssueCodeIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, info := range AllCodes() {
		registered[string(info.Code)] = true
	}

	pattern := regexp.MustCompile(`ISSUE-\d+`)
	files, err := filepath.Glob(filepath.Join("..", "policies", "*.rego"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no rego policies found: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range pattern.FindAllString(string(data), -1) {
			if !registered[code] {
				t.Errorf("%s emits %s which is not registered in control/codes.go; register it (and its identity declaration) before shipping", filepath.Base(f), code)
			}
		}
	}
}
