package control

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/getplumber/plumber/configuration"
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

// Remediation and description prose may name config keys as
// "controlName.fieldKey". Each such reference must point at a real field of
// that control's schema, or the advice drifts from the code the way the
// stale ISSUE-101/102 references did before this PR fixed them (#458). Only
// dotted pairs whose left side IS a registered control are checked, so
// ".plumber.yaml", "docker.io" and similar prose never false-positive.
func TestProseConfigKeyReferencesResolve(t *testing.T) {
	fieldsByControl := map[string]map[string]bool{}
	for _, s := range configuration.ConfigSchemas() {
		set := map[string]bool{}
		var walk func(prefix string, fs []configuration.SchemaField)
		walk = func(prefix string, fs []configuration.SchemaField) {
			for _, f := range fs {
				set[prefix+f.Name] = true
				if len(f.Fields) > 0 {
					walk(prefix+f.Name+".", f.Fields)
				}
			}
		}
		walk("", s.Fields)
		fieldsByControl[s.Control] = set
	}

	ref := regexp.MustCompile(`\b([a-zA-Z][A-Za-z0-9]+)\.([a-z][A-Za-z0-9]+)\b`)
	for _, info := range AllCodes() {
		for _, text := range []string{info.Description, info.Remediation} {
			for _, m := range ref.FindAllStringSubmatch(text, -1) {
				control, field := m[1], m[2]
				fields, isControl := fieldsByControl[control]
				if !isControl {
					continue // prose like .plumber.yaml or docker.io, not a control reference
				}
				if !fields[field] {
					t.Errorf("%s prose references %s.%s but that control's schema has no such field; update the wording or the schema", info.Code, control, field)
				}
			}
		}
	}
}

// Every issue code's ControlName resolves to a registered control, so no
// issue can be silently orphaned by a typo or a control rename: an orphaned
// code would vanish from every control's IssueCodes in the exported catalog
// while still being emittable by the engine (#458).
func TestEveryIssueCodeBelongsToARegisteredControl(t *testing.T) {
	known := map[string]bool{}
	for _, e := range configuration.ControlsCatalog() {
		known[e.Name] = true
	}
	for _, info := range AllCodes() {
		if info.ControlName == "" {
			t.Errorf("%s has an empty ControlName; every issue belongs to a control", info.Code)
			continue
		}
		if !known[info.ControlName] {
			t.Errorf("%s names control %q which is not in the registry; fix the ControlName or register the control", info.Code, info.ControlName)
		}
	}
}
