package configuration

import "testing"

// fieldAt walks a welded schema to the field at the dotted path below the
// control name ("defaultMustBeProtected", "allowFailureMustBeFalse.enabled").
func fieldAt(t *testing.T, control string, path ...string) SchemaField {
	t.Helper()
	s, ok := ConfigSchemaFor(control)
	if !ok {
		t.Fatalf("control %s has no schema", control)
	}
	fields := s.Fields
	var found SchemaField
	for i, name := range path {
		ok = false
		for _, f := range fields {
			if f.Name == name {
				found = f
				fields = f.Fields
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("control %s has no field %s (segment %d)", control, name, i)
		}
	}
	return found
}

// A behavior toggle is a boolean whose unset state simply takes the
// documented default: rendering it as a three-state expectation ("must be
// enabled / must be disabled / not checked") invents a state the CLI does
// not have. The schema exports Toggle so a form can tell the two apart
// (operator report, 2026-09-21).
func TestSchemaExportsToggleOnBehaviorSwitches(t *testing.T) {
	toggles := []struct {
		control string
		path    []string
	}{
		{"branchMustBeProtected", []string{"defaultMustBeProtected"}},
		{"containerImageMustComeFromAuthorizedSources", []string{"trustDockerHubOfficialImages"}},
		{"containerImageMustComeFromAuthorizedSources", []string{"includePlumberDefaults"}},
		{"containerImageMustNotUseForbiddenTags", []string{"containerImagesMustBePinnedByDigest"}},
		{"includesMustNotUseForbiddenVersions", []string{"defaultBranchIsForbiddenVersion"}},
		{"pipelineMustNotUseDockerInDocker", []string{"detectInsecureDaemon"}},
		{"githubActionMustComeFromAuthorizedSources", []string{"trustGithubOfficialActions"}},
		{"githubActionMustComeFromAuthorizedSources", []string{"trustSameOrgActions"}},
		{"githubActionMustComeFromAuthorizedSources", []string{"includePlumberDefaults"}},
		{"securityJobsMustNotBeWeakened", []string{"allowFailureMustBeFalse", "enabled"}},
		{"securityJobsMustNotBeWeakened", []string{"rulesMustNotBeRedefined", "enabled"}},
		{"securityJobsMustNotBeWeakened", []string{"whenMustNotBeManual", "enabled"}},
	}
	for _, tc := range toggles {
		f := fieldAt(t, tc.control, tc.path...)
		if !f.Toggle {
			t.Errorf("%s.%v must export Toggle=true", tc.control, tc.path)
		}
	}
}

// Every control's own `enabled` boolean is a toggle by construction: it
// turns the control on or off, never expresses an expectation about the
// scanned project. The rule is structural so a new control can never ship
// an `enabled` that renders as an expectation.
func TestSchemaEveryEnabledBooleanIsAToggle(t *testing.T) {
	for _, s := range ConfigSchemas() {
		for _, f := range s.Fields {
			if f.Name == "enabled" && f.Type == "bool" && !f.Toggle {
				t.Errorf("%s.enabled must export Toggle=true", s.Control)
			}
		}
	}
}

// Expectation booleans stay non-toggles: unset means "assert nothing about
// this setting", a real third state a form must keep offering.
func TestSchemaExpectationBooleansStayNonToggle(t *testing.T) {
	expectations := []struct {
		control string
		path    []string
	}{
		{"mergeRequestSettingsMustBeCompliant", []string{"mergePipelinesEnabled"}},
		{"mergeRequestSettingsMustBeCompliant", []string{"removeSourceBranchAfterMerge"}},
		{"mergeRequestApprovalSettingsMustBeCompliant", []string{"preventApprovalByAuthor"}},
		{"branchMustBeProtected", []string{"allowForcePush"}},
		{"branchMustBeProtected", []string{"codeOwnerApprovalRequired"}},
	}
	for _, tc := range expectations {
		f := fieldAt(t, tc.control, tc.path...)
		if f.Toggle {
			t.Errorf("%s.%v is an expectation and must NOT export Toggle", tc.control, tc.path)
		}
	}
}

// A toggle whose unset state means ON must say so through Default, or a
// form seeding the zero value would silently flip the behavior off.
func TestSchemaTogglesThatDefaultOnDeclareIt(t *testing.T) {
	defaultOn := []struct {
		control string
		path    []string
	}{
		{"pipelineMustNotUseDockerInDocker", []string{"detectInsecureDaemon"}},
		{"securityJobsMustNotBeWeakened", []string{"allowFailureMustBeFalse", "enabled"}},
		{"securityJobsMustNotBeWeakened", []string{"rulesMustNotBeRedefined", "enabled"}},
		{"securityJobsMustNotBeWeakened", []string{"whenMustNotBeManual", "enabled"}},
	}
	for _, tc := range defaultOn {
		f := fieldAt(t, tc.control, tc.path...)
		if f.Default != "true" {
			t.Errorf("%s.%v defaults to on when unset and must declare Default \"true\", got %q", tc.control, tc.path, f.Default)
		}
	}
}
