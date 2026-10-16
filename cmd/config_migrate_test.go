package cmd

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// migrateString runs migrateYAMLDocument over a YAML text and returns the
// rewritten text and the change list.
func migrateString(t *testing.T, in string) (string, bool, []string) {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(in), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	migrated, changes, err := migrateYAMLDocument(&doc)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	out, err := encodeYAMLDocument(&doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), migrated, changes
}

// The old cache control key is renamed in place under github.controls,
// keeping its comments, its position and enabled; every field the new
// control does not carry is dropped and named.
func TestMigrateRenamesTheCacheControl(t *testing.T) {
	out, migrated, changes := migrateString(t, `version: "2.0"
github:
  controls:
    workflowsMustDeclarePermissions:
      enabled: true
    # Cache poisoning
    releaseWorkflowsMustNotRestoreUntrustedCache:
      enabled: false
      publishActions: [pypa/gh-action-pypi-publish]
      cacheActions:
        - {action: actions/cache, mode: always}
      publishScriptPatterns: ['npm publish']
      publishScriptExcludePatterns: ['--dry-run']
      allowedJobs: ['*/lint', 'docs/*']
    pipelineMustNotEnableDebugTrace:
      enabled: true
`)
	if !migrated {
		t.Fatal("want a migration")
	}
	want := `version: "2.0"
github:
  controls:
    workflowsMustDeclarePermissions:
      enabled: true
    # Cache poisoning
    untrustedTriggersMustNotWriteCache:
      enabled: false
    pipelineMustNotEnableDebugTrace:
      enabled: true
`
	if out != want {
		t.Errorf("migrated:\n%s\nwant:\n%s", out, want)
	}
	all := strings.Join(changes, "\n")
	for _, s := range []string{
		"renamed github.controls.releaseWorkflowsMustNotRestoreUntrustedCache to untrustedTriggersMustNotWriteCache",
		"dropped publishActions, cacheActions, publishScriptPatterns, publishScriptExcludePatterns",
		"dropped allowedJobs [*/lint, docs/*]",
		"exemptJobs",
	} {
		if !strings.Contains(all, s) {
			t.Errorf("changes lack %q:\n%s", s, all)
		}
	}
}

// An empty allowedJobs exempted nothing: it is dropped with the other
// fields, with no pointer to exemptJobs.
func TestMigrateDropsAnEmptyAllowedJobsQuietly(t *testing.T) {
	_, _, changes := migrateString(t, `version: "2.0"
github:
  controls:
    releaseWorkflowsMustNotRestoreUntrustedCache:
      enabled: true
      publishActions: [a/b]
      allowedJobs: []
`)
	want := []string{
		"renamed github.controls.releaseWorkflowsMustNotRestoreUntrustedCache to untrustedTriggersMustNotWriteCache",
		"dropped publishActions, allowedJobs (the control no longer detects release jobs)",
	}
	if strings.Join(changes, "\n") != strings.Join(want, "\n") {
		t.Errorf("changes = %q, want %q", changes, want)
	}
}

// When the new key is already there, the old block is dropped, never
// merged into it.
func TestMigrateDropsTheOldCacheControlBesideTheNewOne(t *testing.T) {
	out, migrated, changes := migrateString(t, `version: "2.0"
github:
  controls:
    releaseWorkflowsMustNotRestoreUntrustedCache:
      enabled: true
    untrustedTriggersMustNotWriteCache:
      enabled: true
      exemptJobs: [triage/label]
`)
	if !migrated {
		t.Fatal("want a migration")
	}
	if strings.Contains(out, "releaseWorkflowsMustNotRestoreUntrustedCache") || !strings.Contains(out, "exemptJobs: [triage/label]") {
		t.Errorf("migrated:\n%s", out)
	}
	if len(changes) != 1 || !strings.Contains(changes[0], "already set") {
		t.Errorf("changes = %v", changes)
	}
}

// A v2.0 file with no renamed key is left alone.
func TestMigrateLeavesACurrentFileAlone(t *testing.T) {
	_, migrated, changes := migrateString(t, `version: "2.0"
github:
  controls:
    untrustedTriggersMustNotWriteCache:
      enabled: true
`)
	if migrated || len(changes) != 0 {
		t.Errorf("migrated = %v, changes = %v, want neither", migrated, changes)
	}
}

// The v1 to v2.0 step is unchanged: top-level controls move under
// gitlab.controls and the version is set.
func TestMigrateStillUpgradesAV1File(t *testing.T) {
	out, migrated, changes := migrateString(t, `controls:
  containerImageMustNotUseForbiddenTags:
    enabled: true
`)
	if !migrated || !strings.Contains(out, "gitlab:\n  controls:\n    containerImageMustNotUseForbiddenTags:") || !strings.HasPrefix(out, `version: "2.0"`) {
		t.Errorf("migrated = %v:\n%s", migrated, out)
	}
	if len(changes) != 2 {
		t.Errorf("changes = %v", changes)
	}
}
