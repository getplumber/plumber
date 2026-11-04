package cmd

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// uncomment strips a leading YAML comment marker and the whitespace
// around it, so a documentation block written as "# contents: read"
// reads the same as a live "contents: read" line. action.yml is a
// composite action and cannot declare a real permissions block (that is
// the calling workflow's job), so it documents the one the README's
// snippet carries as a commented block instead; the scan below reads
// either shape.
func uncomment(trimmed string) string {
	trimmed = strings.TrimPrefix(trimmed, "#")
	return strings.TrimSpace(trimmed)
}

// permissionsBlockHasScopes reads path line by line and reports whether a
// "permissions:" block, live or documented as a comment, contains both
// an "actions: read" line and a "contents: read" line before the block
// ends (a line back at the block's own indentation, or less, that is not
// one of its scope lines). A line-based scan is enough here: every file
// keeps the block as a short, flat list of "<scope>: <level>" lines.
func permissionsBlockHasScopes(path string) (hasActions, hasContents bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = f.Close() }()

	inBlock := false
	blockIndent := -1
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		indent := len(line) - len(strings.TrimLeft(line, " \t#"))
		trimmed := uncomment(strings.TrimSpace(line))
		if trimmed == "" {
			continue
		}
		if trimmed == "permissions:" {
			inBlock, blockIndent = true, indent
			continue
		}
		if !inBlock {
			continue
		}
		if indent <= blockIndent {
			// Back at or above the block's own indentation: it is over.
			inBlock = false
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "actions:") && strings.Contains(trimmed, "read"):
			hasActions = true
		case strings.HasPrefix(trimmed, "contents:") && strings.Contains(trimmed, "read"):
			hasContents = true
		}
	}
	return hasActions, hasContents, scanner.Err()
}

// TestActionTemplateGrantsActionsRead pins the shape no existing scripts
// test covers: action.yml's composite steps run against the GitHub API
// (workflow states, runs, one job log) through the token the calling
// workflow supplies, so both the action's own description (README.md's
// GitHub snippet, the one new contributors copy) and the action.yml
// metadata that documents it must keep naming "actions: read" next to
// "contents: read". Only README.md carries the actual permissions block
// a workflow copies (action.yml is a composite action and cannot declare
// permissions for its caller), so this test reads both files for it.
func TestActionTemplateGrantsActionsRead(t *testing.T) {
	for _, path := range []string{"../action.yml", "../README.md"} {
		hasActions, hasContents, err := permissionsBlockHasScopes(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !hasContents {
			t.Errorf("%s: permissions: block is missing contents: read", path)
		}
		if !hasActions {
			t.Errorf("%s: permissions: block is missing actions: read", path)
		}
	}
}

// TestActionMissingLockfileOnlyWarns pins the split in action.yml between
// a repository with no workflow lockfile, which gets a warning and keeps
// going, and a lockfile that fails verification, which fails the job. The
// logic lives in the composite action's run: blocks, so the test reads
// the shape of the file: the verify step warns and records "missing", the
// skip branches record "skipped", and the Enforce gate step only exits 1
// on "failed" and "error", the statuses that must fail the job.
func TestActionMissingLockfileOnlyWarns(t *testing.T) {
	raw, err := os.ReadFile("../action.yml")
	if err != nil {
		t.Fatalf("reading action.yml: %v", err)
	}
	action := string(raw)

	_, verify, found := strings.Cut(action, "- name: Verify workflow lockfile")
	if !found {
		t.Fatal("action.yml has no Verify workflow lockfile step")
	}
	skips, afterSkips, found := strings.Cut(verify, `if [ ! -f "$lockfile" ]; then`)
	if !found {
		t.Fatal("the verify step has no lockfile presence check")
	}
	missing, _, found := strings.Cut(afterSkips, "\n        fi\n")
	if !found {
		t.Fatal("the lockfile presence check has no closing fi")
	}

	if got := strings.Count(skips, "status skipped"); got != 2 {
		t.Errorf("the project and GHES branches must record status skipped, found %d", got)
	}
	if !strings.Contains(missing, `echo "::warning file=${lockfile}::No workflow lockfile`) {
		t.Error("the verify step must emit a ::warning when the lockfile is missing")
	}
	if strings.Contains(missing, "::error") {
		t.Error("the verify step must not emit an ::error when the lockfile is missing")
	}
	if !strings.Contains(missing, "status missing") {
		t.Error("the verify step must record status missing when the lockfile is missing")
	}
	for _, status := range []string{"status failed", "status error"} {
		if strings.Contains(missing, status) {
			t.Errorf("a missing lockfile must not record %q: the Enforce gate would fail the job", status)
		}
	}

	_, gate, found := strings.Cut(action, "- name: Enforce gate")
	if !found {
		t.Fatal("action.yml has no Enforce gate step")
	}
	_, afterCase, found := strings.Cut(gate, `case "${LOCKFILE_STATUS:-}" in`)
	if !found {
		t.Fatal("the Enforce gate has no lockfile status case")
	}
	arms, _, found := strings.Cut(afterCase, "esac")
	if !found {
		t.Fatal("the Enforce gate's lockfile status case has no esac")
	}
	for _, status := range []string{"failed)", "error)"} {
		if !strings.Contains(arms, status) {
			t.Errorf("the Enforce gate must fail the job on lockfile status %q", status)
		}
	}
	for _, status := range []string{"missing)", "skipped)", "passed)", "*)"} {
		if strings.Contains(arms, status) {
			t.Errorf("the Enforce gate must not act on lockfile status %q", status)
		}
	}
	if got := strings.Count(arms, "exit 1"); got != 2 {
		t.Errorf("the Enforce gate must exit 1 on failed and error only, found %d exits", got)
	}
}
