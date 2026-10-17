package provider

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	"github.com/getplumber/plumber/capability"
	"github.com/getplumber/plumber/capability/capdecl"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
)

// capturedLog hooks the standard logger (every package logger hangs off it) so a
// test asserts on what the run printed, and restores it afterwards.
func capturedLog(t *testing.T) *logrustest.Hook {
	t.Helper()
	std := logrus.StandardLogger()
	savedLevel, savedHooks := std.GetLevel(), std.Hooks
	std.SetLevel(logrus.DebugLevel)
	hook := logrustest.NewLocal(std)
	t.Cleanup(func() {
		std.ReplaceHooks(savedHooks)
		std.SetLevel(savedLevel)
	})
	return hook
}

// entriesAt returns the messages logged at level.
func entriesAt(hook *logrustest.Hook, level logrus.Level) []string {
	var out []string
	for _, e := range hook.AllEntries() {
		if e.Level == level {
			out = append(out, e.Message)
		}
	}
	return out
}

// platformConf is a platform-mode configuration whose /context served raw as its
// capabilities field ("" is a context without the field, an older platform) and whose
// .plumber.yaml carries file.
func platformConf(raw string, file []capability.Declaration) *configuration.Configuration {
	ctx := &platform.ProjectContext{}
	if raw != "" {
		ctx.Capabilities = json.RawMessage(raw)
	}
	pc := &configuration.PlumberConfig{}
	if file != nil {
		pc.Capabilities = file // the raw key round-trips through yaml.Marshal like a decoded one
	}
	return &configuration.Configuration{
		PlatformRun:   &platform.RunContext{Context: ctx},
		PlumberConfig: pc,
	}
}

// capabilityPipeline has one job per tool the tests below tell apart: gitleaks (in the
// built-in list), an in-house scanner and semgrep (neither built in), and a plain job.
func capabilityPipeline() *control.AnalysisResult {
	return &control.AnalysisResult{Pipeline: &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "leaks", Scripts: []string{"gitleaks detect"}},
		{Name: "corp", Scripts: []string{"scan-secrets --all"}},
		{Name: "sast", Scripts: []string{"semgrep ci"}},
		{Name: "test", Scripts: []string{"make test"}},
	}}}
}

var (
	builtinOnly = []capability.Match{{Kind: "secret_detection", Job: "leaks", Tool: "gitleaks", Evidence: "commands"}}
	inHouseOnly = []capability.Match{{Kind: "secret_detection", Job: "corp", Tool: "in-house", Evidence: "commands"}}
	sastDecl    = `[{"name":"sast","recognizers":[{"tool":"semgrep","commands":["semgrep *"]}]}]`
	inHouseDecl = []capability.Declaration{{Name: "secret_detection", Recognizers: []capdecl.Recognizer{{Tool: "in-house", Commands: []string{"scan-secrets*"}}}}}
)

const servedInForce = "capabilities: the platform's declarations are in force, the .plumber.yaml key is ignored in platform mode"

// Spec 4.2 and 4.6: in platform mode the effective list is built from the served list,
// the built-in list filling in every name it does not declare.
func TestCapabilitiesOf_PlatformServedListFilledByBuiltin(t *testing.T) {
	got := CapabilitiesOf(capabilityPipeline(), platformConf(sastDecl, nil))
	want := []capability.Match{
		{Kind: "secret_detection", Job: "leaks", Tool: "gitleaks", Evidence: "commands"},
		{Kind: "sast", Job: "sast", Tool: "semgrep", Evidence: "commands"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// Spec 4.2: a served declaration carrying a built-in's name replaces it whole, so an
// organization narrows secret_detection to its own tool.
func TestCapabilitiesOf_PlatformServedReplacesBuiltinByName(t *testing.T) {
	raw := `[{"name":"secret_detection","recognizers":[{"tool":"in-house","commands":["scan-secrets*"]}]}]`
	if got := CapabilitiesOf(capabilityPipeline(), platformConf(raw, nil)); !reflect.DeepEqual(got, inHouseOnly) {
		t.Fatalf("got %+v, want only the in-house tool %+v", got, inHouseOnly)
	}
}

// Spec 3 decision 9 and 4.6: in platform mode the served list is the configuration; a
// .plumber.yaml that also carries the key is ignored and gets one info line saying so.
func TestCapabilitiesOf_PlatformIgnoresTheFileKeyWithOneInfoLine(t *testing.T) {
	hook := capturedLog(t)
	got := CapabilitiesOf(capabilityPipeline(), platformConf(sastDecl, inHouseDecl))
	if len(got) != 2 || got[0].Tool != "gitleaks" || got[1].Kind != "sast" {
		t.Fatalf("got %+v, want the served list, not the file's", got)
	}
	if infos := entriesAt(hook, logrus.InfoLevel); !reflect.DeepEqual(infos, []string{servedInForce}) {
		t.Fatalf("info lines = %q, want exactly %q", infos, servedInForce)
	}

	hook.Reset()
	CapabilitiesOf(capabilityPipeline(), platformConf(sastDecl, nil))
	if infos := entriesAt(hook, logrus.InfoLevel); len(infos) != 0 {
		t.Fatalf("info lines = %q, want none without the file key", infos)
	}
}

// Spec 4.6: a context without the field (an older platform), an empty served list or a
// failed /context fetch means the built-in list only; the file key stays ignored in
// platform mode.
func TestCapabilitiesOf_PlatformWithoutServedListUsesBuiltin(t *testing.T) {
	for name, conf := range map[string]*configuration.Configuration{
		"older platform":            platformConf("", inHouseDecl),
		"served empty list":         platformConf(`[]`, nil),
		"served null":               platformConf(`null`, nil),
		"failed context":            {PlatformRun: &platform.RunContext{}},
		"failed context, file list": {PlatformRun: &platform.RunContext{}, PlumberConfig: &configuration.PlumberConfig{Capabilities: inHouseDecl}},
	} {
		if got := CapabilitiesOf(capabilityPipeline(), conf); !reflect.DeepEqual(got, builtinOnly) {
			t.Errorf("%s: got %+v, want the built-in list only %+v", name, got, builtinOnly)
		}
	}
}

// Spec 4.2 and 7: the served list is decoded (tolerantly) and checked against the bounds
// again (the platform validated it already); one that fails either is never half used:
// one warning names the failure and the run falls back to the built-in list, never fails.
// (A recognizer whose only key is unknown is pruned before the bounds are checked, see
// TestCapabilitiesOf_PlatformServedRecognizerWithOnlyUnknownFieldsIsPruned.)
func TestCapabilitiesOf_PlatformInvalidServedListFallsBackToBuiltin(t *testing.T) {
	for name, raw := range map[string]string{
		"malformed name":   `[{"name":"SAST","recognizers":[{"tool":"semgrep","commands":["semgrep *"]}]}]`,
		"duplicate names":  `[{"name":"sast","recognizers":[{"commands":["a"]}]},{"name":"sast","recognizers":[{"commands":["b"]}]}]`,
		"not a json array": `{"name":"sast"}`,
	} {
		t.Run(name, func(t *testing.T) {
			hook := capturedLog(t)
			if got := CapabilitiesOf(capabilityPipeline(), platformConf(raw, nil)); !reflect.DeepEqual(got, builtinOnly) {
				t.Fatalf("got %+v, want the built-in list only %+v", got, builtinOnly)
			}
			if warns := entriesAt(hook, logrus.WarnLevel); len(warns) != 1 {
				t.Fatalf("warnings = %q, want exactly one", warns)
			}
		})
	}
}

// Spec 4.6 (ruling: the served list is decoded tolerantly): a platform newer than the CLI
// may serve a recognizer field the CLI does not know yet; the CLI ignores that key and
// keeps the fields it knows, rather than dropping the whole list.
func TestCapabilitiesOf_PlatformServedListToleratesUnknownKeys(t *testing.T) {
	hook := capturedLog(t)
	raw := `[{"name":"sast","future":true,"recognizers":[{"tool":"semgrep","commands":["semgrep *"],"github_actions":["semgrep/semgrep-action@*"]}]}]`
	got := CapabilitiesOf(capabilityPipeline(), platformConf(raw, nil))
	want := []capability.Match{
		{Kind: "secret_detection", Job: "leaks", Tool: "gitleaks", Evidence: "commands"},
		{Kind: "sast", Job: "sast", Tool: "semgrep", Evidence: "commands"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want the known patterns kept %+v", got, want)
	}
	if warns := entriesAt(hook, logrus.WarnLevel); len(warns) != 0 {
		t.Fatalf("warnings = %q, want none for an unknown served key", warns)
	}
}

// Spec 4.2 and 7: the .plumber.yaml declarations are checked against the same bounds as
// the served list; a list that fails them is never half used: one warning naming the
// violation, the built-in list alone, and the run goes on.
func TestCapabilitiesOf_StandaloneInvalidFileListFallsBackToBuiltin(t *testing.T) {
	hook := capturedLog(t)
	file := []capability.Declaration{{Name: "SAST", Recognizers: []capdecl.Recognizer{{Tool: "semgrep", Commands: []string{"semgrep *"}}}}}
	got := CapabilitiesOf(capabilityPipeline(), &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{Capabilities: file}})
	if !reflect.DeepEqual(got, builtinOnly) {
		t.Fatalf("got %+v, want the built-in list only %+v", got, builtinOnly)
	}
	var warns []*logrus.Entry
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			warns = append(warns, e)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("warnings = %d, want exactly one", len(warns))
	}
	if err, _ := warns[0].Data[logrus.ErrorKey].(error); err == nil || !strings.Contains(err.Error(), "a capability name must be 1 to 64 bytes") {
		t.Fatalf("warning %q error = %v, want the violation named", warns[0].Message, warns[0].Data[logrus.ErrorKey])
	}
}

// Spec 4.3: a pattern that does not compile is skipped with one warning line through the
// CLI's logger; the rest of the list keeps working.
func TestCapabilitiesOf_UncompilablePatternWarnsAndIsSkipped(t *testing.T) {
	hook := capturedLog(t)
	file := []capability.Declaration{{Name: "sast", Recognizers: []capdecl.Recognizer{{Tool: "semgrep", Commands: []string{"semgrep [", "semgrep *"}}}}}
	got := CapabilitiesOf(capabilityPipeline(), &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{Capabilities: file}})
	if len(got) != 2 || got[1] != (capability.Match{Kind: "sast", Job: "sast", Tool: "semgrep", Evidence: "commands"}) {
		t.Fatalf("got %+v, want the compilable pattern to still match", got)
	}
	warns := entriesAt(hook, logrus.WarnLevel)
	if len(warns) != 1 || !strings.Contains(warns[0], "semgrep [") {
		t.Fatalf("warnings = %q, want one naming the pattern", warns)
	}
}

// Spec 4.6: a standalone run reads the .plumber.yaml key, the built-in list filling in;
// without the key it is the built-in list alone. No pipeline, nothing at all.
func TestCapabilitiesOf_StandaloneFileListOrBuiltin(t *testing.T) {
	withFile := CapabilitiesOf(capabilityPipeline(), &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{Capabilities: inHouseDecl}})
	if !reflect.DeepEqual(withFile, inHouseOnly) {
		t.Fatalf("with the file key = %+v, want %+v", withFile, inHouseOnly)
	}
	for name, conf := range map[string]*configuration.Configuration{
		"no file key":    {PlumberConfig: &configuration.PlumberConfig{}},
		"no config":      {},
		"no conf at all": nil,
	} {
		if got := CapabilitiesOf(capabilityPipeline(), conf); !reflect.DeepEqual(got, builtinOnly) {
			t.Errorf("%s: got %+v, want the built-in list only %+v", name, got, builtinOnly)
		}
	}
	if got := CapabilitiesOf(&control.AnalysisResult{}, nil); got != nil {
		t.Fatalf("no pipeline = %+v, want nil", got)
	}
	if got := CapabilitiesOf(nil, nil); got != nil {
		t.Fatalf("nil result = %+v, want nil", got)
	}
}

// Wrapper scripts are read off disk only when the checkout IS the analyzed
// project at the analyzed ref, the same two gates the CI-file read and the
// config digest use (control/task.go, cmd/platform_mode.go). Otherwise a
// script of whatever repository the CLI stands in would become wrapper_script
// evidence for another project. Image and command evidence need no checkout
// and keep working either way. The ref gate reads the CI environment, so the
// test sets it with t.Setenv rather than building a repository.
func TestCapabilitiesOf_WrapperScriptsOnlyFromTheAnalyzedCheckoutAtItsRef(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ci"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ci", "scan.sh"), []byte("#!/bin/sh\ntrufflehog filesystem .\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := &control.AnalysisResult{Pipeline: &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Name: "image", Image: &ir.Image{Registry: "docker.io", Name: "zricethezav/gitleaks"}},
		{Name: "command", Scripts: []string{"gitleaks detect"}},
		{Name: "wrapper", Scripts: []string{"./ci/scan.sh"}},
	}}}
	withWrapper := []capability.Match{
		{Kind: "secret_detection", Job: "command", Tool: "gitleaks", Evidence: "commands"},
		{Kind: "secret_detection", Job: "image", Tool: "gitleaks", Evidence: "images"},
		{Kind: "secret_detection", Job: "wrapper", Tool: "trufflehog", Evidence: "wrapper_script"},
	}
	withoutWrapper := withWrapper[:2]

	t.Setenv("CI", "true")
	t.Setenv("CI_COMMIT_REF_NAME", "main")

	t.Run("the analyzed project at its ref", func(t *testing.T) {
		got := CapabilitiesOf(result, &configuration.Configuration{GitRepoRoot: root, CheckoutIsAnalyzedProject: true, Branch: "main"})
		if !reflect.DeepEqual(got, withWrapper) {
			t.Fatalf("got %+v, want %+v", got, withWrapper)
		}
	})
	t.Run("the checkout is another project", func(t *testing.T) {
		got := CapabilitiesOf(result, &configuration.Configuration{GitRepoRoot: root, CheckoutIsAnalyzedProject: false, Branch: "main"})
		if !reflect.DeepEqual(got, withoutWrapper) {
			t.Fatalf("got %+v, want no wrapper evidence %+v", got, withoutWrapper)
		}
	})
	t.Run("the checkout is at another ref", func(t *testing.T) {
		got := CapabilitiesOf(result, &configuration.Configuration{GitRepoRoot: root, CheckoutIsAnalyzedProject: true, Branch: "release"})
		if !reflect.DeepEqual(got, withoutWrapper) {
			t.Fatalf("got %+v, want no wrapper evidence %+v", got, withoutWrapper)
		}
	})
}

// Spec 4.6 (the served list is decoded tolerantly): a recognizer the platform accepted with
// only fields this CLI does not know (a future github_actions, or a key the CLI cannot read)
// carries no pattern here. It is pruned, with one debug line naming the capability and the
// recognizer index, before the bounds are checked, so the rest of the org list stays in
// force instead of the whole list falling back to the built-in one.
func TestCapabilitiesOf_PlatformServedRecognizerWithOnlyUnknownFieldsIsPruned(t *testing.T) {
	t.Run("the known recognizer is kept", func(t *testing.T) {
		hook := capturedLog(t)
		raw := `[{"name":"sast","recognizers":[{"tool":"semgrep-action","github_actions":["semgrep/semgrep-action@*"]},{"tool":"semgrep","commands":["semgrep *"]}]}]`
		got := CapabilitiesOf(capabilityPipeline(), platformConf(raw, nil))
		want := []capability.Match{
			{Kind: "secret_detection", Job: "leaks", Tool: "gitleaks", Evidence: "commands"},
			{Kind: "sast", Job: "sast", Tool: "semgrep", Evidence: "commands"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want the known recognizer kept %+v", got, want)
		}
		if warns := entriesAt(hook, logrus.WarnLevel); len(warns) != 0 {
			t.Fatalf("warnings = %q, want none", warns)
		}
		var pruned []*logrus.Entry
		for _, e := range hook.AllEntries() {
			if e.Level == logrus.DebugLevel && strings.Contains(e.Message, "pruned") {
				pruned = append(pruned, e)
			}
		}
		if len(pruned) != 1 || pruned[0].Data["capability"] != "sast" || pruned[0].Data["recognizer"] != 0 {
			t.Fatalf("pruned debug lines = %+v, want one naming capability sast and recognizer 0", pruned)
		}
	})
	t.Run("a capability left without a recognizer keeps its name and matches nothing", func(t *testing.T) {
		hook := capturedLog(t)
		raw := `[{"name":"secret_detection","recognizers":[{"tool":"gitleaks-action","github_actions":["gitleaks/gitleaks-action@*"]}]}]`
		if got := CapabilitiesOf(capabilityPipeline(), platformConf(raw, nil)); len(got) != 0 {
			t.Fatalf("got %+v, want nothing: the served name still replaces the built-in", got)
		}
		if warns := entriesAt(hook, logrus.WarnLevel); len(warns) != 0 {
			t.Fatalf("warnings = %q, want none", warns)
		}
	})
	t.Run("a recognizer whose only key is a typo is pruned too", func(t *testing.T) {
		hook := capturedLog(t)
		raw := `[{"name":"sast","recognizers":[{"tool":"semgrep","command":["semgrep *"]}]}]`
		if got := CapabilitiesOf(capabilityPipeline(), platformConf(raw, nil)); !reflect.DeepEqual(got, builtinOnly) {
			t.Fatalf("got %+v, want sast to match nothing and the built-in secret_detection %+v", got, builtinOnly)
		}
		if warns := entriesAt(hook, logrus.WarnLevel); len(warns) != 0 {
			t.Fatalf("warnings = %q, want none", warns)
		}
	})
}

// fileConf is a standalone configuration whose .plumber.yaml is text, loaded the way the
// run loads it (LoadPlumberConfigFromBytes), which must never fail on the capabilities key.
func fileConf(t *testing.T, text string) *configuration.Configuration {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte("version: \"2.0\"\n"+text), "test")
	if err != nil {
		t.Fatalf("the configuration load must never fail on the capabilities key: %v", err)
	}
	return &configuration.Configuration{PlumberConfig: pc}
}

// Spec 4.2 and 7: the .plumber.yaml key is decoded strictly when the effective list is
// built; a typo key, a wrong-typed field, a map instead of a list or a list over the bounds
// is never half applied and never fails the run: one warning naming the error, the
// built-in list alone.
func TestCapabilitiesOf_StandaloneMalformedFileKeyFallsBackToBuiltin(t *testing.T) {
	var over strings.Builder
	over.WriteString("capabilities:\n")
	for i := 0; i < 51; i++ {
		fmt.Fprintf(&over, "  - name: c%d\n    recognizers: [{commands: [\"a\"]}]\n", i)
	}
	for name, tc := range map[string]struct{ text, says string }{
		"typo key":          {"capabilities:\n  - name: secret_detection\n    recognizers:\n      - tool: in-house\n        command: [\"scan-secrets*\"]\n", "command"},
		"wrong-typed field": {"capabilities:\n  - name: secret_detection\n    recognizers:\n      - tool: in-house\n        images: \"*foo*\"\n", "unmarshal"},
		"a map, not a list": {"capabilities:\n  name: secret_detection\n", "unmarshal"},
		"over the bounds":   {over.String(), "at most 50 capabilities"},
	} {
		t.Run(name, func(t *testing.T) {
			conf := fileConf(t, tc.text)
			hook := capturedLog(t)
			if got := CapabilitiesOf(capabilityPipeline(), conf); !reflect.DeepEqual(got, builtinOnly) {
				t.Fatalf("got %+v, want the built-in list only %+v", got, builtinOnly)
			}
			var warns []*logrus.Entry
			for _, e := range hook.AllEntries() {
				if e.Level == logrus.WarnLevel {
					warns = append(warns, e)
				}
			}
			if len(warns) != 1 {
				t.Fatalf("warnings = %d, want exactly one", len(warns))
			}
			if err, _ := warns[0].Data[logrus.ErrorKey].(error); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("warning error = %v, want it to name %q", warns[0].Data[logrus.ErrorKey], tc.says)
			}
		})
	}
	t.Run("a good file still works", func(t *testing.T) {
		conf := fileConf(t, "capabilities:\n  - name: secret_detection\n    recognizers:\n      - tool: in-house\n        commands: [\"scan-secrets*\"]\n")
		if got := CapabilitiesOf(capabilityPipeline(), conf); !reflect.DeepEqual(got, inHouseOnly) {
			t.Fatalf("got %+v, want %+v", got, inHouseOnly)
		}
	})
}

// Spec 4.6: in platform mode a malformed .plumber.yaml key never fails the load nor the
// run; the served list is the configuration, the key gets its one info line, no warning.
func TestCapabilitiesOf_PlatformMalformedFileKeyIsIgnored(t *testing.T) {
	conf := fileConf(t, "capabilities:\n  name: secret_detection\n")
	conf.PlatformRun = &platform.RunContext{Context: &platform.ProjectContext{Capabilities: json.RawMessage(sastDecl)}}
	hook := capturedLog(t)
	got := CapabilitiesOf(capabilityPipeline(), conf)
	if len(got) != 2 || got[1].Kind != "sast" {
		t.Fatalf("got %+v, want the served list", got)
	}
	if warns := entriesAt(hook, logrus.WarnLevel); len(warns) != 0 {
		t.Fatalf("warnings = %q, want none", warns)
	}
	if infos := entriesAt(hook, logrus.InfoLevel); !reflect.DeepEqual(infos, []string{servedInForce}) {
		t.Fatalf("info lines = %q, want exactly %q", infos, servedInForce)
	}
}

// Spec 4.2, the disable gesture: a declaration of a built-in's name with no recognizer
// switches the built-in off, from either source; a job the built-in would recognize yields
// nothing.
func TestCapabilitiesOf_DisableGestureSwitchesTheBuiltinOff(t *testing.T) {
	file := fileConf(t, "capabilities:\n  - name: secret_detection\n    recognizers: []\n")
	if got := CapabilitiesOf(capabilityPipeline(), file); len(got) != 0 {
		t.Fatalf("file: got %+v, want nothing", got)
	}
	served := platformConf(`[{"name":"secret_detection","recognizers":[]}]`, nil)
	if got := CapabilitiesOf(capabilityPipeline(), served); len(got) != 0 {
		t.Fatalf("served: got %+v, want nothing", got)
	}
}
