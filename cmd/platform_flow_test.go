package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/platform"
)

// pushServer answers the push with the given body and records the request.
func pushServer(t *testing.T, status int, body string, got *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*got = b
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// Spec s2-s4 end to end: two policies, one blocking; the log carries both
// sections and the verdict; the exit is the platform's; the push carries
// exactly the two policy entries and no local one.
func TestPlatformFlow_TwoPoliciesOneBlocking(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint := printOutput
	printOutput = true
	defer func() { printOutput = origPrint }()
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	prod := policyWithTree("Prod", "pipelineMustNotUseDockerInDocker", `{"enabled":true}`)
	prod.Enforcement = platform.EnforcementBlock
	eighty := 80
	prod.MinPoints = &eighty
	conf := confWithPolicies(t, a, prod)
	var pushed []byte
	srv := pushServer(t, 200, `{"gate":{"evaluated":true,"blocking":true,"policies":[{"id":"`+a.ID+`","name":"A","enforcement":"report","blocking":false,"live_fail_count":1},{"id":"`+prod.ID+`","name":"Prod","enforcement":"block","blocking":true,"live_fail_count":0}]},"global_score":{"letter":"B","points":83}}`, &pushed)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	var err error
	out := captureStdoutAll(t, func() {
		_ = captureStderr(t, func() {
			err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf)
		})
	})
	var gateErr *PlatformGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("exit must be the platform's blocking verdict, got %v", err)
	}
	assertContains(t, out, "== Policy: A  [report]")
	assertContains(t, out, "== Policy: Prod  [block, min_points 80]")
	assertContains(t, out, "== Platform verdict")
	assertContains(t, out, "Global score (platform): B  83 / 100 pts")
	assertContains(t, out, "Exit 1: Prod blocks")
	// The local Summary block is the whole thing platform mode replaces: its
	// Status line and the gate sentence beside it ("... required ≥ 100 pts")
	// are the only two strings that carry a LOCAL verdict. The bare word
	// "required" is not usable as the marker: it is also part of two control
	// display names ("Pipeline must include required components") that a
	// policy section legitimately lists.
	if strings.Contains(out, "  Status: ") || strings.Contains(out, "required ≥") {
		t.Fatal("the local gate line must not be printed in platform mode")
	}
	var push struct {
		Results []struct {
			Policy   string `json:"policy"`
			PolicyID string `json:"policy_id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(pushed, &push); err != nil || len(push.Results) != 2 || push.Results[0].Policy != "A" || push.Results[1].Policy != "Prod" {
		t.Fatalf("push results: %s (err %v)", pushed, err)
	}
	// The gate the renderer explained is keyed on ids, and so is the push:
	// if the two sets ever diverge the verdict block would attribute one
	// policy's numbers to another. Same ids, same order.
	for i, want := range []string{a.ID, prod.ID} {
		if push.Results[i].PolicyID != want {
			t.Errorf("pushed result %d has policy_id %q, want the gated policy's own id %q", i, push.Results[i].PolicyID, want)
		}
	}
}

// Spec s4: zero policies (context failed) evaluates nothing, prints the notice,
// exits 0, and never pushes.
func TestPlatformFlow_NoPolicies_NothingEvaluatedNoPush(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint := printOutput
	printOutput = true
	defer func() { printOutput = origPrint }()
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = testDefaultPlumberConfig(t)
	conf.PlatformRun = &platform.RunContext{Endpoint: "https://platform.example.com", ProjectPath: "g/p", ContextErr: errors.New("dial tcp: connection refused")}
	pushed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { pushed = true }))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	var err error
	out := captureStdoutAll(t, func() {
		_ = captureStderr(t, func() { err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf) })
	})
	if err != nil {
		t.Fatalf("want exit 0, got %v", err)
	}
	assertContains(t, out, "no policy resolved for g/p (dial tcp: connection refused), nothing evaluated")
	if strings.Contains(out, "Plumber Score") || pushed {
		t.Fatalf("nothing may be evaluated or pushed: banner=%v pushed=%v", strings.Contains(out, "Plumber Score"), pushed)
	}
}

// Spec s1: a local threshold and a local file change nothing but the notices.
func TestPlatformFlow_LocalThresholdIgnored(t *testing.T) {
	newGateFlagsCmd(t)
	minPointsSet, minPoints = true, 100
	a := policyWithTree("A", "pipelineMustNotUseDockerInDocker", `{"enabled":true}`) // no finding under this policy
	conf := confWithPolicies(t, a)
	var pushed []byte
	srv := pushServer(t, 200, `{"gate":{"evaluated":true,"blocking":false,"policies":[{"id":"`+a.ID+`","name":"A","enforcement":"report","blocking":false,"live_fail_count":0}]},"global_score":{"letter":"A","points":100}}`, &pushed)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()
	var err error
	_ = captureStdoutAll(t, func() {
		_ = captureStderr(t, func() { err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf) })
	})
	if err != nil {
		t.Fatalf("the debug-trace finding is not in policy A and min-points is inert: want exit 0, got %v", err)
	}
}

// The GitLab entry point, with collection stubbed: everything after p.Run is
// the production path (#467's stubRunProvider in cmd/platform_push_test.go).
// Same two policies as above; asserts the same verdict and the same push.
func TestPlatformFlow_RunWithProvider_TwoPolicies(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint := printOutput
	printOutput = true
	defer func() { printOutput = origPrint }()
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	prod := policyWithTree("Prod", "pipelineMustNotUseDockerInDocker", `{"enabled":true}`)
	prod.Enforcement = platform.EnforcementBlock
	conf := confWithPolicies(t, a, prod)
	var pushed []byte
	srv := pushServer(t, 200, `{"gate":{"evaluated":true,"blocking":true,"policies":[{"id":"`+a.ID+`","name":"A","enforcement":"report","blocking":false,"live_fail_count":1},{"id":"`+prod.ID+`","name":"Prod","enforcement":"block","blocking":true,"live_fail_count":0}]},"global_score":{"letter":"B","points":83}}`, &pushed)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()
	var err error
	out := captureStdoutAll(t, func() {
		_ = captureStderr(t, func() {
			err = runWithProvider(stubRunProvider{Provider: testProvider(t), result: debugTraceResult()}, nil, conf, nil, nil)
		})
	})
	var gateErr *PlatformGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("exit must be the platform's blocking verdict, got %v", err)
	}
	assertContains(t, out, "== Policy: Prod  [block]")
	assertContains(t, out, "Exit 1: Prod blocks")
	if !strings.Contains(string(pushed), `"policy":"Prod"`) {
		t.Fatalf("push must carry the Prod entry: %s", pushed)
	}
}

// --no-controls is inventory-only and evaluates nothing under ANY mode, so it
// keeps today's sequence even under --platform: the artifacts are still
// written and publishAndFinalize's no-controls guards still run. Routing it
// down the platform branch instead would return from runPlatformMode on a
// zero-policy run and skip both - a CI-less project would exit 0 with no
// inventory and no diagnosis.
func TestPlatformFlow_NoControlsKeepsTheInventoryGuardsUnderPlatform(t *testing.T) {
	origPrint, origNoControls := printOutput, noControls
	printOutput = true
	defer func() { printOutput, noControls = origPrint, origNoControls }()

	// conf.PlatformRun resolves nothing, which is what makes the bug
	// reachable: with a policy the platform branch would push instead.
	newConf := func(t *testing.T) *configuration.Configuration {
		t.Helper()
		conf := configuration.NewDefaultConfiguration()
		conf.PlumberConfig = testDefaultPlumberConfig(t)
		conf.NoControls = true
		conf.PlatformRun = &platform.RunContext{Endpoint: "https://platform.example.com", ProjectPath: "g/p", ContextErr: errors.New("dial tcp: connection refused")}
		return conf
	}

	t.Run("an unusable CI still fails with IncompleteDataError and pushes nothing", func(t *testing.T) {
		newGateFlagsCmd(t)
		noControls = true
		pushed := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { pushed = true }))
		defer srv.Close()
		restore := withPlatformTestEnv(t, srv.URL, "tok")
		defer restore()

		var err error
		_ = captureStdoutAll(t, func() {
			_ = captureStderr(t, func() {
				err = presentResultWithProvider(testProvider(t), nil, &control.AnalysisResult{CiMissing: true}, newConf(t))
			})
		})

		var incomplete *IncompleteDataError
		if !errors.As(err, &incomplete) {
			t.Fatalf("err = %v, want *IncompleteDataError: a --no-controls run over a CI-less project must not exit 0 with an empty inventory", err)
		}
		if pushed {
			t.Fatal("a --no-controls run publishes nothing, platform push included")
		}
	})

	t.Run("a usable CI inventories, evaluates nothing and pushes nothing", func(t *testing.T) {
		newGateFlagsCmd(t)
		noControls = true
		pushed := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { pushed = true }))
		defer srv.Close()
		restore := withPlatformTestEnv(t, srv.URL, "tok")
		defer restore()

		var err error
		out := captureStdoutAll(t, func() {
			_ = captureStderr(t, func() {
				err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), newConf(t))
			})
		})

		if err != nil {
			t.Fatalf("err = %v, want nil: an inventory run over a valid CI succeeds", err)
		}
		if pushed {
			t.Fatal("a --no-controls run publishes nothing, platform push included")
		}
		if strings.Contains(out, "== Policy") {
			t.Fatalf("--no-controls evaluated nothing, so no policy section may be rendered:\n%s", out)
		}
		assertContains(t, out, "no controls requested, nothing to score")
	})
}

// Spec s4 + ruling: a degraded collection is pushed and the verdict decides.
func TestPlatformFlow_DegradedIsPushedNotExit3(t *testing.T) {
	newGateFlagsCmd(t)
	a := policyWithTree("A", "pipelineMustNotUseDockerInDocker", `{"enabled":true}`)
	conf := confWithPolicies(t, a)
	result := debugTraceResult()
	result.DataCollectionDegraded, result.DegradedReasons = true, []string{"merged CI fetch failed"}
	var pushed []byte
	srv := pushServer(t, 200, `{"gate":{"evaluated":true,"blocking":false,"policies":[]}}`, &pushed)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()
	var err error
	_ = captureStdoutAll(t, func() {
		_ = captureStderr(t, func() { err = presentResultWithProvider(testProvider(t), nil, result, conf) })
	})
	if err != nil {
		t.Fatalf("degraded in platform mode: want the platform's non-blocking verdict (exit 0), got %v", err)
	}
	if !strings.Contains(string(pushed), `"degraded":true`) {
		t.Fatalf("the push must carry collection.degraded: %s", pushed)
	}
}

// Spec s5 end to end: with --output set, the file a platform-mode run leaves
// behind carries one entry per policy and the PLATFORM's global score. It is
// the ordering that makes this reachable: the artifacts are written after the
// push, because before it there is no score that may be written at all.
func TestPlatformFlow_OutputFileCarriesThePoliciesAndTheGlobalScore(t *testing.T) {
	newGateFlagsCmd(t)
	origOutput := outputFile
	defer func() { outputFile = origOutput }()
	outputFile = filepath.Join(t.TempDir(), "analysis.json")

	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	prod := policyWithTree("Prod", "pipelineMustNotUseDockerInDocker", `{"enabled":true}`)
	prod.Enforcement = platform.EnforcementBlock
	conf := confWithPolicies(t, a, prod)
	var pushed []byte
	srv := pushServer(t, 200, `{"gate":{"evaluated":true,"blocking":false,"policies":[{"id":"`+a.ID+`","name":"A","enforcement":"report","blocking":false,"live_fail_count":0}]},"global_score":{"letter":"B","points":83}}`, &pushed)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	var err error
	_ = captureStdoutAll(t, func() {
		_ = captureStderr(t, func() { err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf) })
	})
	if err != nil {
		t.Fatalf("want the platform's non-blocking verdict (exit 0), got %v", err)
	}
	if len(pushed) == 0 {
		t.Fatal("the push must happen before the artifacts are written")
	}

	raw, readErr := os.ReadFile(outputFile)
	if readErr != nil {
		t.Fatalf("read the report: %v", readErr)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("the report is not valid JSON: %v", err)
	}
	policies, ok := report["policies"].([]any)
	if !ok || len(policies) != 2 {
		t.Fatalf("policies: %#v", report["policies"])
	}
	names := []string{}
	for _, p := range policies {
		entry, _ := p.(map[string]any)
		names = append(names, entry["name"].(string))
	}
	if names[0] != "A" || names[1] != "Prod" {
		t.Fatalf("policy entries = %v, want [A Prod] in /context order", names)
	}
	score, ok := report["plumberScore"].(map[string]any)
	if !ok || score["letter"] != "B" || score["points"] != 83.0 {
		t.Fatalf("plumberScore must be the platform's global score, got %#v", report["plumberScore"])
	}
	if _, present := report["minPoints"]; present {
		t.Error("no local gate ran, so no local gate key may be written")
	}
}

// The collection-truth diagnostics are facts about what was collected, not a
// verdict, so platform mode keeps every one of them: CI configuration errors
// explain why an inventory is thin, and the tier caveats explain why a
// control could not be checked on this GitLab plan. Dropping them turned a
// diagnosable run into a silent one (spec s3 renders today's control blocks;
// these are part of that report).
func TestPlatformFlow_CollectionDiagnosticsAreStillPrinted(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint := printOutput
	printOutput = true
	defer func() { printOutput = origPrint }()
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	conf := confWithPolicies(t, a)
	result := debugTraceResult()
	result.CiErrors = []string{"boom"}
	result.ApprovalRulesTierCaveat = true
	result.MRApprovalSettingsTierCaveat = true
	result.MRSettingsPremiumCaveatFields = []string{"mergeTrainsEnabled"}
	result.SecurityPolicyTierCaveat = true
	var pushed []byte
	srv := pushServer(t, 200, `{"gate":{"evaluated":true,"blocking":false,"policies":[]}}`, &pushed)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	var err error
	out := captureStdoutAll(t, func() {
		_ = captureStderr(t, func() { err = presentResultWithProvider(testProvider(t), nil, result, conf) })
	})

	if err != nil {
		t.Fatalf("the gate did not block: want exit 0, got %v", err)
	}
	assertContains(t, out, "CI configuration errors:")
	assertContains(t, out, "boom")
	assertContains(t, out, "MR approval rules are a GitLab Premium/Ultimate feature.")
	assertContains(t, out, "MR approval settings are a GitLab Premium/Ultimate feature.")
	assertContains(t, out, "mergeTrainsEnabled")
	assertContains(t, out, "Security policies are a GitLab Ultimate feature")
}

// Spec s4: --fail-warnings is one of the two exit sources platform mode
// keeps, and a run that resolved no policy is no exception. Returning a bare
// nil there made the opt-in silently inert on exactly the runs (an
// unreachable platform, an unassigned project) where the warnings are the
// only thing the operator has left.
func TestPlatformFlow_NoPolicies_FailWarningsStillDecidesTheExit(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint, origFail := printOutput, failWarnings
	printOutput = true
	defer func() { printOutput, failWarnings = origPrint, origFail }()

	newConf := func(t *testing.T) *configuration.Configuration {
		t.Helper()
		conf := configuration.NewDefaultConfiguration()
		conf.PlumberConfig = testDefaultPlumberConfig(t)
		conf.PlatformRun = &platform.RunContext{
			Endpoint:    "https://platform.example.com",
			ProjectPath: "g/p",
			ContextErr:  errors.New("dial tcp: connection refused"),
		}
		return conf
	}
	run := func(t *testing.T, warnings []string) error {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("a run that resolved no policy must never push")
		}))
		defer srv.Close()
		restore := withPlatformTestEnv(t, srv.URL, "tok")
		defer restore()
		result := debugTraceResult()
		result.Warnings = warnings
		var err error
		_ = captureStdoutAll(t, func() {
			_ = captureStderr(t, func() { err = presentResultWithProvider(testProvider(t), nil, result, newConf(t)) })
		})
		return err
	}

	t.Run("warnings exist", func(t *testing.T) {
		failWarnings = true
		err := run(t, []string{"could not verify the default branch"})
		var degraded *DegradedError
		if !errors.As(err, &degraded) {
			t.Fatalf("err = %v, want a *DegradedError: --fail-warnings is a data-quality opt-in, not a score gate", err)
		}
	})

	t.Run("no warnings still exits 0", func(t *testing.T) {
		failWarnings = true
		if err := run(t, nil); err != nil {
			t.Fatalf("err = %v, want nil: nothing was evaluated and there is nothing to warn about", err)
		}
	})

	t.Run("without the opt-in nothing fails", func(t *testing.T) {
		failWarnings = false
		if err := run(t, []string{"could not verify the default branch"}); err != nil {
			t.Fatalf("err = %v, want nil: warnings alone never fail a run", err)
		}
	})
}

// Row 63, the flow half: a LINKED run whose platform answered and resolved
// no policy used to return before the push, so the run was lost entirely -
// the platform kept showing the PREVIOUS run as the project's current one,
// and freshness lied about a project that had just been analysed. It now
// goes through the same publishRun path as any other push, carrying the
// nothing-evaluated marker and no result, and the platform's own gate answer
// is what decides the exit code. Nothing local is invented at either end.
func TestRunPlatformMode_Row63_ZeroPoliciesStillPushes(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint := printOutput
	printOutput = true
	defer func() { printOutput = origPrint }()

	var reqs []string
	var pushed []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqs = append(reqs, r.Method+" "+r.URL.Path)
		pushed = b
		w.WriteHeader(http.StatusAccepted)
		// What the platform answers a run it recorded as not evaluable: no
		// verdict, and the reason echoed back.
		_, _ = w.Write([]byte(`{"gate":{"evaluated":false,"reason":"no_policy"}}`))
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	// The /context fetch SUCCEEDED and assigned nothing, which is the only
	// shape row 63 marks: an unreachable platform said nothing at all.
	conf := confWithPolicies(t)
	var err error
	var errOut string
	out := captureStdoutAll(t, func() {
		errOut = captureStderr(t, func() {
			err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf)
		})
	})

	if len(reqs) != 1 || reqs[0] != "POST /api/v1/pushes" {
		t.Fatalf("requests = %v, want exactly one POST /api/v1/pushes: the run must reach the platform (row 63)", reqs)
	}
	var body struct {
		Evaluation *struct {
			NothingEvaluated bool   `json:"nothing_evaluated"`
			Reason           string `json:"reason"`
		} `json:"evaluation"`
		Results []json.RawMessage `json:"results"`
	}
	if jsonErr := json.Unmarshal(pushed, &body); jsonErr != nil {
		t.Fatalf("push body does not parse as JSON: %v\n%s", jsonErr, pushed)
	}
	if body.Evaluation == nil || !body.Evaluation.NothingEvaluated {
		t.Fatalf("push body carries no nothing-evaluated marker: %s", pushed)
	}
	if body.Evaluation.Reason != "no_policy" {
		t.Errorf("evaluation.reason = %q, want %q: the platform resolved no policy for this project", body.Evaluation.Reason, "no_policy")
	}
	if len(body.Results) != 0 {
		t.Errorf("results = %d entries, want none: a marked push carrying a result is a 422 by contract\n%s", len(body.Results), pushed)
	}
	// The hazard this rewiring creates: buildPlatformPush's standalone branch
	// would put the LOCAL configuration's verdict on the wire under a platform
	// link, which is the wrong-verdict failure platform mode exists to remove.
	// A linked run never evaluates the local configuration, so no policy entry
	// may reach the wire at all - asserted on the RAW bytes, because a decode
	// into a named struct would pass on a renamed field.
	if strings.Contains(string(pushed), `"policy"`) {
		t.Errorf("a policy entry from the local configuration reached the wire on a linked run that evaluated nothing:\n%s", pushed)
	}
	if err != nil {
		t.Fatalf("err = %v, want nil: the platform answered evaluated:false, which is not a blocking verdict", err)
	}
	// The one-line notice stays, and the platform's own answer is reported
	// rather than swallowed: without it the operator sees a push and no word
	// on what the platform made of it.
	assertContains(t, out, "no policy resolved for  (no policy assigned), nothing evaluated")
	assertContains(t, errOut, "platform gate not evaluated: no_policy")

	// The platform stays the authority on the exit code here exactly as it
	// is on every other push: if it ever answers a blocking gate for such a
	// run, the CLI reports it instead of deciding locally that a run which
	// evaluated nothing has nothing to block.
	t.Run("a blocking answer from the platform still decides", func(t *testing.T) {
		blocking := gatePushServer(t, http.StatusAccepted, `{"gate":{"evaluated":true,"blocking":true,"reason":"the organisation requires a policy on every project","policies":[]}}`)
		defer blocking.Close()
		restoreBlocking := withPlatformTestEnv(t, blocking.URL, "tok")
		defer restoreBlocking()

		var blockErr error
		_ = captureStdoutAll(t, func() {
			_ = captureStderr(t, func() {
				blockErr = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), confWithPolicies(t))
			})
		})
		var gateErr *PlatformGateError
		if !errors.As(blockErr, &gateErr) {
			t.Fatalf("err = %v (%T), want a *PlatformGateError: the platform decides, not the CLI", blockErr, blockErr)
		}
	})

	// The boundary of the change, stated here beside the pushing case: a
	// platform whose /context fetch FAILED assigned no policy because it
	// answered nothing. It is not a nothing-evaluated run, the only verdict
	// available for it would be the local configuration's, and it keeps
	// exactly the behaviour it had before row 63 - the notice, no request at
	// all, exit 0.
	t.Run("an unreachable platform is unchanged", func(t *testing.T) {
		var unreachableReqs []string
		unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			unreachableReqs = append(unreachableReqs, r.Method+" "+r.URL.Path)
		}))
		defer unreachable.Close()
		restoreUnreachable := withPlatformTestEnv(t, unreachable.URL, "tok")
		defer restoreUnreachable()

		conf := configuration.NewDefaultConfiguration()
		conf.PlumberConfig = testDefaultPlumberConfig(t)
		conf.PlatformRun = &platform.RunContext{
			Endpoint:    "https://platform.example.com",
			ProjectPath: "g/p",
			ContextErr:  errors.New("dial tcp: connection refused"),
		}
		var unreachableErr error
		unreachableOut := captureStdoutAll(t, func() {
			_ = captureStderr(t, func() {
				unreachableErr = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf)
			})
		})
		if len(unreachableReqs) != 0 {
			t.Fatalf("requests = %v, want none: a run the platform never answered is not marked and is not pushed", unreachableReqs)
		}
		if unreachableErr != nil {
			t.Fatalf("err = %v, want nil", unreachableErr)
		}
		assertContains(t, unreachableOut, "no policy resolved for g/p (dial tcp: connection refused), nothing evaluated")
	})
}

// Row 63, the publish leg: the nothing-evaluated push goes through publishRun
// like every other push, and publishRun opens with the score-publishing leg.
// That leg publishes nothing under --platform, but it is not silent: with
// score-push off it invites the operator to turn on a live badge. A run that
// evaluated nothing has no score to put on a badge, and this path never
// printed that invitation before (the early return skipped publishRun
// entirely), so pushing the run must not start advertising one.
func TestRunPlatformMode_Row63_NothingEvaluatedPushDoesNotNudgeForABadge(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint, origPushScore := printOutput, pushScore
	printOutput, pushScore = true, false
	defer func() { printOutput, pushScore = origPrint, origPushScore }()
	// The nudge prints at most once per process, so without this reset the
	// test would report on whatever ran before it rather than on the run it
	// drives.
	scorePublishOnce = sync.Once{}

	pushes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pushes++
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"gate":{"evaluated":false,"reason":"no_policy"}}`))
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	var err error
	var errOut string
	_ = captureStdoutAll(t, func() {
		errOut = captureStderr(t, func() {
			err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), confWithPolicies(t))
		})
	})

	if err != nil {
		t.Fatalf("err = %v, want nil: the platform answered evaluated:false", err)
	}
	// Without this the assertion below would also pass on a run that never
	// reached the publish leg at all.
	if pushes != 1 {
		t.Fatalf("pushes = %d, want exactly 1: the run must have reached the publish leg", pushes)
	}
	if strings.Contains(errOut, "turn on score-push") {
		t.Errorf("the badge nudge printed on a run that evaluated nothing, and there is no verdict to badge:\n%s", errOut)
	}
}

// Row 63, the all-unappliable shape: policies DID resolve (len(runs) > 0),
// but every one of their trees failed to apply, so buildPolicyResults sends
// an empty results array and the push carries the same nothing-evaluated
// marker as the zero-policy case above. publishRun's badge-nudge skip must
// key on that same "no policy result produced" fact rather than on
// len(runs) == 0, or this shape sails through with runs non-empty and starts
// advertising a badge for a verdict nobody computed.
func TestRunPlatformMode_Row63_AllUnappliableRunsDoesNotNudgeForABadge(t *testing.T) {
	newGateFlagsCmd(t)
	origPrint, origPushScore := printOutput, pushScore
	printOutput, pushScore = true, false
	defer func() { printOutput, pushScore = origPrint, origPushScore }()
	scorePublishOnce = sync.Once{}

	unreadableA := policyWithTree("Unreadable A", "pipelineMustNotEnableDebugTrace", unreadableControlConfig)
	unreadableB := policyWithTree("Unreadable B", "pipelineMustNotUseDockerInDocker", unreadableControlConfig)
	conf := confWithPolicies(t, unreadableA, unreadableB)

	pushes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pushes++
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"gate":{"evaluated":false,"reason":"policies_not_applicable"}}`))
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	var err error
	var errOut string
	_ = captureStdoutAll(t, func() {
		errOut = captureStderr(t, func() {
			err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf)
		})
	})

	if err != nil {
		t.Fatalf("err = %v, want nil: the platform answered evaluated:false", err)
	}
	if pushes != 1 {
		t.Fatalf("pushes = %d, want exactly 1: the run must have reached the publish leg", pushes)
	}
	if strings.Contains(errOut, "turn on score-push") {
		t.Errorf("the badge nudge printed on a run whose policies all failed to apply, and there is no verdict to badge:\n%s", errOut)
	}
}
