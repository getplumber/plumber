package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	assertContains(t, out, "no policy resolved for g/p (dial tcp: connection refused), nothing evaluated, exit 0")
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
