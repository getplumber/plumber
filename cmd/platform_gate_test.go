package cmd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
)

// gatePushServer starts a server that answers every request (the push POST;
// no /context call happens because these tests leave CI_PROJECT_PATH unset,
// same as the existing platform_push_test.go fixtures) with the given status
// and body.
func gatePushServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
}

func gateConf(t *testing.T) *configuration.Configuration {
	t.Helper()
	return &configuration.Configuration{ConfigFilePath: ".plumber.yaml", PlumberConfig: testDefaultPlumberConfig(t)}
}

// blocking:true must fail the run: a *PlatformGateError naming every
// blocking policy, and the job-log line on stderr must name each blocking
// policy together with its live_fail_count - the operator's only signal for
// why the run was blocked.
func TestMaybePushPlatform_GateBlockingFailsWithPolicyDetail(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `{"gate":{"evaluated":true,"blocking":true,"reason":"live failures exceed policy threshold","policies":[
		{"id":"p1","name":"team-baseline","enforcement":"block","blocking":true,"live_fail_count":3},
		{"id":"p2","name":"prod-images","enforcement":"block","blocking":true,"live_fail_count":1},
		{"id":"p3","name":"advisory-only","enforcement":"report","blocking":false,"live_fail_count":9}
	]}}`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	var err error
	out := captureStderr(t, func() {
		err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
	})

	var gateErr *PlatformGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("maybePushPlatform = %v (%T), want a *PlatformGateError", err, err)
	}
	if len(gateErr.Policies) != 2 {
		t.Fatalf("PlatformGateError.Policies = %d entries, want exactly the 2 blocking ones: %+v", len(gateErr.Policies), gateErr.Policies)
	}
	for _, want := range []string{"team-baseline", "3", "prod-images", "1"} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr = %q, want it to name every blocking policy and its live_fail_count (missing %q)", out, want)
		}
	}
	if strings.Contains(out, "advisory-only") {
		t.Errorf("stderr = %q, want only the blocking policies named, not the report-only one", out)
	}
}

// blocking:true with NO per-policy blocking entry (a future platform
// blocking for a run-level reason, or an empty policies array): the run must
// still exit 1 via a *PlatformGateError, and the job-log line must carry the
// gate's reason - never a bare "BLOCKED: " with nothing after the colon
// (the PR-review test-coverage finding: the top-level flag and the
// per-policy subset are computed independently and can disagree).
func TestMaybePushPlatform_GateBlockingWithoutPolicyDetailStillNamesTheReason(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `{"gate":{"evaluated":true,"blocking":true,"reason":"snapshot too stale to evaluate","policies":[
		{"id":"p1","name":"team-baseline","enforcement":"block","blocking":false,"live_fail_count":0}
	]}}`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	var err error
	out := captureStderr(t, func() {
		err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
	})

	var gateErr *PlatformGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("maybePushPlatform = %v (%T), want a *PlatformGateError: the top-level blocking flag decides", err, err)
	}
	if !strings.Contains(out, "platform gate BLOCKED: snapshot too stale to evaluate") {
		t.Errorf("stderr = %q, want the gate's reason on the BLOCKED line when no policy is individually marked blocking", out)
	}
	if strings.Contains(out, "BLOCKED: \n") {
		t.Errorf("stderr = %q, want never a bare BLOCKED line with nothing after the colon", out)
	}
}

// PlatformGateError.Error() is the ONLY human-readable reason the operator
// sees when the run passes locally but the platform blocks (Execute prints
// it at process exit; the terminal report still says PASSED) - so it is
// pinned directly, on both the detail path and the no-detail fallback
// (the PR-review test-coverage finding, second round).
func TestPlatformGateError_Error_NamesBlockingPolicies(t *testing.T) {
	err := &PlatformGateError{
		Reason: "live failures exceed threshold",
		Policies: []platformGatePolicy{
			{Name: "team-baseline", LiveFailCount: 3},
			{Name: "prod-images", LiveFailCount: 1},
		},
	}
	msg := err.Error()
	for _, want := range []string{"team-baseline", "3", "prod-images", "1", "live failures exceed threshold"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to carry %q", msg, want)
		}
	}
}

func TestPlatformGateError_Error_NoDetailStaysHonest(t *testing.T) {
	msg := (&PlatformGateError{}).Error()
	if strings.HasSuffix(strings.TrimSpace(msg), ":") {
		t.Errorf("Error() = %q, want never a bare trailing colon", msg)
	}
	if !strings.Contains(msg, "the platform provided no policy detail") {
		t.Errorf("Error() = %q, want the honest no-detail placeholder (the same fallback as the job-log line)", msg)
	}
}

// The same shape with NEITHER a blocking policy NOR a reason: the line still
// says something honest rather than trailing off.
func TestMaybePushPlatform_GateBlockingWithoutAnyDetailStaysHonest(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `{"gate":{"evaluated":true,"blocking":true,"policies":[]}}`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	var err error
	out := captureStderr(t, func() {
		err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
	})
	var gateErr *PlatformGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("maybePushPlatform = %v (%T), want a *PlatformGateError", err, err)
	}
	if !strings.Contains(out, "platform gate BLOCKED: the platform provided no policy detail") {
		t.Errorf("stderr = %q, want the honest no-detail placeholder", out)
	}
}

// blocking:false leaves the exit code alone.
func TestMaybePushPlatform_GatePassingDoesNotFail(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `{"gate":{"evaluated":true,"blocking":false,"policies":[]}}`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	if err := maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil); err != nil {
		t.Fatalf("maybePushPlatform = %v, want nil: a non-blocking gate must not fail the run", err)
	}
}

// evaluated:false is the platform's own explicit fail-open (e.g. nothing
// configured to gate this project yet): the run proceeds, and the reason is
// logged so the operator can see why no verdict was rendered.
func TestMaybePushPlatform_GateNotEvaluatedFailsOpenWithReason(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `{"gate":{"evaluated":false,"reason":"no policy configured to gate this project"}}`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	var err error
	out := captureStderr(t, func() {
		err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
	})
	if err != nil {
		t.Fatalf("maybePushPlatform = %v, want nil: evaluated:false must fail open", err)
	}
	if !strings.Contains(out, "no policy configured to gate this project") {
		t.Errorf("stderr = %q, want the gate's reason logged", out)
	}
}

// A 2xx response with no "gate" key at all (an old platform that predates
// gate evaluation) must fail open with the distinct NO-VERDICT line - the
// platform is up and the push landed, so emitting the alertable
// "unavailable" sentence would false-positive every alert built on it
// during a platform rollout (the PR-review finding). Never an error, and
// never silently unexplained.
func TestMaybePushPlatform_MissingGateKeyFailsOpenAsNoVerdict(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `{"ok":true}`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	var err error
	out := captureStderr(t, func() {
		err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
	})
	if err != nil {
		t.Fatalf("maybePushPlatform = %v, want nil: a missing gate key must fail open", err)
	}
	if !strings.Contains(out, "platform returned no gate verdict, letting through") {
		t.Errorf("stderr = %q, want the exact no-verdict sentence", out)
	}
	if strings.Contains(out, "gate unavailable, letting through") {
		t.Errorf("stderr = %q, want NOT the alertable unavailable sentence on a healthy 2xx (the alerting contract)", out)
	}
}

// An unparseable 2xx body is treated identically to a missing gate key: fail
// open, the same no-verdict line, never an error.
func TestMaybePushPlatform_UnparseableBodyFailsOpenAsNoVerdict(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `not json`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	var err error
	out := captureStderr(t, func() {
		err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
	})
	if err != nil {
		t.Fatalf("maybePushPlatform = %v, want nil: an unparseable body must fail open", err)
	}
	if !strings.Contains(out, "platform returned no gate verdict, letting through") {
		t.Errorf("stderr = %q, want the exact no-verdict sentence", out)
	}
	if strings.Contains(out, "gate unavailable, letting through") {
		t.Errorf("stderr = %q, want NOT the alertable unavailable sentence on a healthy 2xx (the alerting contract)", out)
	}
}

// The two class-distinguished fail-open sentences, pinned per failure class.
// Every case must leave the exit code alone (err == nil).
func TestMaybePushPlatform_ClassDistinguishedFailOpenSentences(t *testing.T) {
	unavailable := "gate unavailable, letting through"
	notRun := "gate NOT RUN: authentication/configuration failed"

	tests := []struct {
		name   string
		status int
		want   string
	}{
		{"401 unauthorized", http.StatusUnauthorized, notRun},
		{"403 forbidden", http.StatusForbidden, notRun},
		{"422 unprocessable", http.StatusUnprocessableEntity, notRun},
		{"400 other 4xx (closest honest fit is NOT RUN)", http.StatusBadRequest, notRun},
		{"404 other 4xx (closest honest fit is NOT RUN)", http.StatusNotFound, notRun},
		{"500 internal server error", http.StatusInternalServerError, unavailable},
		{"503 service unavailable", http.StatusServiceUnavailable, unavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := gatePushServer(t, tc.status, "")
			defer srv.Close()
			restore := withPlatformTestEnv(t, srv.URL, "tok-123")
			defer restore()

			var err error
			out := captureStderr(t, func() {
				err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
			})
			if err != nil {
				t.Fatalf("maybePushPlatform = %v, want nil: a remote push failure must never fail the run", err)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("status %d: stderr = %q, want the exact sentence %q", tc.status, out, tc.want)
			}
		})
	}

	t.Run("transport error (unreachable)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := srv.URL
		srv.Close() // nothing is listening now

		restore := withPlatformTestEnv(t, url, "tok-123")
		defer restore()

		var err error
		out := captureStderr(t, func() {
			err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
		})
		if err != nil {
			t.Fatalf("maybePushPlatform = %v, want nil: a transport failure must never fail the run", err)
		}
		if !strings.Contains(out, unavailable) {
			t.Errorf("stderr = %q, want the exact sentence %q", out, unavailable)
		}
	})

	// A 2xx means the push was accepted and the token was fine - this is
	// never an auth/config problem, even though the body then failed to
	// read (the connection dropped mid-response before the gate verdict
	// could be decoded). And the platform is not DOWN either: it must get
	// the distinct no-verdict line, keeping both alertable sentences
	// precise (the PR-review finding).
	t.Run("2xx with a body that fails to read", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("ResponseWriter does not support hijacking")
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			defer func() { _ = conn.Close() }()
			// Declares a 100-byte body (so the 2xx status line is real and
			// already sent) but only writes 5 bytes before the connection
			// closes: the client's io.ReadAll(resp.Body) sees an
			// unexpected EOF reading the declared-but-never-sent rest.
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
			_ = buf.Flush()
		}))
		defer srv.Close()
		restore := withPlatformTestEnv(t, srv.URL, "tok-123")
		defer restore()

		var err error
		out := captureStderr(t, func() {
			err = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
		})
		if err != nil {
			t.Fatalf("maybePushPlatform = %v, want nil: a 2xx body-read failure must never fail the run", err)
		}
		if !strings.Contains(out, "platform returned no gate verdict, letting through") {
			t.Errorf("stderr = %q, want the no-verdict sentence (a 2xx status must never classify as NOT-RUN or unavailable)", out)
		}
		if strings.Contains(out, notRun) {
			t.Errorf("stderr = %q, want NOT the NOT-RUN sentence: a 2xx status means the push was accepted and the token was fine", out)
		}
		if strings.Contains(out, unavailable) {
			t.Errorf("stderr = %q, want NOT the alertable unavailable sentence: the platform answered 2xx", out)
		}
	})
}

// The push-success line is unaffected by any of this: it stays exactly as
// it was before the gate feature existed.
func TestMaybePushPlatform_SuccessLineUnchangedOnPassingGate(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `{"gate":{"evaluated":true,"blocking":false}}`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	out := captureStderr(t, func() {
		if err := maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil); err != nil {
			t.Fatalf("maybePushPlatform: %v", err)
		}
	})
	if !strings.Contains(out, "✓ Results pushed to the platform:") {
		t.Errorf("stderr = %q, want the unchanged push-success line", out)
	}
}

// classifyExecError must map *PlatformGateError to the same exit code (1) as
// a local score-gate failure: it is a verdict on the project, not a program
// error. Unlike the local score gate, the terminal report never reflects a
// platform block, so the reason must always be emitted, regardless of
// --print.
func TestClassifyExecError_PlatformGateError(t *testing.T) {
	err := &PlatformGateError{Policies: []platformGatePolicy{{Name: "team-baseline", LiveFailCount: 3}}}
	for _, printOutput := range []bool{true, false} {
		prefix, code, emit := classifyExecError(err, printOutput)
		if prefix != "Blocked" || code != 1 || !emit {
			t.Errorf("classifyExecError(PlatformGateError, printOutput=%v) = (%q, %d, %v), want (Blocked, 1, true)", printOutput, prefix, code, emit)
		}
	}
}

// The precedence the plan fixes: a local score-gate failure and a platform
// gate block can both occur on the same run. The local gate's error stays
// primary (exit 1, same as before), but the platform gate's job-log line
// must still have reached stderr - nothing about losing the precedence race
// may swallow that message.
func TestFinalizeRun_LocalGateAndPlatformGateBothPresent(t *testing.T) {
	srv := gatePushServer(t, http.StatusAccepted, `{"gate":{"evaluated":true,"blocking":true,"policies":[
		{"id":"p1","name":"team-baseline","enforcement":"block","blocking":true,"live_fail_count":3}
	]}}`)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	var platformErr error
	out := captureStderr(t, func() {
		platformErr = maybePushPlatform(testProvider(t), gateConf(t), &control.AnalysisResult{}, nil)
	})
	var gotGateErr *PlatformGateError
	if !errors.As(platformErr, &gotGateErr) {
		t.Fatalf("maybePushPlatform = %v, want a *PlatformGateError", platformErr)
	}
	if !strings.Contains(out, "team-baseline") || !strings.Contains(out, "3") {
		t.Fatalf("stderr = %q, want the platform gate's job-log line naming team-baseline (3)", out)
	}

	failingGate := complianceSummary{minPoints: 100, score: scoreWithPoints(0), controlCount: 1}
	result := &control.AnalysisResult{}
	finalErr := finalizeRun(result, failingGate, platformErr)

	var scoreErr *ScoreGateError
	if !errors.As(finalErr, &scoreErr) {
		t.Fatalf("finalizeRun = %v (%T), want the local *ScoreGateError to stay primary", finalErr, finalErr)
	}
	// Both messages are present: the local gate's message via the returned
	// error (the primary exit reason), and the platform gate's job-log line
	// already on stderr from the maybePushPlatform call above.
}
