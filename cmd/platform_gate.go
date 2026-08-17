package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// platformGatePolicy is one policy's gate verdict, from the push response's
// gate.policies array. All five fields are consulted: ID/Name/Enforcement
// identify the policy, Blocking selects which entries name the run's
// failure, LiveFailCount is what the job-log line reports for each one.
type platformGatePolicy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Enforcement   string `json:"enforcement"`
	Blocking      bool   `json:"blocking"`
	LiveFailCount int    `json:"live_fail_count"`
}

// platformGate is the push response's "gate" block: the platform's
// post-push gate evaluation for this run. Evaluated false means the
// platform deliberately did not render a verdict (e.g. nothing configured
// to gate this project yet) - Reason then explains why, and the run
// proceeds exactly like every other fail-open case.
type platformGate struct {
	Evaluated bool                 `json:"evaluated"`
	Blocking  bool                 `json:"blocking"`
	Reason    string               `json:"reason"`
	Policies  []platformGatePolicy `json:"policies"`
}

// platformPushResponse is the shape decoded from a 2xx push response body.
// Gate is a pointer so a response with no "gate" key at all (an old
// platform that predates gate evaluation) is distinguishable from one that
// evaluated the gate - see evaluatePlatformGate.
type platformPushResponse struct {
	Gate *platformGate `json:"gate"`
}

// PlatformGateError reports that the platform's post-push gate evaluation
// blocked this run: one or more policies has live-monitoring failures the
// operator configured as blocking. It is a verdict on the project, exactly
// like ScoreGateError, not a program error - classifyExecError maps it to
// the same exit code (1). Policies is already filtered to the blocking
// subset of gate.policies.
type PlatformGateError struct {
	Reason   string
	Policies []platformGatePolicy
}

func (e *PlatformGateError) Error() string {
	// The same never-a-bare-colon guarantee as the job-log line (the shared
	// platformGateDetail fallback chain): on a run that passes locally but is
	// blocked by the platform, this string is the ONLY human-readable reason
	// the operator sees (classifyExecError emits it at process exit while the
	// terminal report still says PASSED), so it must always carry something.
	msg := "platform gate blocked the run: " + platformGateDetail(e.Policies, e.Reason)
	if len(e.Policies) > 0 && e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}
	return msg
}

// platformGateDetail is the shared fallback chain both output paths of a
// gate block use (the job-log line in evaluatePlatformGate and
// PlatformGateError.Error()): the blocking policies' descriptions, else the
// gate's own reason, else an honest placeholder - never empty, so neither
// path can ever end in a bare colon (the PR-review findings, both rounds).
func platformGateDetail(policies []platformGatePolicy, reason string) string {
	detail := strings.Join(platformGatePolicyDescriptions(policies), ", ")
	if detail == "" {
		detail = reason
	}
	if detail == "" {
		detail = "the platform provided no policy detail"
	}
	return detail
}

// platformGatePolicyDescriptions renders "name (N live failures)" per
// policy - the shared text both PlatformGateError.Error() and the job-log
// line use, so the two can never drift apart.
func platformGatePolicyDescriptions(policies []platformGatePolicy) []string {
	out := make([]string, 0, len(policies))
	for _, p := range policies {
		out = append(out, fmt.Sprintf("%s (%d live failures)", p.Name, p.LiveFailCount))
	}
	return out
}

// evaluatePlatformGate parses a successful push response's gate block and
// decides the platform-gate outcome for this run. Every fail-open path
// prints exactly one line and returns nil - never an error - matching the
// same "unavailable-class" sentence the transport/non-2xx failures use
// (platformGateFailOpenLine), so an old platform that has never heard of
// gates behaves identically to one that is temporarily down:
//
//   - a body that does not parse as JSON, or one that parses but carries no
//     "gate" key at all: an old platform. Fail open with the unavailable
//     line.
//   - evaluated:false: the platform's own explicit fail-open (nothing
//     configured to gate this project, a snapshot not yet collected,
//     etc). Fail open, logging the platform's own reason.
//   - blocking:false: nothing to do, the run proceeds.
//   - blocking:true: a *PlatformGateError naming every blocking policy
//     (gate.policies filtered to Blocking==true) is returned, and the
//     same detail is printed to stderr here - the job-log line - so it
//     reaches the operator regardless of what finalizeRun's precedence
//     ultimately does with the returned error (a local score-gate failure
//     outranks it and discards it as the *returned* error, but the line
//     already reached the log).
func evaluatePlatformGate(body []byte) error {
	var resp platformPushResponse
	if err := json.Unmarshal(body, &resp); err != nil || resp.Gate == nil {
		// A 2xx-accepted push whose body carries no usable gate verdict: an
		// older platform that predates the gate, or a mangled body. The
		// platform is UP and the push LANDED, so this is the no-verdict
		// line, never the alertable "unavailable" sentence (see the
		// constants' doc comment below).
		scoreWarn(platformGateNoVerdictLine)
		return nil
	}
	gate := resp.Gate

	if !gate.Evaluated {
		msg := "platform gate not evaluated"
		if gate.Reason != "" {
			msg += ": " + gate.Reason
		}
		scoreWarn(msg)
		return nil
	}

	if !gate.Blocking {
		return nil
	}

	blocking := make([]platformGatePolicy, 0, len(gate.Policies))
	for _, p := range gate.Policies {
		if p.Blocking {
			blocking = append(blocking, p)
		}
	}
	// The job-log line names every blocking policy - but the top-level
	// Blocking flag is the platform's decision and does not structurally
	// guarantee a non-empty per-policy subset. When no entry is marked
	// blocking (a future platform blocking for a run-level reason, or a
	// shape this CLI predates), the line must still carry WHY:
	// platformGateDetail falls back to gate.reason, then to an honest
	// placeholder - never a bare "BLOCKED: " with nothing after the colon
	// (PR-review finding).
	fmt.Fprintf(os.Stderr, "✗ platform gate BLOCKED: %s\n", platformGateDetail(blocking, gate.Reason))
	return &PlatformGateError{Reason: gate.Reason, Policies: blocking}
}

// The two EXACT fail-open sentences the spec requires (see
// platformGateFailOpenLine's doc comment for the class boundary), plus the
// informational no-verdict line. All three wordings are load-bearing - tests
// assert these literal strings, and the README tells operators the first two
// are stable enough to alert on - so they are named constants rather than
// inlined at each call site.
//
// platformGateNoVerdictLine is deliberately NOT either alertable sentence: a
// reachable platform that accepted the push (2xx) but returned no usable
// gate verdict (an older platform that predates the gate, an unparseable
// body, or a body that could not be read) is a routine rollout state, not an
// outage and not a misconfiguration. Emitting the "unavailable" sentence
// there would false-positive every alert built on it during a platform
// upgrade window (the PR-review finding this constant exists to fix).
const (
	platformGateUnavailableLine = "gate unavailable, letting through"
	platformGateNotRunLine      = "gate NOT RUN: authentication/configuration failed"
	platformGateNoVerdictLine   = "platform returned no gate verdict, letting through"
)

// platformGateFailOpenLine classifies a failed push (non-2xx, transport, or
// a 2xx whose body could not even be read) into its fail-open sentence, by
// HTTP status code. statusCode is 0 for a transport-level failure (timeout,
// DNS, connection refused) - no response was ever received, so the platform
// is the thing that's unreachable, the same class as a 5xx.
//
//   - 0 (transport) or 5xx: the platform itself is unavailable - the CLI
//     cannot know whether the run would have passed, so it lets through
//     with the alertable "unavailable" sentence.
//   - 2xx: the push was ACCEPTED and the token was fine; only the gate
//     verdict is missing (the body could not be read). The platform is
//     neither down nor misconfigured, so this is the informational
//     no-verdict line - the same one evaluatePlatformGate emits for a
//     2xx body without a gate key - keeping both alertable sentences
//     precise (the PR-review finding).
//   - 401/403/422: the request reached the platform but was rejected on
//     authentication or configuration grounds (bad/expired token, project
//     not recognized) - not a "the platform is down" condition, so it gets
//     the NOT-RUN class instead.
//   - any other 4xx (400 malformed request, 404 unknown route, 429 rate
//     limited, ...): no dedicated bucket exists for these. The closest
//     honest fit is still NOT-RUN - the request as sent was rejected, which
//     reads closer to "misconfigured" than "platform is down" - flagged for
//     Thomas in the PR body per the plan's global constraints rather than
//     silently decided.
func platformGateFailOpenLine(statusCode int) string {
	if statusCode >= 200 && statusCode < 300 {
		return platformGateNoVerdictLine
	}
	if statusCode == 0 || statusCode >= 500 {
		return platformGateUnavailableLine
	}
	return platformGateNotRunLine
}
