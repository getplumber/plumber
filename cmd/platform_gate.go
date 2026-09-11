package cmd

import (
	"bytes"
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

// platformPushResponseEnvelope is the first stage of decoding a 2xx push
// response body: both blocks are held as raw JSON so each can be decoded on
// its own terms. The gate decides the exit code and is decoded strictly right
// after; the global score (PushAccepted.global_score: the average of the
// policies' FINAL points, letter from that average) is display data and is
// decoded tolerantly. An absent key and a null one are both "the platform
// sent nothing here" - see isAbsentJSON.
type platformPushResponseEnvelope struct {
	Gate        json.RawMessage `json:"gate"`
	GlobalScore json.RawMessage `json:"global_score"`
}

// platformVerdict is what a push produced, for every consumer after the push:
// the renderer's "Platform verdict" block, the badge and MR comment headline,
// the JSON top-level score, and finalizeRun's exit code (through the error
// evaluatePlatformGate returns beside it). Unavailable is the fail-open
// reason when no usable gate came back (old platform, unparseable body); Gate
// is nil in that case.
type platformVerdict struct {
	Gate        *platformGate
	GlobalScore *platformScore
	Unavailable string
}

// platformGatePassed is the platform-mode answer to "did this run pass": the
// gate did not block. Every fail-open case (no push, no verdict, an old
// platform, an unevaluated gate) passes, which is invariant 5's let-through
// stated once for every consumer that reports a verdict - the JSON report's
// `passed`, the MR comment's status line - so none of them can invent a
// stricter reading than the exit code's.
func platformGatePassed(v *platformVerdict) bool {
	return v == nil || v.Gate == nil || !v.Gate.Blocking
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

// platformGateNoVerdict is the single no-verdict fail-open: a 2xx push whose
// body carried no usable gate (an old platform, a body that is not JSON, a
// gate that did not decode). It prints one line, carries whatever global
// score the body did yield, and returns a nil error - the let-through
// invariant 5 requires, stated in plain words rather than passed silently.
// detail, when present, names which part failed; the alertable sentence is
// deliberately NOT used here (see the constants below).
func platformGateNoVerdict(detail string, score *platformScore) (*platformVerdict, error) {
	line := platformGateNoVerdictLine
	if detail != "" {
		line += " (" + detail + ")"
	}
	scoreWarn(line)
	return &platformVerdict{GlobalScore: score, Unavailable: line}, nil
}

// decodePlatformGlobalScore decodes the response's global_score with
// platformScore's tolerant unmarshaller. This is display data - the badge
// letter, the comment headline, the JSON top-level score - never a verdict,
// so a shape it cannot read costs the score alone: nil, one line, and the
// gate beside it is untouched. Absent and null are simply "no score", which
// is a routine state and says nothing.
func decodePlatformGlobalScore(raw json.RawMessage) *platformScore {
	if isAbsentJSON(raw) {
		return nil
	}
	var score platformScore
	if err := json.Unmarshal(raw, &score); err != nil {
		scoreWarn(fmt.Sprintf("the platform's global score could not be decoded (%v); this run reports no global score", err))
		return nil
	}
	return &score
}

// isAbsentJSON reports whether a raw field is missing or JSON null, the two
// spellings of "the platform sent nothing here".
func isAbsentJSON(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// evaluatePlatformGate parses a successful push response's gate block and
// decides the platform-gate outcome for this run, returning a *platformVerdict
// alongside the error for every consumer downstream of the push (the
// renderer's "Platform verdict" block, the badge, the MR comment, the JSON
// top-level score). Every fail-open path prints exactly one line and returns
// a non-nil verdict with a nil error - never an error - matching the same
// "unavailable-class" sentence the transport/non-2xx failures use
// (platformGateFailOpenLine), so an old platform that has never heard of
// gates behaves identically to one that is temporarily down:
//
//   - a body that does not parse as JSON, one that carries no "gate" key at
//     all (an old platform), or one whose gate block does not decode: no
//     verdict. Fail open with the no-verdict line, the verdict's Gate nil and
//     Unavailable set (naming the decode failure when there was one). A body
//     that DID parse still hands back the global score it carried: the gate
//     is missing, the score the badge and the comment publish is not. A gate
//     is never PARTIALLY decoded - see the two-stage decode below.
//   - evaluated:false: the platform's own explicit fail-open (nothing
//     configured to gate this project, a snapshot not yet collected,
//     etc). Fail open, logging the platform's own reason; the verdict still
//     carries the decoded Gate and GlobalScore, with Unavailable set to the
//     same reason.
//   - blocking:false: nothing to do, the run proceeds; the verdict carries
//     the decoded Gate and GlobalScore, Unavailable empty.
//   - blocking:true: a *PlatformGateError naming every blocking policy
//     (gate.policies filtered to Blocking==true) is returned alongside the
//     same verdict (Gate and GlobalScore decoded), and the same detail is
//     printed to stderr here - the job-log line - so it reaches the operator
//     regardless of what finalizeRun's precedence ultimately does with the
//     returned error (a local score-gate failure outranks it and discards it
//     as the *returned* error, but the line already reached the log).
func evaluatePlatformGate(body []byte) (*platformVerdict, error) {
	// Two stages, and the split is the whole point. The gate is the run's
	// exit code and is decoded STRICTLY; the global score is display data and
	// is decoded tolerantly. Doing both in one pass is what broke: encoding/
	// json leaves a mistyped field at its zero value and keeps going, so
	// "blocking":"true" handed back a fully-formed gate with Blocking false
	// and a blocking verdict silently became exit 0. No amount of tolerance
	// may ever be able to soften a verdict, so tolerance is not applied to
	// the gate at all.
	var envelope platformPushResponseEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		// The body is not JSON at all: nothing in it can be trusted, so
		// nothing is carried out of it.
		return platformGateNoVerdict("", nil)
	}

	// Decoded first so every fail-open path below can still carry it: the
	// gate is missing, the score the badge and the comment publish is not.
	score := decodePlatformGlobalScore(envelope.GlobalScore)

	if isAbsentJSON(envelope.Gate) {
		// A 2xx-accepted push whose body carries no gate at all: an older
		// platform that predates it. The platform is UP and the push LANDED,
		// so this is the no-verdict line, never the alertable "unavailable"
		// sentence (see the constants' doc comment below).
		return platformGateNoVerdict("", score)
	}

	var decoded platformGate
	if err := json.Unmarshal(envelope.Gate, &decoded); err != nil {
		// A gate whose own fields did not decode is NOT a verdict. It is not
		// partially one either: a half-decoded gate reads as "evaluated,
		// not blocking", which is the one answer this CLI must never invent.
		// Drop it and fail open honestly, saying which half failed.
		return platformGateNoVerdict(fmt.Sprintf("the gate block did not decode: %v", err), score)
	}
	gate := &decoded

	if !gate.Evaluated {
		msg := "platform gate not evaluated"
		if gate.Reason != "" {
			msg += ": " + gate.Reason
		}
		scoreWarn(msg)
		return &platformVerdict{Gate: gate, GlobalScore: score, Unavailable: msg}, nil
	}

	if !gate.Blocking {
		return &platformVerdict{Gate: gate, GlobalScore: score}, nil
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
	return &platformVerdict{Gate: gate, GlobalScore: score}, &PlatformGateError{Reason: gate.Reason, Policies: blocking}
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
