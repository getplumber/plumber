package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	providerPkg "github.com/getplumber/plumber/provider"
)

// platformSentinelURL is the GitLab CI component's default for its `platform`
// input. GitLab requires the `id_tokens:` block's `aud` to be non-empty, so
// the input (which doubles as both the audience and PLUMBER_ANALYZE_PLATFORM)
// cannot default to "". ".invalid" is reserved by RFC 2606 and can never
// resolve to a real host, so it is a safe value to mint a token against and
// wire through as the env var on every run without turning the push on for
// everyone. effectivePlatformPush treats this exact value as "not configured".
const platformSentinelURL = "https://platform.invalid"

// effectivePlatformPush resolves whether to push to the platform and the base
// URL to push to. Unlike the badge, there is no separate opt-in: supplying the
// URL is the opt-in, because a platform URL has no other meaning. Resolved only
// from operator-controlled sources (the flag / PLUMBER_ANALYZE_PLATFORM), never
// from the analyzed repository's config file. platformSentinelURL is the one
// value that does NOT opt in — see its doc comment.
func effectivePlatformPush() (push bool, endpoint string) {
	endpoint = strings.TrimRight(strings.TrimSpace(platformURL), "/")
	if endpoint == platformSentinelURL {
		return false, ""
	}
	return endpoint != "", endpoint
}

// platformEnvelope is the body POSTed to the platform. It exists so the
// analysis document can be pushed unchanged: everything the platform needs to
// know that the document does not carry lives here, not in the report.
//
// results is an array from the first release even though local policy
// resolution yields exactly one entry, because #368 makes it one entry per
// policy. Growing it must not change the shape of anything else.
type platformEnvelope struct {
	SchemaVersion int              `json:"schemaVersion"`
	Results       []platformResult `json:"results"`
}

// platformResult is one policy's verdict on this project.
//
// Degraded and DegradedReasons sit here rather than in the report because the
// analysis JSON document carries no degradation signal at all: the flag reaches
// SARIF (as invocations) and GitLab SAST (as scan.messages) and stops there.
// Without them the platform would receive a partial scan and render it as a
// complete one, with a score computed from missing data.
type platformResult struct {
	Policy          platformPolicy  `json:"policy"`
	Degraded        bool            `json:"degraded"`
	DegradedReasons []string        `json:"degradedReasons"`
	Report          json.RawMessage `json:"report"`
}

// platformPolicy identifies which policy produced the sibling report. Today
// Source is either "local" (Ref names the .plumber.yaml file that was
// actually read from disk) or "embedded" (the run used the config compiled
// into the binary — a zero-config run, Ref empty, because no file was read
// and claiming one would name a path that may not exist). Under #368 Source
// also becomes "platform", with Name and Ref carrying what the platform
// returned. A backend written against this keeps working across that change.
type platformPolicy struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Ref    string `json:"ref"`
}

// platformPolicySourceLocal marks a policy descriptor whose Ref names a
// .plumber.yaml file that was actually read from disk.
const platformPolicySourceLocal = "local"

// platformPolicySourceEmbedded marks a policy descriptor for a run that used
// the config embedded in the binary (no .plumber.yaml on disk, no --config
// pointing at a real file). Ref is empty in this case: the flag default
// (".plumber.yaml") names no file that was actually read, and asserting it
// as the descriptor's Ref would claim a local file that may not exist.
const platformPolicySourceEmbedded = "embedded"

// policyNameFor derives a stable, human-meaningful policy name from the config
// path: ".plumber.yaml" is the unnamed default, and any leading qualifier
// ("team.plumber.yml", ".plumber.strict.yaml") names the policy. Under #368 the
// platform supplies the name instead and this is not consulted.
func policyNameFor(configPath string) string {
	base := filepath.Base(strings.TrimSpace(configPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "default"
	}
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
	base = strings.TrimPrefix(base, ".")
	switch {
	case base == "" || base == "plumber":
		return "default"
	case strings.HasPrefix(base, "plumber."):
		return strings.TrimPrefix(base, "plumber.")
	case strings.HasSuffix(base, ".plumber"):
		return strings.TrimSuffix(base, ".plumber")
	default:
		return base
	}
}

// buildPlatformEnvelope wraps the analysis document for the platform. report
// is embedded as json.RawMessage from the SAME buildAnalysisJSONReport call
// that produced the --output file, so the two can never carry different DATA.
// The bytes on the wire are not byte-identical to the --output file, though:
// json.Marshal on the envelope re-serializes report compactly (as one field
// nested inside a larger document) and HTML-escapes '<', '>', '&' in any
// string values. That is intentional and left as-is — whitespace carries no
// semantic meaning, and no real report contains those characters — but callers
// must not assume the transmitted copy is a byte-for-byte match of the file.
func buildPlatformEnvelope(report []byte, configPath string, degraded bool, reasons []string) ([]byte, error) {
	if len(report) == 0 {
		return nil, fmt.Errorf("empty analysis report")
	}
	if reasons == nil {
		reasons = []string{}
	}
	env := platformEnvelope{
		SchemaVersion: 1,
		Results: []platformResult{{
			Policy:          platformPolicyFor(configPath),
			Degraded:        degraded,
			DegradedReasons: reasons,
			Report:          json.RawMessage(report),
		}},
	}
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal platform envelope: %w", err)
	}
	return body, nil
}

// platformPolicyFor derives the policy descriptor from the resolved config
// path (the *configuration.Configuration's ConfigFilePath, see
// maybePushPlatform). configPath is empty or equal to
// builtinDefaultConfigSource ("built-in default", set by
// loadEmbeddedDefaultConfig) exactly when the run never read a local
// .plumber.yaml — the --config flag's own default is ".plumber.yaml"
// regardless of whether that file exists, so it cannot be trusted to tell
// the two cases apart. Only when a real file was read does the descriptor
// claim "local" and carry its path; otherwise it claims "embedded" with no
// Ref, so the descriptor never names a file that may not exist on disk.
func platformPolicyFor(configPath string) platformPolicy {
	ref := strings.TrimSpace(configPath)
	if ref == "" || ref == builtinDefaultConfigSource {
		return platformPolicy{Name: policyNameFor(""), Source: platformPolicySourceEmbedded, Ref: ""}
	}
	return platformPolicy{Name: policyNameFor(ref), Source: platformPolicySourceLocal, Ref: ref}
}

// PlatformTokenError reports that the run could not obtain the CI OIDC
// id-token the platform push requires. It is the ONLY platform-push condition
// that fails a run: the grant is missing from the pipeline's own configuration,
// the user can fix it, and a silently skipped push would hide that from them.
// Everything remote — unreachable, 4xx, 5xx, oversized — is a warning.
type PlatformTokenError struct{ Reason string }

func (e *PlatformTokenError) Error() string {
	return "platform push: " + e.Reason
}

// platformTokenFailure reports a token failure on stderr AND returns it.
//
// Printing here rather than relying on the returned error is what makes the
// message reliable. finalizeRun evaluates this error last, deliberately, so a
// broken id-token grant can never mask a security finding the scan just made.
// The consequence is that on a run which also fails its gate the error is
// discarded, and without this line the user would be told nothing at all: no
// push, no warning, no clue why. That is the failure mode the whole feature
// exists to prevent, so the diagnosis is emitted at the point of failure and
// the error still propagates to decide the exit code when nothing outranks it.
func platformTokenFailure(reason string) error {
	fmt.Fprintf(os.Stderr, "⚠️  platform push: %s\n", reason)
	return &PlatformTokenError{Reason: reason}
}

// maybePushPlatform pushes the analysis result to the configured platform.
// It returns non-nil ONLY for a token failure; see PlatformTokenError. conf's
// only use here is resolving which config file (if any) produced this run's
// policy — for the platform record's policy descriptor — via
// conf.ConfigFilePath, the RESOLVED path set once at load time (falling back
// to the --config flag when conf is nil or the field is empty, e.g. in tests
// that construct the payload directly). Project identity for the platform
// record is a separate matter and still comes from the verified OIDC claims
// server-side, never from operator-supplied config.
func maybePushPlatform(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult, payload []byte) error {
	push, endpoint := effectivePlatformPush()
	if !push || len(payload) == 0 {
		return nil
	}

	// Every failure to obtain the token fails the run, INCLUDING a transport
	// error such as a timeout, DNS failure or refused connection while talking
	// to the CI's own token service. That is deliberate and is not an oversight
	// to be "fixed" into a warning later: minting happens inside the pipeline,
	// against the CI provider's own infrastructure, so a failure there is an
	// ordinary pipeline failure like any other step being unable to reach its
	// dependencies. The never-block rule protects the pipeline from ONE thing
	// only: the platform receiving the data being down. That is a third party
	// the pipeline should not be coupled to; the CI's token endpoint is not.
	token, err := scoreOIDCToken(p, endpoint)
	if err != nil {
		return platformTokenFailure(fmt.Sprintf("could not mint the CI OIDC id-token for %s: %v", endpoint, err))
	}
	if token == "" {
		switch {
		case p.Name() == "github":
			return platformTokenFailure("the workflow must grant `permissions: id-token: write` to push to the platform")
		default:
			return platformTokenFailure("no CI OIDC id-token available for the platform push; the pipeline must declare the component's `id_tokens:` block (" + gitlabPlatformTokenEnv + ")")
		}
	}

	configPath := strings.TrimSpace(configFile)
	if conf != nil {
		if resolved := strings.TrimSpace(conf.ConfigFilePath); resolved != "" {
			configPath = resolved
		}
	}
	body, err := buildPlatformEnvelope(payload, configPath, result.DataCollectionDegraded, result.DegradedReasons)
	if err != nil {
		scoreWarn(fmt.Sprintf("platform push skipped: %v", err))
		return nil
	}

	// Every remote condition lands here, including 413 for an oversized body:
	// the server is the authority on its own limit, so the CLI enforces none.
	// The push is skipped whole rather than truncated, because the platform
	// renders the record as the complete picture.
	if err := postScoreReport(endpoint+"/api/v1/results", token, body); err != nil {
		scoreWarn(fmt.Sprintf("platform push failed: %v", err))
		return nil
	}
	fmt.Fprintf(os.Stderr, "✓ Results pushed to the platform: %s\n", endpoint)
	return nil
}
