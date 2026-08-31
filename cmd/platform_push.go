package cmd

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
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

// The types below mirror the platform's ingestion.Push contract
// (platform/backend/ingestion/contract.go in the monorepo) field-for-field:
// same shape, same json tags, same optionality, snake_case throughout. That
// file is the source of truth. A prior version of this file diverged from
// it — results[].policy was sent as a {name,source,ref} object where the
// contract declares a plain string — and every push was rejected by the real
// parser (json.Unmarshal into a string field fails on an object) as a
// result. See docs/platform-push-testing.md for how a push's raw wire bytes
// are captured and checked against that contract shape, not just decoded
// back into this package's own types.
type platformPush struct {
	SchemaVersion int                    `json:"schema_version"`
	Provider      string                 `json:"provider,omitempty"`
	Instance      string                 `json:"instance,omitempty"`
	Project       platformProject        `json:"project"`
	Ref           platformRef            `json:"ref"`
	Pipeline      platformPipeline       `json:"pipeline"`
	CLI           platformCLI            `json:"cli"`
	Collection    platformCollectionMeta `json:"collection"`
	// Results carries one entry per policy. Local policy resolution always
	// yields exactly one; a multi-policy platform grows this array without
	// changing the shape of anything else.
	Results []platformPolicyResult `json:"results"`
}

// platformProject is the informational project identity carried in the
// body — NOT the authoritative one. The platform derives the authoritative
// identity from the verified CI OIDC claims server-side (ADR-0003); this is
// a convenience for display/search only.
type platformProject struct {
	Path string `json:"path,omitempty"`
	ID   string `json:"id,omitempty"`
}

// platformRef is the analyzed git ref, read straight from the CI environment
// (see platformRefFor). Tag is not populated by this build — the CLI has no
// tag-pipeline source wired to this call site yet.
type platformRef struct {
	Branch string `json:"branch,omitempty"`
	Tag    string `json:"tag,omitempty"`
	SHA    string `json:"sha,omitempty"`
}

// platformPipeline identifies the CI run that produced this push, read
// straight from the CI environment (see platformPipelineFor). StartedAt is
// not populated by this build (no CLI-side source for it yet).
type platformPipeline struct {
	ID        string `json:"id,omitempty"`
	JobID     string `json:"job_id,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
}

// platformCLI carries the CLI version that produced the push. ComponentVersion
// is not populated by this build — the GitLab component version is not
// currently threaded through to the binary at this call site.
type platformCLI struct {
	Version          string `json:"version,omitempty"`
	ComponentVersion string `json:"component_version,omitempty"`
}

// platformCollectionMeta is the honest degradation signal: whether data
// collection was degraded this run. SnapshotCollectedAt is not populated —
// the CLI has no snapshot concept yet. MissingFields is deliberately left
// omitted too: result.DegradedReasons is human prose ("branch protection
// could not be fetched (network or timeout)"), not the field-name list this
// key expects, and forcing prose through it would misrepresent the contract
// rather than honor it.
type platformCollectionMeta struct {
	Degraded            bool     `json:"degraded,omitempty"`
	SnapshotCollectedAt string   `json:"snapshot_collected_at,omitempty"`
	MissingFields       []string `json:"missing_fields,omitempty"`
}

// platformPolicyResult is one policy's verdict: what it ran (EffectiveConfig),
// its explicit per-control findings, and the resulting score. Policy is a
// plain string — the platform's contract has no name/source/ref object here
// (a prior version of this file sent one; see the package doc above).
type platformPolicyResult struct {
	Policy string `json:"policy"`
	// PolicyID is the platform's uuid for Policy, taken from the resolved
	// policy set (buildPolicyResults). A string, not a uuid type, and
	// deliberately left "" rather than a placeholder when there is none:
	// with omitempty that means the key is genuinely absent from the wire,
	// never present with a zero value.
	//
	// A uuid-typed field would make this impossible to express. Go's
	// omitempty never omits a fixed-size array, so a zero uuid.UUID
	// marshals as the literal all-zero uuid string — which the platform's
	// contract explicitly forbids sending, because it is the id its derived
	// fallback policy carries and names no real policies row.
	PolicyID        string            `json:"policy_id,omitempty"`
	EffectiveConfig json.RawMessage   `json:"effective_config,omitempty"`
	Findings        []platformFinding `json:"findings"`
	Score           platformScore     `json:"score"`
}

// platformFinding is one EXPLICIT per-control result entry — see
// platformFindingsFor for how the list is built. A failed control
// contributes one of these per underlying finding (Data populated); a
// passed or not-evaluable control contributes exactly one with no Data.
// Version/Requirement are not populated by this build (no CLI-side source
// for either yet).
type platformFinding struct {
	Control     string          `json:"control"`
	Version     string          `json:"version,omitempty"`
	Requirement string          `json:"requirement,omitempty"`
	Status      string          `json:"status"`
	Data        json.RawMessage `json:"data,omitempty"`

	// Name and Category are the control's display metadata (#440), the
	// docs-catalog wording next to the stable technical id in Control.
	// Additive: the platform ignores unknown fields, and consumers that
	// keyed on Control keep working unchanged.
	Name     string `json:"name,omitempty"`
	Category string `json:"category,omitempty"`
}

// decoratedPlatformFinding builds a push finding entry with the control's
// display metadata attached (#440), so every construction site stays in
// step with the exported catalog.
func decoratedPlatformFinding(controlName, status string, data json.RawMessage) platformFinding {
	f := platformFinding{Control: controlName, Status: status, Data: data}
	if meta, ok := configuration.ControlMetaFor(controlName); ok {
		f.Name = meta.DisplayName
		f.Category = meta.Category
	}
	return f
}

// Finding-status vocabulary the platform's contract defines.
// platformStatusNotEvaluable is never omitted for a degraded/could-not-
// evaluate control — see platformFindingsFor.
const (
	platformStatusPass         = "pass"
	platformStatusFail         = "fail"
	platformStatusNotEvaluable = "not_evaluable"
)

// platformScore is the entry's Plumber Score. Points is
// PlumberScoreResult.RawPointsUnclamped rounded to the nearest int — see
// platformScoreFrom.
type platformScore struct {
	Letter string `json:"letter,omitempty"`
	Points int    `json:"points"`
}

// platformScoreFrom converts the already-computed Plumber Score to the wire
// shape. Points is RawPointsUnclamped — the SIGNED deficit with no floor at
// zero (the contract stores it unclamped; the gate/badge's floored-at-zero
// RawPoints is display-only) — rounded to the nearest int, matching what the
// contract's Score.Points type actually is. Tolerates a nil score (no
// production caller passes one today, but a best-effort push should never
// panic a run over a nil pointer) by sending the zero value.
func platformScoreFrom(score *control.PlumberScoreResult) platformScore {
	if score == nil {
		return platformScore{}
	}
	return platformScore{Letter: score.Score, Points: int(math.Round(score.RawPointsUnclamped))}
}

// policyNameFor derives a stable, human-meaningful policy name from the config
// path: ".plumber.yaml" is the unnamed default, and any leading qualifier
// ("team.plumber.yml", ".plumber.strict.yaml") names the policy.
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

// platformPolicyNameFor is policyNameFor with one normalization on top:
// builtinDefaultConfigSource ("built-in default") is the label
// conf.ConfigFilePath carries for a zero-config run that read the config
// embedded in the binary, not a real file — passing it to policyNameFor
// unchanged would leak that internal sentinel string as the policy name
// ("built-in default") instead of the clean "default" every other
// zero-config path produces. Treated the same as an empty/unresolved path,
// mirroring the special case the pre-contract-rework policy descriptor used
// to apply (platformPolicyFor, since removed).
func platformPolicyNameFor(configPath string) string {
	if strings.TrimSpace(configPath) == builtinDefaultConfigSource {
		return policyNameFor("")
	}
	return policyNameFor(configPath)
}

// buildPlatformPush builds the body POSTed to the platform, matching
// ingestion.Push field-for-field (see the type doc comments above).
//
// configPath is the resolved config path the caller computed
// (conf.ConfigFilePath, falling back to the --config flag); it names the
// single policy of a STANDALONE push. In platform mode the results array
// instead carries one entry per policy the platform resolved - see
// buildPolicyResults, which owns that decision.
func buildPlatformPush(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult, score *control.PlumberScoreResult, configPath string) ([]byte, error) {
	forgeHost, projectPath, _ := resolveScoreTarget(p, conf)

	push := platformPush{
		SchemaVersion: 1,
		Provider:      p.Name(),
		Instance:      forgeHost,
		Project:       platformProject{Path: projectPath, ID: platformProjectID(p, conf)},
		Ref:           platformRefFor(p),
		Pipeline:      platformPipelineFor(p),
		CLI:           platformCLI{Version: strings.TrimPrefix(Version, "v")},
		Collection:    platformCollectionFor(conf, result),
		Results:       buildPolicyResults(p, conf, result, score, configPath),
	}

	body, err := json.Marshal(push)
	if err != nil {
		return nil, fmt.Errorf("marshal platform push: %w", err)
	}
	return body, nil
}

// platformCollectionFor builds the honest-degradation block: whether this
// run's collection degraded, which snapshot read it consumed, and which
// snapshot lanes carried no data.
//
// snapshot_collected_at and missing_fields are populated only in platform
// mode, where a snapshot exists to describe. A standalone run has no
// snapshot, so both stay absent rather than being filled with a fabricated
// "nothing was missing".
func platformCollectionFor(conf *configuration.Configuration, result *control.AnalysisResult) platformCollectionMeta {
	meta := platformCollectionMeta{Degraded: result != nil && result.DataCollectionDegraded}
	if conf == nil || !conf.PlatformRun.Active() {
		return meta
	}
	meta.SnapshotCollectedAt = conf.PlatformRun.SnapshotCollectedAt()
	meta.MissingFields = conf.PlatformRun.MissingSnapshotFields()
	return meta
}

// platformProjectID returns the project's stable numeric GitLab id when it is
// cheaply available — conf.ProjectID, or the CI_PROJECT_ID env var GitLab CI
// always exports — without an extra API round trip. GitHub has no equivalent
// cheap numeric id at this call site, so this only ever returns non-empty for
// a GitLab-shaped provider.
func platformProjectID(p providerPkg.Provider, conf *configuration.Configuration) string {
	if p.Name() == "github" {
		return ""
	}
	if conf != nil && conf.ProjectID != 0 {
		return strconv.Itoa(conf.ProjectID)
	}
	return strings.TrimSpace(os.Getenv("CI_PROJECT_ID"))
}

// platformRefFor reads the analyzed ref straight from the CI environment: the
// running branch (ciRunBranch, already provider-aware) and the head commit
// SHA via the provider's own CIEnvMapping (CI_COMMIT_SHA / GITHUB_SHA — the
// same mapping resolveScoreTarget and the source-link builder use). Both are
// "" outside CI; the omitempty tags on platformRef drop them rather than
// sending a fabricated value.
func platformRefFor(p providerPkg.Provider) platformRef {
	return platformRef{
		Branch: ciRunBranch(p),
		SHA:    strings.TrimSpace(os.Getenv(p.CIEnvVars().CommitSHA)),
	}
}

// platformPipelineFor reads the CI run's own identifiers straight from the
// environment — GitLab's CI_PIPELINE_ID/CI_JOB_ID, GitHub's
// GITHUB_RUN_ID/GITHUB_JOB. Never fabricated for a local run: both env vars
// are simply unset there, and the omitempty tags drop them.
func platformPipelineFor(p providerPkg.Provider) platformPipeline {
	if p.Name() == "github" {
		return platformPipeline{
			ID:    strings.TrimSpace(os.Getenv("GITHUB_RUN_ID")),
			JobID: strings.TrimSpace(os.Getenv("GITHUB_JOB")),
		}
	}
	return platformPipeline{
		ID:    strings.TrimSpace(os.Getenv("CI_PIPELINE_ID")),
		JobID: strings.TrimSpace(os.Getenv("CI_JOB_ID")),
	}
}

// platformEffectiveConfigRaw renders the FLAT per-provider controls map the
// push contract specifies for effective_config (the J12-F5 ruling,
// 2026-08-31): top-level keys are control names, values their configs, in
// the config file's own camelCase spelling. That is exactly what the
// platform's issueident.ParamsFor unmarshals - it imports this module's
// configuration.ControlsConfig, and Go's case-insensitive JSON field match
// makes the camelCase keys land on the right fields. The previous nested
// report shape decoded there to a zero value, storing empty params on every
// issue.
//
// The map is parsed from the same raw text the report's plumberConfig block
// uses (pc.Raw, falling back to the embedded default), so the two surfaces
// cannot disagree about which policy ran; full provenance beyond the
// controls map stays available in the raw push artifact (ADR-0017). An
// absent or empty provider section returns nil and omitempty drops the
// field rather than sending "{}".
func platformEffectiveConfigRaw(pc *configuration.PlumberConfig, provider string) json.RawMessage {
	rawCfg := ""
	if pc != nil && pc.Raw != "" {
		rawCfg = pc.Raw
	}
	if rawCfg == "" {
		rawCfg = string(defaultconfig.Get())
	}
	policy := parsePolicyObject(rawCfg)
	section, _ := policy[provider].(map[string]any)
	controls, _ := section["controls"].(map[string]any)
	if len(controls) == 0 {
		return nil
	}
	raw, err := json.Marshal(controls)
	if err != nil {
		return nil
	}
	// The platform's value guard walks effective_config too, so the same
	// sanitization applies: a config that ever carries a variable value
	// beside its name must declare that value's provenance or not send it.
	sanitized, _ := sanitizeProvenance(raw)
	return sanitized
}

// platformFindingsFor builds the explicit-results findings list: one entry
// per applicable control this run evaluated, reusing control.StatusFor — the
// SAME four-state verdict (passed/failed/skipped/error) the --output JSON,
// CSV and OCSF renderers already compute per control — rather than deriving
// a second, possibly-diverging notion of "did this control pass" here.
//
//   - failed:  one entry PER underlying finding, status=fail, Data carrying
//     that finding serialized exactly as opaengine.Finding.MarshalJSON
//     already produces it.
//   - passed:  one entry, status=pass, no Data.
//   - error:   one entry, status=not_evaluable, no Data — NEVER omitted,
//     because an empty findings list for a control that could not really be
//     evaluated must not read as a silent pass.
//   - skipped: OMITTED entirely. A control disabled in .plumber.yaml (or
//     excluded via --controls/--skip-controls) is still visible in
//     effective_config; "not evaluated by choice" is a different fact from
//     "could not be evaluated" (not_evaluable), and folding them together
//     would hide operator intent from the platform.
//
// includeOnly/skip are conf.ControlsFilter/SkipControlsFilter, applied via
// control.MarkSkippedByFilter exactly as the terminal/JSON renderers do, so a
// --skip-controls run's platform push agrees with what it printed.
func platformFindingsFor(p providerPkg.Provider, result *control.AnalysisResult, pc *configuration.PlumberConfig, includeOnly, skip []string) []platformFinding {
	out := []platformFinding{}
	if pc == nil {
		return out
	}
	entries := p.Controls(pc)
	control.MarkSkippedByFilter(entries, includeOnly, skip)

	var findings []opaengine.Finding
	if result != nil {
		findings = result.Findings
	}
	findingsByControl := control.FindingsByControl(findings)

	for _, e := range entries {
		fs := findingsByControl[e.ControlName]
		switch control.StatusFor(e, result, len(fs)) {
		case control.StatusSkipped:
			continue
		case control.StatusFailed:
			for _, f := range fs {
				out = append(out, decoratedPlatformFinding(platformFindingControlName(f), platformStatusFail, platformFindingDataRaw(f)))
			}
		case control.StatusError:
			out = append(out, decoratedPlatformFinding(e.ControlName, platformStatusNotEvaluable, notEvaluableReasonData(result, e.ControlName)))
		default: // control.StatusPassed
			out = append(out, decoratedPlatformFinding(e.ControlName, platformStatusPass, nil))
		}
	}
	return out
}

// notEvaluableReasonData carries WHY a control could not be evaluated, as a
// machine-readable reason on the finding, so the platform can distinguish
// "the CI configuration could not be resolved" from "this control's data
// lane is not switched over yet" without parsing prose.
//
// Absent when the run recorded no specific reason — the older, run-wide
// degradation signals (a missing or invalid CI config, a failed collection)
// name no single control, and inventing a reason for them would be worse
// than saying nothing.
func notEvaluableReasonData(result *control.AnalysisResult, controlName string) json.RawMessage {
	if result == nil {
		return nil
	}
	reason, ok := result.NotEvaluable[controlName]
	if !ok || reason == "" {
		return nil
	}
	raw, err := json.Marshal(map[string]string{"reason": reason})
	if err != nil {
		return nil
	}
	return raw
}

// platformFindingControlName names a failed finding's control via the same
// registry lookup FindingsByControl itself buckets by (control.LookupCode),
// re-derived per finding rather than reused from the enclosing ControlEntry.
// Falls back to the raw code string when the code has no registry entry —
// never to the enclosing control's name, which would misattribute an
// unclassified finding as belonging to it.
func platformFindingControlName(f opaengine.Finding) string {
	if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil {
		return info.ControlName
	}
	return f.Code
}

// platformFindingDataRaw serializes f exactly as opaengine.Finding.MarshalJSON
// already produces it (code/severity/message/job/file/line/url/fingerprint +
// Data keys, existing casing) — the flat shape the platform's finding
// vocabulary is built to consume, not re-shaped or re-cased here. Marshal
// only fails for a JSON-incompatible value inside f.Data (a channel, a
// function), which Rego cannot produce; nil (omitted) is the safe fallback
// if it ever did.
//
// The serialized data then passes through sanitizeProvenance, which is what
// keeps a finding carrying a variable value from costing the operator their
// whole push: the platform rejects an ENTIRE push (422) over one value
// whose provenance is not declared, so a rule that emits a value without
// declaring where it came from has its value withheld and described here
// rather than taken to the wire.
func platformFindingDataRaw(f opaengine.Finding) json.RawMessage {
	raw, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	sanitized, _ := sanitizeProvenance(raw)
	return sanitized
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
// It returns non-nil ONLY for a token failure; see PlatformTokenError. conf
// supplies the resolved config path/PlumberConfig/ProjectID/control filters
// buildPlatformPush needs (falling back to the --config flag when conf is
// nil or has no resolved path, e.g. in tests that call this directly);
// result and score are threaded straight through so the platform, the
// terminal banner and the JSON report can never disagree about a run's
// findings or score. Project identity for the platform record is a separate
// matter and still comes from the verified OIDC claims server-side, never
// from operator-supplied config.
func maybePushPlatform(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult, score *control.PlumberScoreResult) error {
	push, endpoint := effectivePlatformPush()
	if !push {
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
	body, err := buildPlatformPush(p, conf, result, score, configPath)
	if err != nil {
		scoreWarn(fmt.Sprintf("platform push skipped: %v", err))
		return nil
	}

	// Every remote condition lands here, including 413 for an oversized body:
	// the server is the authority on its own limit, so the CLI enforces none.
	// The push is skipped whole rather than truncated, because the platform
	// renders the record as the complete picture. On failure this is also
	// the gate deadline: the same 15s transport timeout (scorePushHTTPTimeout)
	// bounds both the push and the gate verdict it carries, so no separate
	// gate timeout knob exists.
	respBody, statusCode, err := postScoreReportForBody(endpoint+"/api/v1/pushes", token, body)
	if err != nil {
		scoreWarn(fmt.Sprintf("%s: %v", platformGateFailOpenLine(statusCode), err))
		return nil
	}
	fmt.Fprintf(os.Stderr, "✓ Results pushed to the platform: %s\n", endpoint)
	return evaluatePlatformGate(respBody)
}
