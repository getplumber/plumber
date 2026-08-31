package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/platform"
	providerPkg "github.com/getplumber/plumber/provider"
	"gopkg.in/yaml.v2"
)

// policyEvaluation is one distinct control configuration and the verdict it
// produced. Several policies pointing at the same configuration share one
// of these: the configuration is what decides the verdict, so evaluating it
// twice could only ever produce the same answer at twice the cost.
type policyEvaluation struct {
	effectiveConfig []byte
	findings        []platformFinding
	score           platformScore
}

// buildPolicyResults produces one result entry per policy the platform
// resolved for this project, which is what the push contract's results
// array is: never a merged policy, always one entry each.
//
// Policies are grouped by the FINGERPRINT of the control configuration they
// evaluate under, and each distinct configuration is evaluated exactly once
// (evaluationFor). Two policies configuring the same control differently
// therefore get two independent verdicts, and two policies agreeing on it
// share one evaluation. Today every policy resolves to this run's single
// local configuration, so the grouping collapses to one evaluation feeding
// every entry - which is the correct answer for identical configurations,
// and leaves the structure right for when per-policy configuration starts
// arriving.
//
// In standalone mode - and whenever the context fetch failed - there is no
// policy set to key on, so this falls back to the single locally-named
// entry the CLI has always pushed.
func buildPolicyResults(
	p providerPkg.Provider,
	conf *configuration.Configuration,
	result *control.AnalysisResult,
	score *control.PlumberScoreResult,
	configPath string,
) []platformPolicyResult {
	policies := platformRunOf(conf).Policies()
	if len(policies) == 0 {
		return []platformPolicyResult{localPolicyResult(p, conf, result, score, configPath, "")}
	}

	cache := map[string]*policyEvaluation{}
	out := make([]platformPolicyResult, 0, len(policies))
	for _, pol := range policies {
		cfg := configForPolicy(p.Name(), conf, pol)
		key := configFingerprint(cfg)
		eval, ok := cache[key]
		if !ok {
			eval = evaluationFor(p, conf, result, score, cfg)
			cache[key] = eval
		}
		out = append(out, platformPolicyResult{
			Policy: pol.Name,
			// Only a real platform policy id is stamped. The derived
			// fallback carries the nil uuid, which is not a policies row:
			// keying a result on it would attach the run to a policy that
			// does not exist, so it is pushed name-only instead.
			PolicyID:        realPolicyID(pol),
			EffectiveConfig: eval.effectiveConfig,
			Findings:        eval.findings,
			Score:           eval.score,
		})
	}
	return out
}

// platformRunOf reads the run context off conf, tolerating a nil conf. A
// nil *RunContext is standalone mode and every accessor on it answers
// accordingly, so callers get one uniform "no platform" path instead of
// two nil checks at each site.
func platformRunOf(conf *configuration.Configuration) *platform.RunContext {
	if conf == nil {
		return nil
	}
	return conf.PlatformRun
}

// realPolicyID returns the id to key a push on, or "" when the policy has
// none that may be used. The empty string reaches the wire as an ABSENT
// key (omitempty), never as the literal all-zero uuid, which the platform's
// contract explicitly forbids sending.
func realPolicyID(pol platform.Policy) string {
	if !pol.IsReal() {
		return ""
	}
	return pol.ID
}

// configForPolicy resolves the control configuration a policy is evaluated
// under. It is THE extension point for per-policy configuration, and a
// variable so that is visible: everything downstream already keys on
// whatever it returns, so when the platform starts serving each policy's
// controls this is the only function that changes.
//
// A policy that declares its own control tree is evaluated under THAT tree
// and nothing else. Two policies may declare the same control_type with
// different parameters, which is the shape #368 needed: reading one
// policy's config and reporting it under another's name is precisely the
// bug this replaces.
//
// A policy that declares NO controls falls back to the local configuration.
// That covers the derived "[Plumber default]" fallback, which is not a real
// policies row and has no tree by definition, and any real policy an admin
// has not configured yet. Evaluating those against an empty ruleset would
// report a clean pass for a policy that simply has not been filled in.
var configForPolicy = func(provider string, conf *configuration.Configuration, pol platform.Policy) *configuration.PlumberConfig {
	if conf == nil {
		return nil
	}
	if !pol.DeclaresAnyControl() {
		return conf.PlumberConfig
	}
	cfg, err := policyConfigFromTree(provider, conf, pol)
	if err != nil {
		// Falling back to local config here would silently evaluate this
		// policy under someone else's parameters and report it under this
		// policy's name - the exact confusion the tree exists to end. The
		// run continues; this policy's verdict is the local one and the
		// operator is told the tree could not be applied.
		fmt.Fprintf(os.Stderr, "  platform: policy %q control tree could not be applied (%v); evaluating it under the local configuration\n", pol.Name, err)
		return conf.PlumberConfig
	}
	return cfg
}

// policyConfigFromTree builds the effective PlumberConfig for one policy out
// of the control tree the platform served for it.
//
// The per-control config is spliced in as RAW BYTES rather than decoded and
// re-encoded. JSON is a subset of YAML, so the stored bytes are a legal YAML
// flow-style value, and passing them through untouched preserves exactly what
// a decode/re-encode round trip destroys: integer literals above 2^53, which
// a generic map turns into a lossy float64. The platform went to the same
// trouble to serve these bytes verbatim; discarding that here would waste it.
func policyConfigFromTree(provider string, conf *configuration.Configuration, pol platform.Policy) (*configuration.PlumberConfig, error) {
	version := "2.0"
	if conf.PlumberConfig != nil && strings.TrimSpace(conf.PlumberConfig.Version) != "" {
		version = conf.PlumberConfig.Version
	}

	// The provider section has to be the one being analysed. A v2 config
	// keys controls under `gitlab:` or `github:`, and ControlsFor answers
	// with a ZERO ControlsConfig for a section that is absent rather than an
	// error - so assembling a GitHub policy under `gitlab:` would mark every
	// GitHub control skipped and push a result in which nothing was checked.
	section := strings.TrimSpace(provider)
	if section == "" {
		return nil, fmt.Errorf("no provider to assemble the policy's controls under")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "version: %q\n%s:\n  controls:\n", version, section)
	seen := map[string]bool{}
	applied := 0
	for _, req := range pol.Requirements {
		for _, c := range req.Controls {
			name := strings.TrimSpace(c.ControlType)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			value, err := policyControlValue(c.Config)
			if err != nil {
				// One unreadable control must not cost the policy its other
				// nine. Failing the whole tree over it would send the policy
				// back to the LOCAL configuration, which is the "evaluate one
				// policy under someone else's parameters" outcome this
				// function exists to prevent - a far larger error than
				// dropping the single control that could not be read.
				fmt.Fprintf(os.Stderr, "  platform: policy %q control %q could not be read (%v); it is not applied\n", pol.Name, name, err)
				continue
			}
			applied++
			fmt.Fprintf(&b, "    %s: %s\n", name, value)
		}
	}

	// A tree in which NOTHING could be read is not a policy that configures
	// nothing: it is a tree that did not arrive. Evaluating against the
	// empty ruleset it assembles to would report every control skipped and
	// push a verdict in which the policy checked nothing at all, so this
	// takes the same route a policy with no tree takes - the caller's
	// fallback to the local configuration, with the reason on stderr.
	if applied == 0 {
		return nil, fmt.Errorf("none of the policy's %d declared control(s) could be read", len(seen))
	}

	assembled := b.String()
	var cfg configuration.PlumberConfig
	if err := yaml.Unmarshal([]byte(assembled), &cfg); err != nil {
		return nil, fmt.Errorf("assembling the policy's controls: %w", err)
	}
	// Raw is this config's source text, and configFingerprint keys the
	// evaluation cache on it. Leaving it empty would make every assembled
	// config hash identically, so two policies with DIFFERENT parameters
	// would silently share one evaluation - the exact cross-policy bleed the
	// control tree exists to prevent.
	cfg.Raw = assembled
	return &cfg, nil
}

// policyControlValue renders one control's stored config as the YAML flow
// scalar that gets spliced into the assembled document.
//
// The bytes pass through uncompiled. JSON is a subset of YAML, so the
// platform's stored bytes are already a legal flow-style value, and passing
// them through untouched preserves exactly what a decode/re-encode round
// trip destroys: an integer literal above 2^53, which a generic map turns
// into a lossy float64.
//
// Two things have to be handled rather than trusted:
//
//   - An ABSENT config. json.Compact answers "unexpected end of JSON input"
//     for zero bytes, which the caller must not treat as a broken tree. A
//     control declared with no parameters is one enabled at its defaults,
//     which is what an empty mapping says.
//   - Three code points where the two grammars genuinely disagree. NEL
//     (U+0085), LINE SEPARATOR (U+2028) and PARAGRAPH SEPARATOR (U+2029)
//     are ordinary string characters to JSON but LINE BREAKS to YAML, and
//     libyaml folds a line break inside a double-quoted scalar to a space.
//     A trustedUrls entry or an allowlist pattern pasted from a document
//     would then be evaluated against a value that differs from the one the
//     platform stored, and silently stop matching. Escaping them keeps the
//     value identical while staying valid JSON.
func policyControlValue(raw json.RawMessage) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "{}", nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return "", err
	}
	// json.Compact is lexical: it never parses a number, so a big integer
	// survives byte-for-byte, and these replacements are byte-for-byte too.
	return yamlLineBreaks.Replace(compact.String()), nil
}

// yamlLineBreaks escapes the three code points YAML reads as line breaks
// inside a quoted scalar and JSON reads as ordinary characters. The
// replacements are the JSON escapes for the same code points, so the value
// a YAML parser produces is the one the platform stored.
var yamlLineBreaks = strings.NewReplacer(
	"\u0085", `\u0085`,
	"\u2028", `\u2028`,
	"\u2029", `\u2029`,
)

// configFingerprint identifies a control configuration, so two policies
// sharing one are evaluated once. It hashes the config's own raw text,
// which is what determines every control's parameters; a nil config
// fingerprints as a distinct, stable value rather than colliding with an
// empty one.
func configFingerprint(pc *configuration.PlumberConfig) string {
	if pc == nil {
		return "nil-config"
	}
	// Raw is the config's own source text and is what a file-loaded config
	// always carries. A config assembled in memory may not have it, and
	// hashing an empty Raw would give every such config the SAME key -
	// silently collapsing distinct policies into one shared evaluation. Fall
	// back to the marshaled content so the key still reflects what the config
	// actually says.
	material := []byte(pc.Raw)
	if len(bytes.TrimSpace(material)) == 0 {
		if encoded, err := yaml.Marshal(pc); err == nil {
			material = encoded
		}
	}
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:])
}

// evaluationFor produces the verdict for one distinct control
// configuration.
//
// The findings come from control.StatusFor over the already-collected
// result, exactly as the single-policy path has always built them, so a
// policy's entry and the terminal output can never disagree about what this
// run found.
func evaluationFor(
	p providerPkg.Provider,
	conf *configuration.Configuration,
	result *control.AnalysisResult,
	score *control.PlumberScoreResult,
	pc *configuration.PlumberConfig,
) *policyEvaluation {
	var includeOnly, skip []string
	if conf != nil {
		includeOnly, skip = conf.ControlsFilter, conf.SkipControlsFilter
	}

	// When this policy carries its OWN config, the verdict must come from
	// that config. Reusing the run's findings would report a finding computed
	// under different parameters while claiming this policy's effective
	// config - a false positive under a policy that never asked for the
	// check. Re-evaluation reuses the collected IR, so it costs no git-host
	// traffic.
	scopedResult, scopedScore := result, score
	if conf != nil && pc != nil && pc != conf.PlumberConfig {
		if scoped, s, ok := control.ReEvaluateForConfig(result, conf, p.Name(), pc); ok {
			// The whole scoped result, not a copy with only the findings
			// swapped in: it carries this policy's own not_evaluable marks,
			// and StatusFor reads them to report a control whose lane died
			// as an error rather than a pass.
			scopedResult = scoped
			scopedScore = &s
		}
	}

	return &policyEvaluation{
		effectiveConfig: platformEffectiveConfigRaw(pc),
		findings:        platformFindingsFor(p, scopedResult, pc, includeOnly, skip),
		score:           platformScoreFrom(scopedScore),
	}
}

// localPolicyResult is the standalone entry: one policy named after the
// config file this run loaded. Unchanged from what the CLI has always
// pushed, so a run without --platform context behaves exactly as before.
func localPolicyResult(
	p providerPkg.Provider,
	conf *configuration.Configuration,
	result *control.AnalysisResult,
	score *control.PlumberScoreResult,
	configPath, policyID string,
) platformPolicyResult {
	var pc *configuration.PlumberConfig
	if conf != nil {
		pc = conf.PlumberConfig
	}
	eval := evaluationFor(p, conf, result, score, pc)
	return platformPolicyResult{
		Policy:          platformPolicyNameFor(configPath),
		PolicyID:        policyID,
		EffectiveConfig: eval.effectiveConfig,
		Findings:        eval.findings,
		Score:           eval.score,
	}
}
