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

// buildPolicyResults maps the evaluated policy runs onto the push contract's
// results array: one entry per REAL policy of every applied run (policies
// sharing a run share its findings and score), the derived placeholder under
// its own name (R1), and nothing at all for a run that was not applied (R3,
// R6): a policy the CLI could not evaluate is absent from the push, never a
// clean entry.
//
// The runs are the product of evaluatePlatformPolicies, which is also what
// the terminal render and the artifacts read - so an entry here can never
// disagree with what the run reported.
func buildPolicyResults(runs []policyRun, p providerPkg.Provider, conf *configuration.Configuration) []platformPolicyResult {
	var includeOnly, skip []string
	if conf != nil {
		includeOnly, skip = conf.ControlsFilter, conf.SkipControlsFilter
	}

	out := []platformPolicyResult{}
	for _, run := range runs {
		if !run.Applied {
			continue
		}
		findings := platformFindingsFor(p, run.Result, run.Config, includeOnly, skip)
		effective := platformEffectiveConfigRaw(run.Config, p.Name())
		// run.Score is nil when this run's own control set evaluated
		// nothing real (row 45), and the wire's score must then be
		// genuinely absent rather than platformScoreFrom's zero-value
		// fallback for a nil input.
		var score *platformScore
		if run.Score != nil {
			s := platformScoreFrom(run.Score)
			score = &s
		}
		for _, pol := range run.Policies {
			out = append(out, platformPolicyResult{
				Policy: pol.Name,
				// Only a real platform policy id is stamped. The derived
				// fallback carries the nil uuid, which is not a policies
				// row: keying a result on it would attach the run to a
				// policy that does not exist, so it is pushed name-only
				// instead.
				PolicyID:        realPolicyID(pol),
				EffectiveConfig: effective,
				Findings:        findings,
				Score:           score,
			})
		}
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

// policyConfigVersion is the schema version every assembled policy
// configuration declares. It is a constant on purpose (R4): the platform's
// control tree is the whole configuration in platform mode, and reading the
// version off the run's LOCAL file would let a file the policy has nothing to
// do with decide how that policy's controls are parsed.
const policyConfigVersion = "2.0"

// policyConfigFromTree builds the effective PlumberConfig for one policy out
// of the control tree the platform served for it.
//
// The per-control config is spliced in as RAW BYTES rather than decoded and
// re-encoded. JSON is a subset of YAML, so the stored bytes are a legal YAML
// flow-style value, and passing them through untouched preserves exactly what
// a decode/re-encode round trip destroys: integer literals above 2^53, which
// a generic map turns into a lossy float64. The platform went to the same
// trouble to serve these bytes verbatim; discarding that here would waste it.
func policyConfigFromTree(provider string, pol platform.Policy) (*configuration.PlumberConfig, error) {
	version := policyConfigVersion

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
				// nine. Failing the whole tree over it would leave the policy
				// unevaluated and absent from the push, a far larger error
				// than dropping the single control that could not be read.
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
	// push a verdict in which the policy checked nothing at all, so the
	// caller reports the policy as not applied instead and it is left out of
	// the push entirely.
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

// standalonePolicyResult is the standalone entry: one policy named after the
// config file this run loaded, evaluated under that same local
// configuration. Unchanged from what the CLI has always pushed (it is the
// former localPolicyResult body), so a run without --platform context
// behaves exactly as before.
//
// The findings come from control.StatusFor over the already-collected
// result, exactly as the single-policy path has always built them, so the
// pushed entry and the terminal output can never disagree about what this
// run found.
func standalonePolicyResult(
	p providerPkg.Provider,
	conf *configuration.Configuration,
	result *control.AnalysisResult,
	score *control.PlumberScoreResult,
	configPath string,
) platformPolicyResult {
	var pc *configuration.PlumberConfig
	var includeOnly, skip []string
	if conf != nil {
		pc = conf.PlumberConfig
		includeOnly, skip = conf.ControlsFilter, conf.SkipControlsFilter
	}
	// A nil score (row 45: nothing was evaluated, or the deliberate
	// --no-controls/best-effort nil) must reach the wire as an absent
	// "score" key, not platformScoreFrom's zero-value fallback.
	var wireScore *platformScore
	if score != nil {
		s := platformScoreFrom(score)
		wireScore = &s
	}
	return platformPolicyResult{
		Policy:          platformPolicyNameFor(configPath),
		EffectiveConfig: platformEffectiveConfigRaw(pc, p.Name()),
		Findings:        platformFindingsFor(p, result, pc, includeOnly, skip),
		Score:           wireScore,
	}
}
