package cmd

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/defaultconfig"
	"github.com/getplumber/plumber/utils"
)

var (
	configSlimFile   string
	configSlimOutput string
)

// maxSlimConfigBytes bounds the source file read by 'config slim', mirroring
// the 2 MiB cap the loader applies to every .plumber.yaml. Kept in sync with
// configuration's own limit (unexported there) so both slim branches reject an
// oversized file up front rather than buffering it unbounded.
const maxSlimConfigBytes = 2 << 20 // 2 MiB

var configSlimCmd = &cobra.Command{
	Use:   "slim",
	Short: "Rewrite a full .plumber.yaml as a minimal overlay",
	Long: `Collapse a full .plumber.yaml into a small overlay that extends
plumber:default, keeping only the controls whose values differ from the
baseline. Comments are not preserved; the result is a fresh minimal file.
Review it, then commit. Use 'plumber config resolve' to expand it again.

Examples:
  plumber config slim -o .plumber.yaml
  plumber config slim -c old.yaml -o slim.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := slimToOverlay(configSlimFile)
		if err != nil {
			return err
		}
		if configSlimOutput == "" {
			fmt.Print(string(out))
			return nil
		}
		if err := os.WriteFile(configSlimOutput, out, 0o600); err != nil {
			return fmt.Errorf("failed to write %s: %w", configSlimOutput, err)
		}
		fmt.Fprintf(os.Stderr, "Wrote slim overlay to %s\n", configSlimOutput)
		return nil
	},
}

// slimToOverlay reads a full config and returns a minimal overlay keeping
// only controls whose subtree differs from the embedded base.
//
// Overlay-ness (extends: plumber:default) is detected from the RAW map
// first, before any migration, because the two kinds of source need
// different treatment:
//
//   - An overlay source is already v2 and sparse. It is diffed directly
//     off its raw map, unchanged from before: routing it through
//     LoadPlumberConfig would resolve/materialize it (union the curated
//     base allowlists in) and re-widen trust before slim ever sees it.
//   - A legacy source (no extends: a v1 file or a full v2 replacement) is
//     normalized through LoadPlumberConfig first, which migrates v1 to v2
//     (getplumber/plumber#365 finding #7) and struct-round-trips the
//     config so both sides of the diff are comparable. It does NOT
//     resolve/materialize, because a legacy source has no extends.
//     Controls the legacy config omits are, by its own semantics, disabled
//     (see control.DisabledControlNames: an absent control does not run);
//     the omission diff below preserves that by emitting an explicit
//     `enabled: false` for any base-enabled control the source left out,
//     so resolving the emitted overlay against the base does not
//     re-enable it by inheritance (finding #8).
func slimToOverlay(src string) ([]byte, error) {
	if src == "" {
		src = ".plumber.yaml"
	}
	data, err := utils.ReadFileLimit(src, maxSlimConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", src, err)
	}

	var rawMap map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &rawMap); err != nil {
		return nil, fmt.Errorf("parse %s: %w", src, err)
	}

	// Whether the source is already an overlay (extends: plumber:default)
	// changes what includePlumberDefaults means on an allowlist-aware
	// control kept in the slim output: see forceLegacyAllowlistSemantics.
	// Detected from the raw map, before any migration.
	srcIsOverlay := isOverlaySource(rawMap)

	overlay := map[interface{}]interface{}{
		"extends": configuration.ExtendsPlumberDefault,
		"version": "2.0",
	}

	if srcIsOverlay {
		var baseMap map[interface{}]interface{}
		if err := yaml.Unmarshal(defaultconfig.Get(), &baseMap); err != nil {
			return nil, err
		}
		for _, p := range []string{"gitlab", "github"} {
			diff := diffControls(baseMap, rawMap, p)
			if len(diff) > 0 {
				overlay[p] = map[interface{}]interface{}{"controls": diff}
			}
		}
		return yaml.Marshal(overlay)
	}

	// Legacy source: normalize both sides through the loader so v1 is
	// migrated and both maps are struct-normalized and directly
	// comparable.
	srcCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(data, src)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", src, err)
	}
	baseCfg, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base")
	if err != nil {
		return nil, err
	}

	userMap, err := normalizeConfigToMap(srcCfg)
	if err != nil {
		return nil, err
	}
	baseMap, err := normalizeConfigToMap(baseCfg)
	if err != nil {
		return nil, err
	}

	for _, p := range []string{"gitlab", "github"} {
		diff := diffControls(baseMap, userMap, p)
		addOmittedDisabledControls(diff, baseMap, userMap, p, baseCfg)
		forceLegacyAllowlistSemantics(diff)
		pinLegacyStrictScalarFields(diff, srcCfg.ControlsFor(p))
		if len(diff) > 0 {
			overlay[p] = map[interface{}]interface{}{"controls": diff}
		}
	}
	return yaml.Marshal(overlay)
}

// normalizeConfigToMap marshals a loaded *configuration.PlumberConfig back
// to YAML and unmarshals it into a generic map, so it can be diffed with
// diffControls/controlsSubmap the same way a raw source map is. Routing
// both the source and the base through this gives them the same struct
// shape (e.g. a migrated v1 config and the embedded v2 base), which is
// what makes a value-level diff across a v1->v2 migration meaningful.
func normalizeConfigToMap(cfg *configuration.PlumberConfig) (map[interface{}]interface{}, error) {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[interface{}]interface{}
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// addOmittedDisabledControls mutates diff in place: for each control name
// that is enabled in the base but absent from the (legacy) source, the
// source has disabled that control by omission (control.DisabledControlNames
// treats an absent control the same as an explicit enabled:false). Without
// this, slim would simply drop the control, and resolving the emitted
// overlay against the base would inherit and re-enable it. A control that
// is absent from BOTH sides is left alone: it already resolves to "off" on
// both, so no diff entry is needed.
func addOmittedDisabledControls(diff, baseMap, userMap map[interface{}]interface{}, provider string, baseCfg *configuration.PlumberConfig) {
	baseControls := controlsSubmap(baseMap, provider)
	userControls := controlsSubmap(userMap, provider)
	baseDisabled := control.DisabledControlNames(baseCfg.ControlsFor(provider))
	for name := range baseControls {
		if _, present := userControls[name]; present {
			continue
		}
		nameStr, ok := name.(string)
		if !ok || baseDisabled[nameStr] {
			continue
		}
		diff[name] = map[interface{}]interface{}{"enabled": false}
	}
}

// isOverlaySource reports whether the parsed source config's top-level
// `extends` value is exactly configuration.ExtendsPlumberDefault, i.e.
// the source is already an overlay rather than a full/legacy config.
func isOverlaySource(userMap map[interface{}]interface{}) bool {
	v, ok := userMap["extends"]
	if !ok {
		return false
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	return strings.TrimSpace(s) == configuration.ExtendsPlumberDefault
}

// allowlistAwareControls are the controls whose includePlumberDefaults
// toggle changes the meaning of their kept trust list. In overlay mode
// includePlumberDefaults defaults to true, so materializeAuthorizedSources
// unions the curated base allowlist (~140 entries) into whatever list the
// overlay provides. A legacy full config ignores the toggle entirely and
// always uses its list as-is.
var allowlistAwareControls = map[string]bool{
	"githubActionMustComeFromAuthorizedSources":   true,
	"containerImageMustComeFromAuthorizedSources": true,
}

// forceLegacyAllowlistSemantics mutates diff in place so that kept
// allowlist-aware controls reproduce legacy "list used as-is" semantics
// once resolved. Only call this when the SOURCE config is legacy (not an
// overlay): in that case includePlumberDefaults is inert in the source (it
// was never honored there), so any value already present must be
// overridden to false, not preserved: otherwise a legacy config that
// narrowed or emptied its trust list would get silently widened back to
// the curated base list once the slimmed overlay is resolved. It copies a
// control's submap before mutating so the original parsed userMap (which
// the submap is a reference into) is never touched.
//
// When the source is already an overlay, do NOT call this: an absent
// toggle there legitimately means "union with base" and an explicit value
// is the user's real overlay-mode intent, so the control must pass through
// diffControls verbatim.
func forceLegacyAllowlistSemantics(diff map[interface{}]interface{}) {
	for name := range allowlistAwareControls {
		v, ok := diff[name]
		if !ok {
			continue
		}
		submap, ok := v.(map[interface{}]interface{})
		if !ok {
			continue
		}
		copied := copySubmap(submap)
		copied["includePlumberDefaults"] = false
		diff[name] = copied
	}
}

// pinLegacyStrictScalarFields mutates diff in place so that kept controls
// pin the non-pointer scalar/list fields (plus one *bool, see below) whose
// Go zero value is STRICTER than the base default. Without this, a legacy
// source that leaves such a field unset gets it dropped by yaml's
// omitempty when the control is marshaled (normalizeConfigToMap) and
// diffed, and resolving the emitted overlay against the base then inherits
// the base's MORE PERMISSIVE value, silently widening trust
// (cmd/config_slim.go:142 finding). Only call this for a LEGACY source (not
// an overlay source): an overlay source is diffed off its raw map, never
// round-tripped through a *configuration.PlumberConfig, so there is no
// srcCfg struct to read effective values from, and its own omitted fields
// legitimately mean "inherit base" by overlay semantics.
//
// The pinned fields:
//
//   - githubActionMustComeFromAuthorizedSources.minimumStars (int): unset
//     (0) means star-based trust is disabled (strict); base is 20000.
//   - actionsMustBePinnedByCommitSha.trustedOwners ([]string): unset
//     (empty) means every action must be SHA-pinned (strict); base is
//     [actions, github].
//   - containerImageMustComeFromAuthorizedSources.trustDockerHubOfficialImages
//     (*bool): this is the one pointer field that is NOT safe to leave
//     unpinned. trustGithubOfficialActions and trustSameOrgActions are
//     deliberately left alone here: their nil scan-time fallback (true, see
//     control/task.go) matches the base's literal true, so a nil source
//     pointer inheriting the base value yields the identical effective
//     value either way. trustDockerHubOfficialImages breaks that pattern:
//     its nil scan-time fallback is false, while base sets it to true, so a
//     nil source pointer must be pinned to its scan-effective value,
//     computed with the exact same nil => false fallback control/task.go
//     itself uses, or resolving against base would silently flip it to
//     true.
//
// Only acts on a control already present in diff (i.e. already kept by
// diffControls/addOmittedDisabledControls). Copies a control's submap
// before mutating so the original parsed userMap is never touched
// (mirrors forceLegacyAllowlistSemantics).
func pinLegacyStrictScalarFields(diff map[interface{}]interface{}, srcControls *configuration.ControlsConfig) {
	if srcControls == nil {
		return
	}

	if v, ok := diff["githubActionMustComeFromAuthorizedSources"]; ok {
		if c := srcControls.GithubActionMustComeFromAuthorizedSources; c != nil {
			if submap, ok := v.(map[interface{}]interface{}); ok {
				copied := copySubmap(submap)
				copied["minimumStars"] = c.MinimumStars
				diff["githubActionMustComeFromAuthorizedSources"] = copied
			}
		}
	}

	if v, ok := diff["actionsMustBePinnedByCommitSha"]; ok {
		if c := srcControls.ActionsMustBePinnedByCommitSha; c != nil {
			if submap, ok := v.(map[interface{}]interface{}); ok {
				copied := copySubmap(submap)
				owners := c.TrustedOwners
				if owners == nil {
					owners = []string{}
				}
				copied["trustedOwners"] = owners
				diff["actionsMustBePinnedByCommitSha"] = copied
			}
		}
	}

	if v, ok := diff["containerImageMustComeFromAuthorizedSources"]; ok {
		if c := srcControls.ContainerImageMustComeFromAuthorizedSources; c != nil {
			if submap, ok := v.(map[interface{}]interface{}); ok {
				copied := copySubmap(submap)
				// Mirror control/task.go's own nil => false fallback exactly.
				effective := false
				if c.TrustDockerHubOfficialImages != nil {
					effective = *c.TrustDockerHubOfficialImages
				}
				copied["trustDockerHubOfficialImages"] = effective
				diff["containerImageMustComeFromAuthorizedSources"] = copied
			}
		}
	}
}

// copySubmap returns a shallow copy of a control's submap so callers can
// mutate the copy without touching the original map they got the value
// from (which may be a reference into the parsed userMap).
func copySubmap(m map[interface{}]interface{}) map[interface{}]interface{} {
	copied := make(map[interface{}]interface{}, len(m))
	for k, val := range m {
		copied[k] = val
	}
	return copied
}

// diffControls returns the controls under <provider>.controls in userMap
// whose value differs from baseMap (or is absent from base).
func diffControls(baseMap, userMap map[interface{}]interface{}, provider string) map[interface{}]interface{} {
	out := map[interface{}]interface{}{}
	userControls := controlsSubmap(userMap, provider)
	baseControls := controlsSubmap(baseMap, provider)
	for name, uv := range userControls {
		bv, ok := baseControls[name]
		if !ok || !reflect.DeepEqual(bv, uv) {
			out[name] = uv
		}
	}
	return out
}

func controlsSubmap(m map[interface{}]interface{}, provider string) map[interface{}]interface{} {
	prov, ok := m[provider].(map[interface{}]interface{})
	if !ok {
		return map[interface{}]interface{}{}
	}
	controls, ok := prov["controls"].(map[interface{}]interface{})
	if !ok {
		return map[interface{}]interface{}{}
	}
	return controls
}
