package configuration

import (
	"fmt"
	"strings"

	"github.com/getplumber/plumber/internal/defaultconfig"
	"gopkg.in/yaml.v2"
)

// ExtendsPlumberDefault is the only value accepted by the top-level
// `extends:` key in v1. It selects overlay mode against the embedded
// baseline shipped in the binary.
const ExtendsPlumberDefault = "plumber:default"

// detectExtends reads the top-level `extends:` value from raw config
// bytes. It returns "" when the key is absent (legacy mode) and an
// error when the value is anything other than ExtendsPlumberDefault.
// Malformed YAML is not treated as an extends error; the normal loader
// reports parse failures.
func detectExtends(data []byte) (string, error) {
	var raw map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return "", nil
	}
	v, ok := raw["extends"]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("extends must be a string; only %q is supported", ExtendsPlumberDefault)
	}
	s = strings.TrimSpace(s)
	if s != ExtendsPlumberDefault {
		return "", fmt.Errorf("unsupported extends value %q; only %q is supported", s, ExtendsPlumberDefault)
	}
	return s, nil
}

// resolveOverlayBytes merges an overlay config (extends: plumber:default)
// onto the embedded baseline and returns the merged YAML with the
// extends key stripped. The result is a full config the normal loader
// can parse.
func resolveOverlayBytes(overlay []byte) ([]byte, error) {
	var baseMap map[interface{}]interface{}
	if err := yaml.Unmarshal(defaultconfig.Get(), &baseMap); err != nil {
		return nil, fmt.Errorf("parsing embedded default: %w", err)
	}
	var overlayMap map[interface{}]interface{}
	if err := yaml.Unmarshal(overlay, &overlayMap); err != nil {
		return nil, fmt.Errorf("parsing overlay: %w", err)
	}
	merged := deepMergeYAML(baseMap, overlayMap)
	delete(merged, "extends")
	out, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshaling merged config: %w", err)
	}
	return out, nil
}

func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func unionAllowlist(baseList, userList []string, include bool) []string {
	var out []string
	if include {
		out = append(out, baseList...)
	}
	out = append(out, userList...)
	return dedupStrings(out)
}

// materializeAuthorizedSources overwrites the resolved allowlist fields
// using the includePlumberDefaults toggle. It only touches a control the
// overlay actually mentioned; controls fully inherited from base keep
// their base list. Runs in overlay mode only.
func materializeAuthorizedSources(resolved, base, overlay *PlumberConfig) {
	for _, p := range []string{ProviderGitLab, ProviderGitHub} {
		rProv := providerControls(resolved, p)
		bProv := providerControls(base, p)
		oProv := providerControls(overlay, p)
		if rProv == nil || oProv == nil {
			continue
		}

		// githubActionMustComeFromAuthorizedSources (TrustedGithubActions)
		if oc := oProv.GithubActionMustComeFromAuthorizedSources; oc != nil {
			rc := rProv.GithubActionMustComeFromAuthorizedSources
			if rc != nil {
				var baseList []string
				if bProv != nil && bProv.GithubActionMustComeFromAuthorizedSources != nil {
					baseList = bProv.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
				}
				rc.TrustedGithubActions = unionAllowlist(baseList, oc.TrustedGithubActions, oc.IsIncludePlumberDefaults())
			}
		}

		// containerImageMustComeFromAuthorizedSources (TrustedUrls)
		if oc := oProv.ContainerImageMustComeFromAuthorizedSources; oc != nil {
			rc := rProv.ContainerImageMustComeFromAuthorizedSources
			if rc != nil {
				var baseList []string
				if bProv != nil && bProv.ContainerImageMustComeFromAuthorizedSources != nil {
					baseList = bProv.ContainerImageMustComeFromAuthorizedSources.TrustedUrls
				}
				rc.TrustedUrls = unionAllowlist(baseList, oc.TrustedUrls, oc.IsIncludePlumberDefaults())
			}
		}
	}
}

// providerControls returns the *ControlsConfig for a provider name, or
// nil when that provider section is absent.
func providerControls(c *PlumberConfig, provider string) *ControlsConfig {
	if c == nil {
		return nil
	}
	switch provider {
	case ProviderGitLab:
		if c.GitLab == nil {
			return nil
		}
		return &c.GitLab.Controls
	case ProviderGitHub:
		if c.GitHub == nil {
			return nil
		}
		return &c.GitHub.Controls
	}
	return nil
}
