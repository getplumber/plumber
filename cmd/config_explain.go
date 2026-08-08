package cmd

import (
	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
)

// controlProvenance labels each control key as "base" or "overlay".
// Controls named in the overlay are "overlay"; controls only the base
// provides are "base". In legacy mode (no extends) every control present
// in the file is "overlay".
func controlProvenance(overlayData []byte) (map[string]string, error) {
	out := map[string]string{}

	ext, err := yamlTopString(overlayData, "extends")
	if err != nil {
		return nil, err
	}
	isOverlay := ext == configuration.ExtendsPlumberDefault

	if isOverlay {
		for _, p := range []string{"gitlab", "github"} {
			for name := range providerControlNames(defaultconfig.Get(), p) {
				out[p+".controls."+name] = "base"
			}
		}
	}
	for _, p := range []string{"gitlab", "github"} {
		for name := range providerControlNames(overlayData, p) {
			out[p+".controls."+name] = "overlay"
		}
	}
	return out, nil
}

// providerControlNames returns the set of control names present under
// <provider>.controls in the given YAML.
func providerControlNames(data []byte, provider string) map[string]struct{} {
	names := map[string]struct{}{}
	var raw map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return names
	}
	prov, ok := raw[provider].(map[interface{}]interface{})
	if !ok {
		return names
	}
	controls, ok := prov["controls"].(map[interface{}]interface{})
	if !ok {
		return names
	}
	for k := range controls {
		if s, ok := k.(string); ok {
			names[s] = struct{}{}
		}
	}
	return names
}

func yamlTopString(data []byte, key string) (string, error) {
	var raw map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return "", nil
	}
	if s, ok := raw[key].(string); ok {
		return s, nil
	}
	return "", nil
}
