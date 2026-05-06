package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	configMigrateInPlace bool
	configMigrateInput   string
	configMigrateOutput  string
)

var configMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Upgrade .plumber.yaml from the legacy v1 schema to v2.0 (per-provider)",
	Long: `Rewrite a legacy .plumber.yaml that uses the top-level controls: block
(schema v1) into the per-provider v2.0 schema, where controls live under
gitlab.controls: or github.controls:. Comments and ordering are preserved.

By default the migrated file is written to <input>.v2 so you can review
before replacing the original. Use --in-place to overwrite directly; the
original is backed up to <input>.bak.

The migration:
  - Wraps the existing top-level 'controls:' under 'gitlab.controls:'.
  - Drops the deprecated top-level 'engine:' block (the Rego engine is now
    the only engine and runs unconditionally).
  - Sets 'version: "2.0"' at the top (or upgrades an existing 'version: "1.0"').
  - Leaves any pre-existing 'gitlab:' or 'github:' blocks alone.

If the file is already on v2.0 (no legacy keys present and version is "2.0"),
the command is a no-op and exits with a friendly message.

Examples:
  plumber config migrate                          # writes .plumber.yaml.v2 alongside the original
  plumber config migrate --in-place               # overwrites .plumber.yaml, backs up to .plumber.yaml.bak
  plumber config migrate --input ./conf.yaml      # explicit input path
  plumber config migrate --output /tmp/new.yaml   # explicit output path`,
	RunE: runConfigMigrate,
}

func runConfigMigrate(cmd *cobra.Command, args []string) error {
	in := configMigrateInput
	if in == "" {
		in = ".plumber.yaml"
	}

	data, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", in, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", in, err)
	}

	migrated, changes, err := migrateYAMLDocument(&doc)
	if err != nil {
		return err
	}

	if !migrated {
		fmt.Fprintf(os.Stderr, "%s is already on schema v2.0 (no legacy keys and version: \"2.0\"). Nothing to do.\n", in)
		return nil
	}

	out := configMigrateOutput
	if out == "" {
		if configMigrateInPlace {
			out = in
		} else {
			out = in + ".v2"
		}
	}

	if configMigrateInPlace && out == in {
		bak := in + ".bak"
		if err := os.WriteFile(bak, data, 0o600); err != nil {
			return fmt.Errorf("write backup %s: %w", bak, err)
		}
		fmt.Fprintf(os.Stderr, "Backed up original to %s\n", bak)
	}

	encoded, err := encodeYAMLDocument(&doc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, encoded, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}

	fmt.Fprintf(os.Stderr, "Migrated %s → %s\n", in, out)
	for _, c := range changes {
		fmt.Fprintf(os.Stderr, "  - %s\n", c)
	}
	if !configMigrateInPlace {
		fmt.Fprintf(os.Stderr, "Review the result, then replace the original with:\n  mv %s %s\n", out, in)
	}
	return nil
}

// migrateYAMLDocument mutates the given document in place to apply the
// v1 → v1.0 schema transform. Returns:
//   - migrated: true if any structural change was made.
//   - changes:  human-readable list of changes for the operator.
func migrateYAMLDocument(doc *yaml.Node) (bool, []string, error) {
	if doc == nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return false, nil, fmt.Errorf("unexpected YAML structure: not a document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false, nil, fmt.Errorf("unexpected YAML structure: top-level is not a mapping")
	}

	var changes []string
	migrated := false

	// Pluck out top-level keys we care about.
	controlsValue := pluckMappingKey(root, "controls")
	pluckedEngine := pluckMappingKey(root, "engine") != nil
	versionValue := findMappingValue(root, "version")

	if pluckedEngine {
		changes = append(changes, "removed deprecated 'engine:' block")
		migrated = true
	}

	if controlsValue != nil {
		// Find or create the `gitlab:` mapping at root.
		gitlabValue := findMappingValue(root, "gitlab")
		if gitlabValue == nil {
			// Insert a fresh `gitlab:` block at root.
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "gitlab"}
			gitlabValue = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			root.Content = append(root.Content, keyNode, gitlabValue)
		}
		// If gitlab already has its own controls, refuse — too dangerous to merge silently.
		if findMappingValue(gitlabValue, "controls") != nil {
			return false, nil, fmt.Errorf(
				"refusing to migrate: 'gitlab.controls:' already exists alongside top-level 'controls:'. " +
					"Resolve the conflict manually: keep the gitlab.controls block and delete the top-level controls block")
		}
		// Move the controls mapping under gitlab.
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "controls"}
		gitlabValue.Content = append(gitlabValue.Content, keyNode, controlsValue)
		changes = append(changes, "moved top-level 'controls:' under 'gitlab.controls:'")
		migrated = true
	}

	if versionValue == nil {
		// Add `version: "2.0"` at the top.
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "version"}
		valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "2.0", Style: yaml.DoubleQuotedStyle}
		root.Content = append([]*yaml.Node{keyNode, valNode}, root.Content...)
		changes = append(changes, "added 'version: \"2.0\"' header")
		migrated = true
	} else if versionValue.Value != "2.0" {
		// Upgrade legacy or empty version to "2.0".
		previous := versionValue.Value
		versionValue.Value = "2.0"
		versionValue.Style = yaml.DoubleQuotedStyle
		if previous == "" {
			changes = append(changes, "set 'version: \"2.0\"'")
		} else {
			changes = append(changes, fmt.Sprintf("upgraded version from %q to \"2.0\"", previous))
		}
		migrated = true
	}

	return migrated, changes, nil
}

// findMappingValue returns the value node associated with the given key
// in a Mapping node, or nil if absent. Mapping nodes store key/value
// pairs as alternating entries in Content.
func findMappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// pluckMappingKey removes the named key (and its value) from a Mapping
// node and returns the value node, or nil if the key was absent. The
// node order of remaining entries is preserved.
func pluckMappingKey(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			val := m.Content[i+1]
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return val
		}
	}
	return nil
}

// encodeYAMLDocument re-emits the (mutated) document with 2-space
// indentation, matching the existing .plumber.yaml convention.
func encodeYAMLDocument(doc *yaml.Node) ([]byte, error) {
	var buf yamlBuffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close yaml encoder: %w", err)
	}
	return buf.Bytes(), nil
}

// yamlBuffer is a minimal io.Writer-shaped sink used by the encoder so
// we don't have to pull in bytes.Buffer for one call site.
type yamlBuffer struct{ b []byte }

func (y *yamlBuffer) Write(p []byte) (int, error) {
	y.b = append(y.b, p...)
	return len(p), nil
}

func (y *yamlBuffer) Bytes() []byte { return y.b }
